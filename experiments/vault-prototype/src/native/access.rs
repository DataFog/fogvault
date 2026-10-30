//! Explicit P3 access adapter and prepared create-if-absent publication.
use super::*;
use fogvault::{
    AccessAdmission, AccessChange, AccessInfo, AccessPath, AccessProfile, KeyProvider,
    ProviderIdentity, RecoveryKey, RevocationHandle,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreationReceipt {
    pub vault_id: [u8; 16],
    pub request_id: [u8; 16],
    pub descriptor_digest: [u8; 32],
    pub head_digest: [u8; 32],
}
pub struct PreparedCreation {
    engine: Engine,
    receipt: CreationReceipt,
}
impl PreparedCreation {
    fn new(engine: Engine) -> Self {
        let receipt = CreationReceipt {
            vault_id: engine.vault_id(),
            request_id: engine.latest_request(),
            descriptor_digest: fogvault::experimental::crypto::digest(engine.descriptor_bytes()),
            head_digest: fogvault::experimental::crypto::digest(engine.head_bytes()),
        };
        Self { engine, receipt }
    }
    pub fn receipt(&self) -> CreationReceipt {
        self.receipt.clone()
    }
    pub fn revocation_handle(&self) -> RevocationHandle {
        self.engine.revocation_handle()
    }
    /// Prepare crypto/providers before this method. The complete encrypted DB
    /// is staged/fsynced, then hard-linked create-if-absent in the same directory.
    /// This scoped native experiment requires filesystem hard-link capability.
    pub fn publish(mut self, path: impl AsRef<Path>, fault: CommitFault) -> Result<Vault> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::Exists);
        }
        let work = self.engine.begin_host_work()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let operation = self
            .receipt
            .request_id
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let stage = parent.join(format!(".fogvault-create-{operation}.stage"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(&stage).map_err(|_| Error::Storage)?);
        let mut connection = connect(&stage, true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        schema::initialize(&transaction)?;
        transaction
            .execute(
                "INSERT INTO vault_state VALUES(1,?1,?2)",
                params![self.engine.descriptor_bytes(), self.engine.head_bytes()],
            )
            .storage()?;
        transaction.commit().storage()?;
        drop(connection);
        std::fs::File::open(&stage)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
        work.check()?;
        if fault == CommitFault::BeforeCommit {
            return Err(Error::InjectedFailure);
        }
        if fault == CommitFault::RolledBackLostReply {
            return Err(Error::OutcomeUnknown {
                request_id: self.receipt.request_id,
            });
        }
        std::fs::hard_link(&stage, path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Storage
            }
        })?;
        // Publication already happened: subsequent errors are never rollback.
        let _ = std::fs::remove_file(&stage);
        if std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .is_err()
            || fault == CommitFault::AfterCommit
        {
            return Err(Error::OutcomeUnknown {
                request_id: self.receipt.request_id,
            });
        }
        self.engine.lock();
        let connection = connect(path, false).map_err(|_| Error::OutcomeUnknown {
            request_id: self.receipt.request_id,
        })?;
        Ok(Vault {
            connection,
            engine: self.engine,
            metrics: OperationMetrics::default(),
            path: std::fs::canonicalize(path).map_err(|_| Error::Storage)?,
            registered: None,
        })
    }
}

impl Vault {
    /// Source-head compare-and-save for externally queued intent. A conflict
    /// after submission is reconciled by request ID, not replayed as new intent.
    #[allow(clippy::too_many_arguments)]
    pub fn save_at(
        &mut self,
        token: &SessionToken,
        expected_head: [u8; 32],
        id: RecordId,
        revision: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.engine.check_session(token)?;
        if self.engine.current_receipt()?.head_digest != expected_head {
            return Err(Error::Conflict);
        }
        self.save(token, id, revision, metadata, payload, request)
    }
    pub fn delete_at(
        &mut self,
        token: &SessionToken,
        expected_head: [u8; 32],
        id: RecordId,
        revision: u64,
        request: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.engine.check_session(token)?;
        if self.engine.current_receipt()?.head_digest != expected_head {
            return Err(Error::Conflict);
        }
        self.delete(token, id, revision, request)
    }
    /// Explicit owner cleanup of this operation's unpublished encrypted stage.
    /// Unlinking a leftover hard-link alias never deletes the published name.
    pub fn discard_creation_stage(
        directory: impl AsRef<Path>,
        receipt: &CreationReceipt,
        limits: Limits,
        maximum_descriptor_bytes: usize,
    ) -> Result<()> {
        let operation = receipt
            .request_id
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let stage = directory
            .as_ref()
            .join(format!(".fogvault-create-{operation}.stage"));
        let mut connection = schema::inspect(&stage)?;
        let transaction = connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            limits,
            &mut OperationMetrics::default(),
            maximum_descriptor_bytes,
        )?;
        if fogvault::experimental::crypto::digest(&descriptor) != receipt.descriptor_digest
            || fogvault::experimental::crypto::digest(&head) != receipt.head_digest
        {
            return Err(Error::Integrity);
        }
        transaction.commit().storage()?;
        drop(connection);
        std::fs::remove_file(stage).map_err(|_| Error::Storage)
    }
    pub fn diagnostic_prepare_creation(
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<PreparedCreation> {
        Ok(PreparedCreation::new(
            Engine::diagnostic_create_with_kdf_policy(password, limits, kdf)?,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn diagnostic_prepare_access_creation(
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
        admission: AccessAdmission,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
    ) -> Result<(PreparedCreation, Option<RecoveryKey>)> {
        let (engine, key) = Engine::diagnostic_create_with_access(
            password, limits, kdf, admission, profile, devices, recovery, provider,
        )?;
        Ok((PreparedCreation::new(engine), key))
    }
    pub fn diagnostic_open_with_access(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Self> {
        Self::open_access_impl(path, limits, kdf, admission, false)
    }
    pub(super) fn open_current_with_access(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Self> {
        Self::open_access_impl(path, limits, kdf, admission, true)
    }
    fn open_access_impl(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
        admission: AccessAdmission,
        current: bool,
    ) -> Result<Self> {
        let mut inspection = schema::inspect(path.as_ref())?;
        let transaction = inspection.transaction().storage()?;
        let (descriptor, _) = load_header(
            &transaction,
            limits,
            &mut OperationMetrics::default(),
            admission.max_descriptor_bytes,
        )?;
        let engine = if current {
            Engine::open_with_access(&descriptor, limits, kdf, admission)?
        } else {
            Engine::diagnostic_open_with_access(&descriptor, limits, kdf, admission)?
        };
        transaction.commit().storage()?;
        drop(inspection);
        Ok(Self {
            connection: connect(path.as_ref(), false)?,
            engine,
            metrics: OperationMetrics::default(),
            path: std::fs::canonicalize(path.as_ref()).map_err(|_| Error::Storage)?,
            registered: None,
        })
    }
    pub fn diagnostic_reconcile_creation(
        path: impl AsRef<Path>,
        receipt: &CreationReceipt,
        limits: Limits,
        kdf: KdfPolicy,
        admission: Option<AccessAdmission>,
    ) -> Result<Self> {
        let vault = if let Some(admission) = admission {
            Self::diagnostic_open_with_access(path, limits, kdf, admission)?
        } else {
            Self::diagnostic_open_with_kdf_policy(path, limits, kdf)?
        };
        let transaction = vault.connection.unchecked_transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            limits,
            &mut OperationMetrics::default(),
            vault.engine.descriptor_byte_limit(),
        )?;
        if vault.vault_id() != receipt.vault_id
            || fogvault::experimental::crypto::digest(&descriptor) != receipt.descriptor_digest
            || fogvault::experimental::crypto::digest(&head) != receipt.head_digest
        {
            return Err(Error::Integrity);
        }
        if head.len() != fogvault::INDEX_HEAD_LEN
            || head[..8] != [0; 8]
            || head[8..24] != receipt.request_id
        {
            return Err(Error::Integrity);
        }
        transaction.commit().storage()?;
        Ok(vault)
    }
    pub fn access_info(&self) -> Result<AccessInfo> {
        self.engine.access_info()
    }
    pub fn configure_access_admission(&mut self, admission: AccessAdmission) -> Result<()> {
        self.engine.configure_access_admission(admission)
    }
    pub fn revocation_handle(&self) -> RevocationHandle {
        self.engine.revocation_handle()
    }
    fn audit_access_candidate(&mut self) -> Result<()> {
        let limits = self.engine.limits();
        self.metrics = OperationMetrics::default();
        let result = (|| {
            let mut registration = self.registered.clone();
            let guard = transactions::read_guard(&mut registration)?;
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            if descriptor != self.engine.descriptor_bytes() {
                return Err(Error::Integrity);
            }
            transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
            self.engine.begin_audit(&head)?;
            audit_snapshot(
                &transaction,
                &mut self.engine,
                limits,
                false,
                &mut self.metrics,
            )?;
            transaction.commit().storage()?;
            self.engine.activate_audit()?;
            Ok(())
        })();
        if result.is_err() {
            self.engine.lock();
        }
        result
    }
    pub fn unlock_access(
        &mut self,
        path: AccessPath<'_>,
        provider: &mut dyn KeyProvider,
    ) -> Result<SessionToken> {
        self.engine.begin_unlock_access(path, provider)?;
        self.audit_access_candidate()?;
        self.engine.current_session()
    }
    pub fn recover_access(&mut self, key: &RecoveryKey) -> Result<()> {
        self.engine.begin_recovery(key)?;
        self.audit_access_candidate()
    }
    pub fn prepare_access_change(
        &self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        change: AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.check_session(token)?;
        self.engine
            .draft_access_change(auth, change, provider, request)
    }
    pub fn prepare_access_maintenance(
        &self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        change: AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.check_session(token)?;
        self.engine
            .draft_access_maintenance(auth, change, provider, request)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_access_setup(
        &mut self,
        token: &SessionToken,
        current: &[u8],
        auth: Option<AccessPath<'_>>,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.check_session(token)?;
        self.engine.draft_access_setup(
            current,
            auth,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_access_setup_maintenance(
        &mut self,
        token: &SessionToken,
        current: &[u8],
        auth: Option<AccessPath<'_>>,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.check_session(token)?;
        self.engine.draft_access_setup_maintenance(
            current,
            auth,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recovery_repair(
        &self,
        key: &RecoveryKey,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.draft_recovery_repair(
            key,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recovery_maintenance(
        &self,
        key: &RecoveryKey,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.engine.draft_recovery_maintenance(
            key,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            request,
        )
    }
    pub fn commit_access_change(
        &mut self,
        draft: CredentialDraft,
        request: [u8; 16],
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        self.apply_credential_draft(draft, request, fault)
    }
    pub fn prepare_access_password_change(
        &self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        password: &[u8],
        target: KdfProfile,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<CredentialDraft> {
        self.engine.check_session(token)?;
        self.engine
            .draft_access_password_change(auth, password, target, provider, request)
    }
    /// A recovery candidate reconciles only its pending repair; normal reads stay denied.
    pub fn reconcile_access_latest(&mut self, request: [u8; 16]) -> Result<CommitReceipt> {
        if self.registered.is_some() {
            return self.reconcile_registered(request);
        }
        if !self.engine.is_recovery_candidate() {
            self.engine.current_session()?;
        }
        let limits = self.engine.limits();
        let result = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine
                .begin_reconcile_snapshot(&descriptor, &head, request)?;
            audit_snapshot(
                &transaction,
                &mut self.engine,
                limits,
                false,
                &mut self.metrics,
            )?;
            transaction.commit().storage()?;
            self.engine.activate_audit()
        })();
        if result.is_err() {
            self.engine.abort_audit();
        }
        result
    }
}
