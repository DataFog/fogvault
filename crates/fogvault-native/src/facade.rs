//! Supported native embedding surface. All persistence is registered; diagnostic
//! fault injection and writable old-format constructors are deliberately absent.
use crate::{native, *};
use std::path::Path;

/// Host-selected access profile and admitted provider limits.
#[derive(Clone, Debug)]
pub struct AccessOptions {
    pub admission: AccessAdmission,
    pub profile: AccessProfile,
    pub devices: Vec<fogvault::ProviderIdentity>,
    pub recovery: bool,
}

/// Registered native host. The caller establishes independent OS protection for
/// this namespace before creation and keeps it separate from vault-file access.
#[derive(Clone)]
pub struct Host(pub(crate) native::NativeHost);
impl Host {
    pub fn create_new(namespace: impl AsRef<Path>) -> Result<Self> {
        native::NativeHost::create_new(namespace).map(Self)
    }
    pub fn open(namespace: impl AsRef<Path>) -> Result<Self> {
        native::NativeHost::open_required(namespace).map(Self)
    }
    pub fn create(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Vault> {
        self.0.create(path, password, limits, kdf).map(Vault)
    }
    pub fn open_vault(
        &self,
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Vault> {
        self.0.open(path, limits, kdf).map(Vault)
    }
    pub fn create_with_access(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
        options: &AccessOptions,
        provider: &mut dyn KeyProvider,
    ) -> Result<(Vault, Option<RecoveryKey>)> {
        let (vault, recovery) = self.0.create_with_access(
            path,
            password,
            limits,
            kdf,
            options.admission.clone(),
            options.profile,
            &options.devices,
            options.recovery,
            provider,
        )?;
        Ok((Vault(vault), recovery))
    }
    pub fn open_with_access(
        &self,
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Vault> {
        self.0
            .open_with_access(path, limits, kdf, admission)
            .map(Vault)
    }
}

/// A durable registered vault. Returned plaintext uses the shared core's
/// zeroizing owner; the host owns copies it makes after a read.
pub struct Vault(pub(crate) native::Vault);
impl Vault {
    pub fn unlock(&mut self, password: &[u8]) -> Result<SessionToken> {
        self.0.unlock(password)
    }
    pub fn unlock_access(
        &mut self,
        path: AccessPath<'_>,
        provider: &mut dyn KeyProvider,
    ) -> Result<SessionToken> {
        self.0.unlock_access(path, provider)
    }
    pub fn recover(&mut self, key: &RecoveryKey) -> Result<()> {
        self.0.recover_access(key)
    }
    pub fn lock(&mut self) {
        self.0.lock();
    }
    pub fn is_unlocked(&self) -> bool {
        self.0.is_unlocked() && self.ready_control().is_ok()
    }
    fn ready_control(&self) -> Result<()> {
        let state = self.0.registered_control_state()?;
        if let Some(pending) = state.pending() {
            return Err(if pending.submission().is_some() {
                Error::OutcomeUnknown {
                    request_id: pending.request_id,
                }
            } else {
                Error::Conflict
            });
        }
        Ok(())
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.0.vault_id()
    }
    pub fn generation(&self) -> Option<u64> {
        self.0.generation()
    }
    pub fn current_session(&self) -> Result<SessionToken> {
        self.ready_control()?;
        self.0.current_session()
    }
    pub fn access_info(&self) -> Result<AccessInfo> {
        self.0.access_info()
    }
    pub fn audit(&mut self, token: &SessionToken) -> Result<AuditReport> {
        self.0.audit(token)
    }
    pub fn read(&mut self, token: &SessionToken, id: RecordId) -> Result<SecretRecord> {
        self.0.read(token, id)
    }
    pub fn save(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.0
            .save(token, id, expected_revision, metadata, payload, request)
    }
    pub fn delete(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: u64,
        request: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.0.delete(token, id, expected_revision, request)
    }
    pub fn begin_records(&mut self, token: &SessionToken) -> Result<RecordCursor> {
        self.0.begin_records(token)
    }
    pub fn record_page(
        &mut self,
        token: &SessionToken,
        cursor: &mut RecordCursor,
        maximum_records: usize,
    ) -> Result<RecordPage> {
        self.0.record_page(token, cursor, maximum_records)
    }
    pub fn change_password(
        &mut self,
        token: &SessionToken,
        current: &[u8],
        new: &[u8],
        request: [u8; 16],
    ) -> Result<CredentialReceipt> {
        self.0.change_password(token, current, new, request)
    }
    pub fn upgrade_kdf(
        &mut self,
        token: &SessionToken,
        password: &[u8],
        target: KdfProfile,
        request: [u8; 16],
    ) -> Result<CredentialReceipt> {
        self.0.upgrade_kdf(token, password, target, request)
    }
    /// Reauthenticate the explicitly selected access path while changing the
    /// password and/or admitted KDF. AND profiles require the device operation.
    #[allow(clippy::too_many_arguments)]
    pub fn change_credentials_with_access(
        &mut self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        new_password: &[u8],
        target: KdfProfile,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<CredentialReceipt> {
        let draft = self.0.prepare_access_password_change(
            token,
            auth,
            new_password,
            target,
            provider,
            request,
        )?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
    }
    pub fn reconcile(&mut self, request: [u8; 16]) -> Result<CommitReceipt> {
        self.0.reconcile_registered(request)
    }
    pub fn abandon_unsubmitted(&mut self, request: [u8; 16]) -> Result<()> {
        self.0.abandon_registered_preparation(request)
    }
    pub fn revocation_handle(&self) -> fogvault::RevocationHandle {
        self.0.revocation_handle()
    }
    pub fn access_change(
        &mut self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        change: fogvault::AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialReceipt, Option<RecoveryKey>)> {
        let (draft, recovery) = self
            .0
            .prepare_access_change(token, auth, change, provider, request)?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
            .map(|receipt| (receipt, recovery))
    }
    /// Explicit unchanged-key maintenance. Use protective replacement for loss
    /// or exposure; maintenance cannot retract access through retained copies.
    pub fn access_maintenance(
        &mut self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        change: fogvault::AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialReceipt, Option<RecoveryKey>)> {
        let (draft, recovery) = self
            .0
            .prepare_access_maintenance(token, auth, change, provider, request)?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
            .map(|receipt| (receipt, recovery))
    }
}

impl Vault {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_device_replacement(
        &self,
        token: &SessionToken,
        source: fogvault::ProtectiveSource<'_>,
        removed_slots: &[[u8; 16]],
        password: &[u8],
        options: &AccessOptions,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(PreparedProtection, Option<RecoveryKey>)> {
        self.0.prepare_device_replacement(
            token,
            source,
            removed_slots,
            password,
            options.profile,
            &options.devices,
            options.recovery,
            provider,
            options.admission.clone(),
            request,
        )
    }
    pub fn prepare_recovery_replacement(
        &self,
        key: &RecoveryKey,
        password: &[u8],
        options: &AccessOptions,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(PreparedProtection, Option<RecoveryKey>)> {
        self.0.prepare_recovery_replacement(
            key,
            password,
            options.profile,
            &options.devices,
            options.recovery,
            provider,
            options.admission.clone(),
            request,
        )
    }
    pub fn commit_protection(
        &mut self,
        draft: &mut PreparedProtection,
    ) -> Result<CredentialReceipt> {
        self.0.commit_protection(draft)
    }
    pub fn resume_protection(
        &mut self,
        ticket: &ProtectionTicket,
        source: fogvault::ProtectiveSource<'_>,
        source_admission: Option<AccessAdmission>,
        target: AccessPath<'_>,
        target_admission: AccessAdmission,
        provider: &mut dyn KeyProvider,
    ) -> Result<PreparedProtection> {
        self.0.resume_protection(
            ticket,
            source,
            source_admission,
            target,
            target_admission,
            provider,
        )
    }
    pub fn abandon_protection(&mut self, ticket: &ProtectionTicket) -> Result<()> {
        self.0.abandon_protection(ticket)
    }
}

impl Vault {
    pub fn last_metrics(&self) -> OperationMetrics {
        self.0.last_metrics()
    }
    pub fn current_receipt(&self, token: &SessionToken) -> Result<CommitReceipt> {
        self.ready_control()?;
        self.0.current_receipt(token)
    }
    pub fn configure_access_admission(&mut self, admission: AccessAdmission) -> Result<()> {
        self.0.configure_access_admission(admission)
    }
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
        self.0.save_at(
            token,
            expected_head,
            id,
            revision,
            metadata,
            payload,
            request,
        )
    }
    pub fn delete_at(
        &mut self,
        token: &SessionToken,
        expected_head: [u8; 32],
        id: RecordId,
        revision: u64,
        request: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.0
            .delete_at(token, expected_head, id, revision, request)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn setup_access(
        &mut self,
        token: &SessionToken,
        current: &[u8],
        auth: Option<AccessPath<'_>>,
        password: &[u8],
        options: &AccessOptions,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialReceipt, Option<RecoveryKey>)> {
        let (draft, key) = self.0.prepare_access_setup(
            token,
            current,
            auth,
            password,
            options.profile,
            &options.devices,
            options.recovery,
            provider,
            options.admission.clone(),
            request,
        )?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
            .map(|receipt| (receipt, key))
    }
    pub fn recovery_maintenance(
        &mut self,
        key: &RecoveryKey,
        password: &[u8],
        options: &AccessOptions,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialReceipt, Option<RecoveryKey>)> {
        let (draft, key) = self.0.prepare_recovery_maintenance(
            key,
            password,
            options.profile,
            &options.devices,
            options.recovery,
            provider,
            request,
        )?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
            .map(|receipt| (receipt, key))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn change_access_password(
        &mut self,
        token: &SessionToken,
        auth: AccessPath<'_>,
        password: &[u8],
        target: KdfProfile,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<CredentialReceipt> {
        let draft = self
            .0
            .prepare_access_password_change(token, auth, password, target, provider, request)?;
        self.0
            .commit_access_change(draft, request, native::CommitFault::None)
    }
}
