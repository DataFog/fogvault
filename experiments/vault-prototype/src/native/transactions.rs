//! Registered point operations: read-only preparation, durable exact target,
//! then live control fencing around the actual path-local vault transaction.
use super::*;
use fogvault::{
    ControlState, ControlWriteOutcome, PreparedControlOperation, SnapshotIdentity,
    TrustedControlStore,
};
use std::collections::BTreeMap;

pub(super) fn identity(descriptor: &[u8], head: &[u8]) -> Result<SnapshotIdentity> {
    if head.len() != fogvault::INDEX_HEAD_LEN {
        return Err(Error::Integrity);
    }
    Ok(SnapshotIdentity {
        descriptor_digest: crate::crypto::digest(descriptor),
        head_digest: crate::crypto::digest(head),
        generation: u64::from_be_bytes(head[..8].try_into().map_err(|_| Error::Integrity)?),
    })
}

pub(super) fn read_guard(
    context: &mut Option<RegisteredContext>,
) -> Result<Option<ControlPublicationGuard<'_>>> {
    let Some(context) = context.as_mut() else {
        return Ok(None);
    };
    let state = context.store.load()?.ok_or(Error::Integrity)?;
    if let Some(pending) = state.pending() {
        return Err(if pending.submission().is_some() {
            Error::OutcomeUnknown {
                request_id: pending.request_id,
            }
        } else {
            Error::Conflict
        });
    }
    context.store.publication_guard(&state).map(Some)
}

pub(super) fn check_guard_snapshot(
    guard: Option<&ControlPublicationGuard<'_>>,
    descriptor: &[u8],
    head: &[u8],
) -> Result<()> {
    if let Some(guard) = guard {
        if identity(descriptor, head)? != guard.current().accepted() {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

impl NativeHost {
    /// Registered creation is the host-owned default. The host namespace must
    /// already be independently protected; this call does not create isolation.
    pub fn create(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Vault> {
        let mut vault =
            Vault::diagnostic_create_current_with_kdf_policy(path, password, limits, kdf)?;
        let accepted = identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())?;
        vault.registered =
            Some(self.register_authenticated(&vault.path, vault.vault_id(), accepted)?);
        Ok(vault)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_access(
        &self,
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
        admission: fogvault::AccessAdmission,
        profile: fogvault::AccessProfile,
        devices: &[fogvault::ProviderIdentity],
        recovery: bool,
        provider: &mut dyn fogvault::KeyProvider,
    ) -> Result<(Vault, Option<fogvault::RecoveryKey>)> {
        let mut recovery_key = None;
        let mut vault = Vault::create_with_engine_factory(
            path,
            password,
            limits,
            kdf,
            |password, limits, kdf| {
                let (engine, key) = Engine::create_with_access(
                    password, limits, kdf, admission, profile, devices, recovery, provider,
                )?;
                recovery_key = key;
                Ok(engine)
            },
        )?;
        let accepted = identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())?;
        vault.registered =
            Some(self.register_authenticated(&vault.path, vault.vault_id(), accepted)?);
        Ok((vault, recovery_key))
    }
    pub fn open(&self, path: impl AsRef<Path>, limits: Limits, kdf: KdfPolicy) -> Result<Vault> {
        let context = self.open_registration(path.as_ref())?;
        let vault = Vault::diagnostic_open_current_with_kdf_policy(path, limits, kdf)?;
        if vault.vault_id() != context.vault_id() {
            return Err(Error::Integrity);
        }
        self.bind_registration(vault, context)
    }
    pub fn open_with_access(
        &self,
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
        admission: fogvault::AccessAdmission,
    ) -> Result<Vault> {
        let context = self.open_registration(path.as_ref())?;
        let vault = Vault::open_current_with_access(path, limits, kdf, admission)?;
        if vault.vault_id() != context.vault_id() {
            return Err(Error::Integrity);
        }
        self.bind_registration(vault, context)
    }
    fn bind_registration(&self, mut vault: Vault, mut context: RegisteredContext) -> Result<Vault> {
        if vault.path != context.vault_path {
            return Err(Error::Integrity);
        }
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        let guard = context.store.publication_guard(&state)?;
        let transaction = vault.connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            vault.engine.limits(),
            &mut vault.metrics,
            vault.engine.descriptor_byte_limit(),
        )?;
        // Opening a submitted source/target remains locked for explicit recovery.
        // An unanchored successor or replay after completion is refused here.
        guard.current().observe(identity(&descriptor, &head)?)?;
        transaction.commit().storage()?;
        drop(guard);
        vault.registered = Some(context);
        Ok(vault)
    }
    /// Deliberate owner enrollment of an already authenticated and audited vault.
    /// The owner must quiesce/drain pre-existing diagnostic or external writers
    /// before enrollment; raw diagnostic handles are outside the host boundary.
    pub fn register_existing(&self, vault: &mut Vault, token: &SessionToken) -> Result<()> {
        if vault.registered.is_some() {
            return Err(Error::Exists);
        }
        if vault.engine.content_format() != 3
            || vault.engine.descriptor_bytes().get(..8) != Some(b"FGVP0003".as_slice())
        {
            return Err(Error::UnsupportedCapability);
        }
        vault.audit(token)?;
        let accepted = identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())?;
        vault.registered =
            Some(self.register_authenticated(&vault.path, vault.vault_id(), accepted)?);
        Ok(())
    }
    /// Diagnostic opening still consults this independently selected registry.
    /// Free-standing legacy diagnostic functions cannot know an arbitrary host's
    /// registry and are outside this host boundary, like direct SQL access.
    pub fn open_unanchored_diagnostic(
        &self,
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Vault> {
        let vault = {
            let mut inspection = schema::inspect(path.as_ref())?;
            let tx = inspection.transaction().storage()?;
            let (descriptor, _) = load_header(&tx, limits, &mut OperationMetrics::default(), 180)?;
            tx.commit().storage()?;
            if descriptor.get(..8) == Some(b"FGVP0003".as_slice()) {
                Vault::diagnostic_open_current_with_kdf_policy(path.as_ref(), limits, kdf)?
            } else {
                Vault::diagnostic_open_with_kdf_policy(path.as_ref(), limits, kdf)?
            }
        };
        self.refuse_registered_diagnostic(path.as_ref(), vault.vault_id())?;
        Ok(vault)
    }
}

struct CaptureNodes<'a> {
    source: SqliteNodes<'a>,
    read: BTreeMap<NodeHash, Vec<u8>>,
    written: BTreeMap<NodeHash, Vec<u8>>,
}
impl<'a> CaptureNodes<'a> {
    fn new(connection: &'a Connection) -> Self {
        Self {
            source: SqliteNodes::new(connection, (2 * MAX_PATH_NODES + 1) as u64),
            read: BTreeMap::new(),
            written: BTreeMap::new(),
        }
    }
}
impl NodeStore for CaptureNodes<'_> {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        if let Some(bytes) = self.written.get(hash).or_else(|| self.read.get(hash)) {
            return Ok(Some(bytes.clone()));
        }
        let value = self.source.get(hash)?;
        if let Some(bytes) = &value {
            self.read.insert(*hash, bytes.clone());
        }
        Ok(value)
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_NODE_BYTES || crate::index::node_hash(bytes) != hash {
            return Err(Error::Integrity);
        }
        if self
            .written
            .get(&hash)
            .or_else(|| self.read.get(&hash))
            .is_some_and(|old| old != bytes)
        {
            return Err(Error::Integrity);
        }
        self.written.insert(hash, bytes.to_vec());
        Ok(())
    }
}

fn source_record(row: &AdmittedRecord) -> Result<SourceRecord> {
    Ok(SourceRecord {
        revision: row.revision,
        envelope_digest: crate::crypto::digest(row.envelope.as_deref().ok_or(Error::Integrity)?),
    })
}

fn record_for_lookup(
    connection: &Connection,
    id: &RecordId,
    present: bool,
    maximum: usize,
    metrics: &mut OperationMetrics,
) -> Result<Option<AdmittedRecord>> {
    if present {
        return load_record_admitted(connection, id, true, maximum, metrics).map(Some);
    }
    if connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
            params![id.as_slice()],
            |row| row.get::<_, bool>(0),
        )
        .storage()?
    {
        return Err(Error::Integrity);
    }
    Ok(None)
}

impl Vault {
    pub fn registered_control_state(&self) -> Result<ControlState> {
        self.registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?
            .store
            .load()?
            .ok_or(Error::Integrity)
    }
    fn stage_limits(&self) -> Result<StageLimits> {
        Ok(StageLimits {
            descriptor_bytes: self.engine.descriptor_byte_limit(),
            envelope_bytes: self.engine.envelope_byte_limit()?,
        })
    }
    fn registered_source(&self, context: &mut RegisteredContext) -> Result<ControlState> {
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        if let Some(pending) = state.pending() {
            return Err(if pending.submission().is_some() {
                Error::OutcomeUnknown {
                    request_id: pending.request_id,
                }
            } else {
                Error::Conflict
            });
        }
        if state.accepted() != identity(self.engine.descriptor_bytes(), self.engine.head_bytes())? {
            return Err(Error::Conflict);
        }
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn registered_save(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request: [u8; 16],
        fault: CommitFault,
    ) -> Result<CommitReceipt> {
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        self.metrics = OperationMetrics::default();
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        self.registered_source(&mut context)?;
        let draft = self
            .engine
            .draft_save(id, expected, metadata, payload, request)?;
        let mut owned_operation = None;
        let result = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_snapshot(&descriptor, &head)?;
            let mut nodes = CaptureNodes::new(&transaction);
            let lookup = self.engine.lookup(&mut nodes, &id)?;
            add_stats(&mut self.metrics.index, lookup.stats);
            let old = record_for_lookup(
                &transaction,
                &id,
                lookup.entry().is_some(),
                self.engine.envelope_byte_limit()?,
                &mut self.metrics,
            )?;
            let prior = old.as_ref().map(|row| StoredRecord {
                revision: row.revision,
                envelope: row.envelope.as_deref().unwrap_or_default(),
            });
            let plan = self.engine.stage_save(&draft, lookup, prior, &mut nodes)?;
            add_stats(&mut self.metrics.index, plan.stats);
            if plan.replay {
                transaction.commit().storage()?;
                self.check_registered_replay(&mut context, &descriptor, &head)?;
                return Ok(plan.receipt);
            }
            let owner = self.engine.control_save(context.registration_id(), &plan)?;
            owned_operation = Some(owner.clone());
            let mut target = PersistedNativeTarget {
                owner_bytes: owner.canonical_bytes().to_vec(),
                operation: owner.operation(),
                request_id: request,
                source_descriptor: descriptor.clone(),
                source_head: head,
                target_descriptor: descriptor,
                target_head: plan.head_bytes,
                source_nodes: nodes.read.into_iter().collect(),
                nodes: nodes.written.into_iter().collect(),
                obsolete: plan.obsolete,
                record: PersistedRecordMutation::Save {
                    id: plan.id,
                    revision: plan.revision,
                    envelope: plan.envelope,
                    expected: old.as_ref().map(source_record).transpose()?,
                },
            };
            target.canonicalize();
            transaction.commit().storage()?;
            let submitted = self.retain_registered_target(&mut context, &owner, &target)?;
            let mut guard = context.store.publication_guard(&submitted)?;
            registered_test_pause("after-submission")?;
            work.check()?;
            self.publish_registered_target(&target, fault, &work)?;
            self.finish_registered_control(&mut guard, &target)?;
            let receipt = self
                .engine
                .confirm_commit(&target.target_head)
                .map_err(|_| Error::OutcomeUnknown {
                    request_id: request,
                })?;
            let _ = context.clear_completed_target(&guard, self.stage_limits()?);
            Ok(receipt)
        })();
        self.registered_result(&mut context, request, owned_operation.as_ref(), result)
    }

    pub(super) fn registered_delete(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        revision: u64,
        request: [u8; 16],
        fault: CommitFault,
    ) -> Result<CommitReceipt> {
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        self.metrics = OperationMetrics::default();
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        self.registered_source(&mut context)?;
        let draft = self.engine.draft_delete(id, revision, request)?;
        let mut owned_operation = None;
        let result = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_snapshot(&descriptor, &head)?;
            let mut nodes = CaptureNodes::new(&transaction);
            let lookup = self.engine.lookup(&mut nodes, &id)?;
            add_stats(&mut self.metrics.index, lookup.stats);
            let old = record_for_lookup(
                &transaction,
                &id,
                lookup.entry().is_some(),
                self.engine.envelope_byte_limit()?,
                &mut self.metrics,
            )?;
            let prior = old.as_ref().map(|row| StoredRecord {
                revision: row.revision,
                envelope: row.envelope.as_deref().unwrap_or_default(),
            });
            let plan = self
                .engine
                .stage_delete(&draft, lookup, prior, &mut nodes)?;
            add_stats(&mut self.metrics.index, plan.stats);
            if plan.replay {
                transaction.commit().storage()?;
                self.check_registered_replay(&mut context, &descriptor, &head)?;
                return Ok(plan.receipt);
            }
            let owner = self
                .engine
                .control_delete(context.registration_id(), &plan)?;
            owned_operation = Some(owner.clone());
            let mut target = PersistedNativeTarget {
                owner_bytes: owner.canonical_bytes().to_vec(),
                operation: owner.operation(),
                request_id: request,
                source_descriptor: plan.prior_descriptor.clone(),
                source_head: plan.prior_head,
                target_descriptor: plan.prior_descriptor,
                target_head: plan.head_bytes,
                source_nodes: nodes.read.into_iter().collect(),
                nodes: nodes.written.into_iter().collect(),
                obsolete: plan.obsolete,
                record: PersistedRecordMutation::Delete {
                    id: plan.id,
                    expected: source_record(old.as_ref().ok_or(Error::Integrity)?)?,
                },
            };
            target.canonicalize();
            transaction.commit().storage()?;
            let submitted = self.retain_registered_target(&mut context, &owner, &target)?;
            let mut guard = context.store.publication_guard(&submitted)?;
            registered_test_pause("after-submission")?;
            work.check()?;
            self.publish_registered_target(&target, fault, &work)?;
            self.finish_registered_control(&mut guard, &target)?;
            let receipt = self
                .engine
                .confirm_commit(&target.target_head)
                .map_err(|_| Error::OutcomeUnknown {
                    request_id: request,
                })?;
            let _ = context.clear_completed_target(&guard, self.stage_limits()?);
            Ok(receipt)
        })();
        self.registered_result(&mut context, request, owned_operation.as_ref(), result)
    }

    pub(super) fn registered_credentials(
        &mut self,
        draft: CredentialDraft,
        request: [u8; 16],
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        let work = self.engine.begin_host_work()?;
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        self.registered_source(&mut context)?;
        let mut owned_operation = None;
        let result = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_credential_snapshot(&descriptor, &head)?;
            let plan = self.engine.stage_credential_change(&draft)?;
            if plan.receipt.request_id != request {
                return Err(Error::Malformed("credential request identity"));
            }
            if plan.replay {
                transaction.commit().storage()?;
                self.check_registered_replay(&mut context, &descriptor, &head)?;
                return Ok(CredentialReceipt {
                    receipt: plan.receipt,
                    key_effect: fogvault::KeyEffect::Preserved,
                    session: self.engine.current_session()?,
                });
            }
            let owner = self
                .engine
                .control_credentials(context.registration_id(), &plan)?;
            owned_operation = Some(owner.clone());
            let target = PersistedNativeTarget {
                owner_bytes: owner.canonical_bytes().to_vec(),
                operation: owner.operation(),
                request_id: request,
                source_descriptor: plan.prior_descriptor,
                source_head: plan.prior_head,
                target_descriptor: plan.descriptor_bytes,
                target_head: plan.head_bytes,
                source_nodes: vec![],
                nodes: vec![],
                obsolete: vec![],
                record: PersistedRecordMutation::None,
            };
            transaction.commit().storage()?;
            let submitted = self.retain_registered_target(&mut context, &owner, &target)?;
            let mut guard = context.store.publication_guard(&submitted)?;
            registered_test_pause("after-submission")?;
            work.check()?;
            self.publish_registered_target(&target, fault, &work)?;
            self.finish_registered_control(&mut guard, &target)?;
            let receipt = self
                .engine
                .confirm_credential_commit(&target.target_descriptor, &target.target_head)
                .map_err(|_| Error::OutcomeUnknown {
                    request_id: request,
                })?;
            let _ = context.clear_completed_target(&guard, self.stage_limits()?);
            Ok(receipt)
        })();
        self.registered_result(&mut context, request, owned_operation.as_ref(), result)
    }

    fn check_registered_replay(
        &self,
        context: &mut RegisteredContext,
        descriptor: &[u8],
        head: &[u8],
    ) -> Result<()> {
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        let guard = context.store.publication_guard(&state)?;
        if state.pending().is_some() || state.accepted() != identity(descriptor, head)? {
            return Err(Error::Conflict);
        }
        check_guard_snapshot(Some(&guard), descriptor, head)
    }

    fn retain_registered_target(
        &self,
        context: &mut RegisteredContext,
        owner: &PreparedControlOperation,
        target: &PersistedNativeTarget,
    ) -> Result<ControlState> {
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        // Cleanup only an already accepted prior target, before preparing new work.
        context.clear_target()?;
        let prepared = state.prepare_ordinary(owner)?;
        let submitted = prepared.authorize_ordinary_submission(owner)?;
        // All three checked control revisions must exist before the first
        // persistence/submission. Discovering exhaustion after vault COMMIT
        // would strand an otherwise valid target at Submitted forever.
        submitted.confirm_target(owner.target())?;
        persist_control(&mut context.store, &state, &prepared)?;
        registered_test_pause("after-preparation")?;
        context.persist_target(target, self.stage_limits_for_target(target)?)?;
        persist_control(&mut context.store, &prepared, &submitted)?;
        Ok(submitted)
    }

    fn stage_limits_for_target(&self, _: &PersistedNativeTarget) -> Result<StageLimits> {
        // The Engine includes only the exact privately retained pending target
        // width. Restart needs explicit host admission, never a journal length.
        self.stage_limits()
    }

    fn registered_result<T>(
        &mut self,
        context: &mut RegisteredContext,
        request: [u8; 16],
        owned: Option<&PreparedControlOperation>,
        result: Result<T>,
    ) -> Result<T> {
        if result.is_ok() {
            return result;
        }
        match context.store.load() {
            Ok(Some(state)) if state.pending().is_some() => {
                if owned.is_some_and(|operation| state.validate_ordinary(operation).is_ok()) {
                    if state
                        .pending()
                        .is_some_and(|pending| pending.submission().is_some())
                    {
                        let _ = self.engine.mark_unknown();
                        return Err(Error::OutcomeUnknown {
                            request_id: request,
                        });
                    }
                    // Unsubmitted preparation belongs to this exact operation;
                    // cancellation remains an explicit owner action.
                    let _ = self.engine.abort_prepared();
                    result
                } else {
                    // Same request ID does not authorize a different operation.
                    // Neither clear its intent nor claim its outcome as ours.
                    let _ = self.engine.abort_prepared();
                    Err(Error::Conflict)
                }
            }
            Ok(Some(state))
                if owned.is_some_and(|operation| state.accepted() == operation.target()) =>
            {
                let _ = self.engine.mark_unknown();
                Err(Error::OutcomeUnknown {
                    request_id: request,
                })
            }
            Ok(Some(_)) => {
                let _ = self.engine.abort_prepared();
                result
            }
            _ => {
                let _ = self.engine.mark_unknown();
                Err(Error::OutcomeUnknown {
                    request_id: request,
                })
            }
        }
    }

    fn finish_registered_control(
        &self,
        guard: &mut ControlPublicationGuard<'_>,
        target: &PersistedNativeTarget,
    ) -> Result<()> {
        let complete = guard.current().confirm_target(target.target_identity()?)?;
        match guard.compare_exchange(&complete)? {
            ControlWriteOutcome::Stored => Ok(()),
            _ => Err(Error::OutcomeUnknown {
                request_id: target.request_id,
            }),
        }
    }

    /// No key/KDF/provider work occurs here. The independently retained exact
    /// target owns publication authority; only a coherent source or exact target
    /// is accepted. The caller holds the live registration coordinator throughout.
    fn publish_registered_target(
        &mut self,
        target: &PersistedNativeTarget,
        fault: CommitFault,
        work: &fogvault::WorkGuard,
    ) -> Result<()> {
        let maximum = self.stage_limits_for_target(target)?;
        self.publish_registered_target_admitted(target, fault, maximum, Some(work))
    }

    fn publish_registered_target_admitted(
        &mut self,
        target: &PersistedNativeTarget,
        fault: CommitFault,
        maximum: StageLimits,
        work: Option<&fogvault::WorkGuard>,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            self.engine.limits(),
            &mut self.metrics,
            maximum.descriptor_bytes,
        )?;
        if descriptor == target.target_descriptor && head == target.target_head {
            validate_selected_target(&transaction, target, maximum, &mut self.metrics)?;
            transaction.commit().storage()?;
            return Ok(());
        }
        if descriptor != target.source_descriptor || head != target.source_head {
            return Err(Error::Conflict);
        }
        for (hash, bytes) in &target.source_nodes {
            if SqliteNodes::new(&transaction, 1).get(hash)?.as_ref() != Some(bytes) {
                return Err(Error::Integrity);
            }
        }
        recheck_source_record(
            &transaction,
            &target.record,
            maximum.envelope_bytes,
            &mut self.metrics,
        )?;
        validate_target_plan(&transaction, target)?;
        if let Some(work) = work {
            work.check()?;
        }
        let mut nodes = SqliteNodes::new(&transaction, u64::MAX);
        for (hash, bytes) in &target.nodes {
            nodes.put(*hash, bytes)?;
        }
        match &target.record {
            PersistedRecordMutation::Save {
                id,
                revision,
                envelope,
                ..
            } => {
                transaction.execute("INSERT INTO records(id,revision,envelope) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,envelope=excluded.envelope", params![id.as_slice(), i64::try_from(*revision).map_err(|_|Error::ResourceLimit)?, envelope]).storage()?;
                self.metrics.record_bytes_written = envelope.len() as u64;
            }
            PersistedRecordMutation::Delete { id, expected } => {
                if transaction
                    .execute(
                        "DELETE FROM records WHERE id=?1 AND revision=?2",
                        params![
                            id.as_slice(),
                            i64::try_from(expected.revision).map_err(|_| Error::ResourceLimit)?
                        ],
                    )
                    .storage()?
                    != 1
                {
                    return Err(Error::Conflict);
                }
            }
            PersistedRecordMutation::None => {}
        }
        if transaction.execute("UPDATE vault_state SET descriptor=?1,head=?2 WHERE id=1 AND descriptor=?3 AND head=?4", params![target.target_descriptor,target.target_head,target.source_descriptor,target.source_head]).storage()? != 1 { return Err(Error::Conflict); }
        self.metrics.head_bytes_written = target.target_head.len() as u64;
        for hash in &target.obsolete {
            if transaction
                .execute(
                    "DELETE FROM index_nodes WHERE hash=?1",
                    params![hash.as_slice()],
                )
                .storage()?
                != 1
            {
                return Err(Error::Integrity);
            }
            self.metrics.index_nodes_deleted += 1;
        }
        if fault == CommitFault::BeforeCommit {
            return Err(Error::OutcomeUnknown {
                request_id: target.request_id,
            });
        }
        if fault == CommitFault::RolledBackLostReply {
            let _ = transaction.rollback();
            return Err(Error::OutcomeUnknown {
                request_id: target.request_id,
            });
        }
        if let Some(work) = work {
            work.check()?;
        }
        if transaction.commit().is_err() {
            return Err(Error::OutcomeUnknown {
                request_id: target.request_id,
            });
        }
        registered_test_pause("after-vault-commit")?;
        if fault == CommitFault::AfterCommit {
            return Err(Error::OutcomeUnknown {
                request_id: target.request_id,
            });
        }
        let readback = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                maximum.descriptor_bytes,
            )?;
            if descriptor != target.target_descriptor || head != target.target_head {
                return Err(Error::Integrity);
            }
            validate_selected_target(&transaction, target, maximum, &mut self.metrics)?;
            transaction.commit().storage()?;
            Ok(())
        })();
        readback.map_err(|_: Error| Error::OutcomeUnknown {
            request_id: target.request_id,
        })
    }

    /// Explicit restart recovery. It may republish only the independently
    /// retained exact target; it never regenerates encryption or rebases intent.
    /// The returned vault stays locked and must be unlocked with current factors.
    pub fn reconcile_registered(&mut self, request: [u8; 16]) -> Result<CommitReceipt> {
        self.metrics = OperationMetrics::default();
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        if state.pending().is_none() {
            let guard = context.store.publication_guard(&state)?;
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            check_guard_snapshot(Some(&guard), &descriptor, &head)?;
            if head.get(8..24) != Some(request.as_slice()) {
                return Err(Error::NotFound);
            }
            transaction.commit().storage()?;
            self.engine.reopen_locked(&descriptor)?;
            return Ok(CommitReceipt {
                generation: state.accepted().generation,
                request_id: request,
                head_digest: state.accepted().head_digest,
            });
        }
        let pending = state.pending().ok_or(Error::NotFound)?;
        if pending.request_id != request {
            return Err(Error::Conflict);
        }
        if pending.submission().is_none() {
            return Err(Error::Conflict);
        }
        let retained_limits = self.stage_limits()?;
        let target = context.load_target(retained_limits)?;
        let owner = PreparedControlOperation::parse(&target.owner_bytes)?;
        state.validate_ordinary(&owner)?;
        state.confirm_target(owner.target())?;
        // Refuse an unadmitted target KDF/profile before publication. Locked
        // parsing retains only trusted host policy and performs no KDF/provider.
        let replacement = self
            .engine
            .prepare_reopen_locked(&target.target_descriptor)?;
        let mut guard = context.store.publication_guard(&state)?;
        self.engine.revocation_handle().revoke();
        self.publish_registered_target_admitted(&target, CommitFault::None, retained_limits, None)?;
        self.finish_registered_control(&mut guard, &target)
            .map_err(|_| Error::OutcomeUnknown {
                request_id: request,
            })?;
        let receipt = CommitReceipt {
            generation: owner.target().generation,
            request_id: request,
            head_digest: owner.target().head_digest,
        };
        self.engine = replacement;
        let _ = context.clear_completed_target(&guard, self.stage_limits()?);
        Ok(receipt)
    }

    /// Explicit owner cancellation of preparation that never authorized a
    /// submission. A live submitted intent always retains its uncertainty.
    pub fn abandon_registered_preparation(&mut self, request: [u8; 16]) -> Result<()> {
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        let pending = state.pending().ok_or(Error::NotFound)?;
        if pending.request_id != request {
            return Err(Error::Conflict);
        }
        let abandoned = state.abandon_unsubmitted()?;
        let mut guard = context.store.publication_guard(&state)?;
        let transaction = self.connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            self.engine.limits(),
            &mut self.metrics,
            self.engine.descriptor_byte_limit(),
        )?;
        if identity(&descriptor, &head)? != state.accepted() {
            return Err(Error::Conflict);
        }
        transaction.commit().storage()?;
        if guard.compare_exchange(&abandoned)? != ControlWriteOutcome::Stored {
            return Err(Error::Conflict);
        }
        self.engine.lock();
        drop(guard);
        // Clearing now rechecks no new operation has acquired the registration.
        let _ = context.clear_target();
        Ok(())
    }
}

fn persist_control(
    store: &mut ProtectedControlSqliteStore,
    prior: &ControlState,
    next: &ControlState,
) -> Result<()> {
    match store.compare_exchange(Some(prior), next)? {
        ControlWriteOutcome::Stored => Ok(()),
        ControlWriteOutcome::Conflict => Err(Error::Conflict),
        ControlWriteOutcome::Unknown if store.load()?.as_ref() == Some(next) => Ok(()),
        ControlWriteOutcome::Unknown => Err(Error::OutcomeUnknown {
            request_id: next.pending().map_or([0; 16], |pending| pending.request_id),
        }),
    }
}

fn recheck_source_record(
    connection: &Connection,
    mutation: &PersistedRecordMutation,
    maximum: usize,
    metrics: &mut OperationMetrics,
) -> Result<()> {
    let (id, expected) = match mutation {
        PersistedRecordMutation::None => return Ok(()),
        PersistedRecordMutation::Save { id, expected, .. } => (id, expected.as_ref()),
        PersistedRecordMutation::Delete { id, expected } => (id, Some(expected)),
    };
    let row = record_for_lookup(connection, id, expected.is_some(), maximum, metrics)?;
    if row.as_ref().map(source_record).transpose()?.as_ref() != expected {
        return Err(Error::Integrity);
    }
    Ok(())
}

// Head bytes are selected by independent control; this reads their canonical
// index root, not a new source of authentication. No secret MAC is recomputed.
fn selected_root(head: &[u8]) -> Result<Option<NodeHash>> {
    if head.len() != fogvault::INDEX_HEAD_LEN {
        return Err(Error::Integrity);
    }
    match head[64] {
        0 if head[65..97] == [0; 32] => Ok(None),
        1 => Ok(Some(head[65..97].try_into().map_err(|_| Error::Integrity)?)),
        _ => Err(Error::Integrity),
    }
}

fn validate_target_plan(connection: &Connection, target: &PersistedNativeTarget) -> Result<()> {
    // Recompute the exact nonsecret point change from the selected source.
    // Membership in source_nodes alone is insufficient for reclamation: a
    // source sibling may remain reachable as the new root after deletion.
    let mut trace = CaptureNodes::new(connection);
    let source_root = selected_root(&target.source_head)?;
    let (root, previous, expected_previous, mut obsolete) = match &target.record {
        PersistedRecordMutation::None => {
            if source_root != selected_root(&target.target_head)? {
                return Err(Error::Integrity);
            }
            return Ok(());
        }
        PersistedRecordMutation::Save {
            id,
            revision,
            envelope,
            expected,
        } => {
            let entry = crate::format::Entry {
                revision: *revision,
                digest: crate::crypto::digest(envelope),
            };
            let change = crate::index::upsert(&mut trace, source_root, *id, entry)?;
            let expected = expected.as_ref().map(|old| crate::format::Entry {
                revision: old.revision,
                digest: old.envelope_digest,
            });
            (
                Some(change.root),
                change.previous,
                expected,
                change.obsolete,
            )
        }
        PersistedRecordMutation::Delete { id, expected } => {
            let change = crate::index::remove(&mut trace, source_root, id)?;
            let expected = Some(crate::format::Entry {
                revision: expected.revision,
                digest: expected.envelope_digest,
            });
            (change.root, change.previous, expected, change.obsolete)
        }
    };
    obsolete.sort();
    let source_nodes: Vec<_> = trace.read.into_iter().collect();
    let nodes: Vec<_> = trace.written.into_iter().collect();
    if root != selected_root(&target.target_head)?
        || previous != expected_previous
        || source_nodes != target.source_nodes
        || nodes != target.nodes
        || obsolete != target.obsolete
    {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn validate_selected_target(
    connection: &Connection,
    target: &PersistedNativeTarget,
    maximum: StageLimits,
    metrics: &mut OperationMetrics,
) -> Result<()> {
    // Query actual committed nodes rather than overlaying a retained recipe.
    // This also validates a promoted source sibling that needed no new node.
    for (hash, bytes) in &target.nodes {
        if SqliteNodes::new(connection, 1).get(hash)?.as_ref() != Some(bytes) {
            return Err(Error::Integrity);
        }
    }
    let (id, expected_entry) = match &target.record {
        PersistedRecordMutation::Save {
            id,
            revision,
            envelope,
            ..
        } => {
            let row = load_record_admitted(connection, id, true, maximum.envelope_bytes, metrics)?;
            if row.revision != *revision || row.envelope.as_deref() != Some(envelope) {
                return Err(Error::Integrity);
            }
            (
                id,
                Some(crate::format::Entry {
                    revision: *revision,
                    digest: crate::crypto::digest(envelope),
                }),
            )
        }
        PersistedRecordMutation::Delete { id, .. } => {
            if connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
                    params![id.as_slice()],
                    |row| row.get::<_, bool>(0),
                )
                .storage()?
            {
                return Err(Error::Integrity);
            }
            (id, None)
        }
        PersistedRecordMutation::None => return Ok(()),
    };
    let mut nodes = SqliteNodes::new(connection, MAX_PATH_NODES as u64);
    let found = crate::index::lookup(&mut nodes, selected_root(&target.target_head)?, id)?;
    if found.entry != expected_entry {
        return Err(Error::Integrity);
    }
    Ok(())
}

#[cfg(test)]
fn registered_test_pause(phase: &str) -> Result<()> {
    if std::env::var("FOGVAULT_REGISTERED_PAUSE").ok().as_deref() == Some(phase) {
        use std::io::Write;
        let marker = std::env::var_os("FOGVAULT_REGISTERED_MARKER").ok_or(Error::Storage)?;
        std::fs::write(marker, phase).map_err(|_| Error::Storage)?;
        println!("REGISTERED_PAUSE_READY {phase}");
        std::io::stdout().flush().map_err(|_| Error::Storage)?;
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
#[cfg(not(test))]
fn registered_test_pause(_: &str) -> Result<()> {
    Ok(())
}
