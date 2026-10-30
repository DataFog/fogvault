//! Scratch SQLite adapter around the portable lifecycle engine.
//! Transactions/CAS are not a persistent writer lease.

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use fogvault::{
    AuditRequest, CommitReceipt, CredentialDraft, CredentialReceipt, Engine, IndexStats, KdfPolicy,
    KdfProfile, NodeHash, NodeStore, SecretRecord, SessionToken, StoredRecord, DESCRIPTOR_LEN,
    MAX_NODE_BYTES, MAX_PATH_NODES,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{Error, Limits, RecordId, Result};
mod access;
#[cfg(feature = "backup")]
mod backup;
#[cfg(feature = "backup")]
pub use backup::RestoreTicket;
#[cfg(test)]
mod capacity_tests;
mod control;
mod durability;
mod protective;
mod records;
mod registered;
#[cfg(test)]
mod registered_process_tests;
mod schema;
mod transactions;
#[cfg(any(test, feature = "diagnostics"))]
pub use access::{CreationReceipt, PreparedCreation};
pub use control::{ControlPublicationGuard, ProtectedControlSqliteStore};
pub use protective::{PreparedProtection, ProtectionTicket};
pub use registered::NativeHost;
use registered::{
    PersistedNativeTarget, PersistedRecordMutation, RegisteredContext, SourceRecord, StageLimits,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFault {
    None,
    BeforeCommit,
    AfterCommit,
    /// Diagnostic lost response after a submitted transaction actually aborts.
    /// The caller must not infer that truth from an untrusted source snapshot.
    RolledBackLostReply,
}

/// Logical work counters, not SQLite page I/O, allocations, or fsync counts.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationMetrics {
    pub index: IndexStats,
    pub head_bytes_read: u64,
    pub head_bytes_written: u64,
    pub record_rows_read: u64,
    pub record_bytes_read: u64,
    pub record_bytes_written: u64,
    pub index_nodes_deleted: u64,
    pub full_audits: u64,
    pub records_scanned: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditReport {
    pub records_checked: u64,
    pub index_nodes_checked: u64,
}

/// SQLite owns I/O and atomic publication. The engine owns all lifecycle,
/// key/session, authenticated-head, record and receipt decisions.
pub struct Vault {
    connection: Connection,
    engine: Engine,
    metrics: OperationMetrics,
    path: PathBuf,
    registered: Option<RegisteredContext>,
}

impl Vault {
    /// Returns a locked vault. Creation never overwrites an occupied path.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn diagnostic_create(
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
    ) -> Result<Self> {
        Self::diagnostic_create_with_kdf_policy(path, password, limits, KdfPolicy::baseline())
    }

    /// The host explicitly admits any KDF profile this instance may read or write.
    /// Creation starts at the existing baseline; this selects no stronger default.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn diagnostic_create_with_kdf_policy(
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
    ) -> Result<Self> {
        Self::create_with_engine_factory(
            path,
            password,
            limits,
            kdf_policy,
            Engine::diagnostic_create_with_kdf_policy,
        )
    }

    /// Explicit unregistered current-format fixture construction. Normal callers
    /// use NativeHost::create, which also installs the independent registration.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn diagnostic_create_current(
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
    ) -> Result<Self> {
        Self::diagnostic_create_current_with_kdf_policy(
            path,
            password,
            limits,
            KdfPolicy::baseline(),
        )
    }
    pub fn diagnostic_create_current_with_kdf_policy(
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Self> {
        Self::create_with_engine_factory(
            path,
            password,
            limits,
            kdf,
            Engine::create_with_kdf_policy,
        )
    }
    fn create_with_engine_factory(
        path: impl AsRef<Path>,
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        create: impl FnOnce(&[u8], Limits, KdfPolicy) -> Result<Engine>,
    ) -> Result<Self> {
        limits.head_bytes()?;
        limits.diagnostic_legacy_envelope_bytes()?;
        kdf_policy.admit(KdfProfile::baseline())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let reservation = options.open(path.as_ref()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Storage
            }
        })?;
        drop(reservation);
        // On failure the reserved scratch file remains occupied, never reset.
        let mut engine = create(password, limits, kdf_policy)?;
        let mut connection = connect(path.as_ref(), true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        schema::initialize(&transaction)?;
        transaction
            .execute(
                "INSERT INTO vault_state(id, descriptor, head) VALUES(1, ?1, ?2)",
                params![engine.descriptor_bytes(), engine.head_bytes()],
            )
            .storage()?;
        transaction.commit().storage()?;
        schema::seal(&connection)?;
        // Native compatibility API creates locked; no session is published here.
        engine.lock();
        Ok(Self {
            connection,
            engine,
            metrics: OperationMetrics::default(),
            path: std::fs::canonicalize(path.as_ref()).map_err(|_| Error::Storage)?,
            registered: None,
        })
    }

    #[cfg(any(test, feature = "diagnostics"))]
    pub fn diagnostic_open(path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        Self::diagnostic_open_with_kdf_policy(path, limits, KdfPolicy::baseline())
    }

    /// An upgraded descriptor requires an explicit matching host allowlist.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn diagnostic_open_with_kdf_policy(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf_policy: KdfPolicy,
    ) -> Result<Self> {
        Self::open_portable(path, limits, kdf_policy, false)
    }
    pub fn diagnostic_open_current_with_kdf_policy(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<Self> {
        Self::open_portable(path, limits, kdf, true)
    }
    fn open_portable(
        path: impl AsRef<Path>,
        limits: Limits,
        kdf_policy: KdfPolicy,
        current: bool,
    ) -> Result<Self> {
        limits.head_bytes()?;
        limits.diagnostic_legacy_envelope_bytes()?;
        // Inspect an unknown destination read-only before configuring a writable adapter.
        let mut inspection = schema::inspect(path.as_ref())?;
        let transaction = inspection.transaction().storage()?;
        schema::admit(&transaction)?;
        let length: i64 = transaction
            .query_row(
                "SELECT length(descriptor) FROM vault_state WHERE id=1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if length != if current { 180 } else { DESCRIPTOR_LEN as i64 } {
            return Err(Error::Malformed("descriptor length"));
        }
        let bytes: Vec<u8> = transaction
            .query_row("SELECT descriptor FROM vault_state WHERE id=1", [], |row| {
                row.get(0)
            })
            .storage()?;
        // Version and descriptor policy are decided by the common engine.
        let engine = if current {
            Engine::open_with_kdf_policy(&bytes, limits, kdf_policy)?
        } else {
            Engine::diagnostic_open_with_kdf_policy(&bytes, limits, kdf_policy)?
        };
        transaction.commit().storage()?;
        drop(inspection);
        let connection = connect(path.as_ref(), false)?;
        Ok(Self {
            connection,
            engine,
            metrics: OperationMetrics::default(),
            path: std::fs::canonicalize(path.as_ref()).map_err(|_| Error::Storage)?,
            registered: None,
        })
    }

    pub fn unlock(&mut self, password: &[u8]) -> Result<SessionToken> {
        self.engine.begin_unlock(password)?;
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
            self.engine.current_session()
        })();
        if result.is_err() {
            self.engine.lock();
        }
        result
    }

    pub fn lock(&mut self) {
        self.engine.lock();
    }
    pub fn is_unlocked(&self) -> bool {
        self.engine.is_unlocked()
    }
    pub fn generation(&self) -> Option<u64> {
        self.engine.generation()
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.engine.vault_id()
    }
    pub fn last_metrics(&self) -> OperationMetrics {
        self.metrics
    }
    /// Retrieve the current capability after successful credential reconciliation.
    /// Ordinary operations still apply the engine's unknown-outcome barrier.
    pub fn current_session(&self) -> Result<SessionToken> {
        self.engine.current_session()
    }

    /// Scrubs all committed record hashes and exact membership in one snapshot.
    pub fn audit(&mut self, token: &SessionToken) -> Result<AuditReport> {
        self.engine.check_session(token)?;
        let limits = self.engine.limits();
        self.engine.current_receipt()?;
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
            self.engine.check_snapshot(&descriptor, &head)?;
            transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
            self.engine.begin_audit(&head)?;
            let report = audit_snapshot(
                &transaction,
                &mut self.engine,
                limits,
                true,
                &mut self.metrics,
            )?;
            transaction.commit().storage()?;
            self.engine.activate_audit()?;
            Ok(report)
        })();
        if result.is_err() {
            self.engine.abort_audit();
        }
        result
    }

    pub fn read(&mut self, token: &SessionToken, id: RecordId) -> Result<SecretRecord> {
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        let limits = self.engine.limits();
        self.engine.current_receipt()?;
        self.metrics = OperationMetrics::default();
        let mut registration = self.registered.clone();
        let guard = transactions::read_guard(&mut registration)?;
        let transaction = self.connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            limits,
            &mut self.metrics,
            self.engine.descriptor_byte_limit(),
        )?;
        self.engine.check_snapshot(&descriptor, &head)?;
        transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
        let found = self.engine.lookup(
            &mut SqliteNodes::new(&transaction, MAX_PATH_NODES as u64),
            &id,
        )?;
        add_stats(&mut self.metrics.index, found.stats);
        let proof = found.entry().ok_or(Error::NotFound)?;
        let row = load_record_admitted(
            &transaction,
            &id,
            true,
            self.engine.envelope_byte_limit()?,
            &mut self.metrics,
        )?;
        let envelope = row.envelope.as_deref().ok_or(Error::Integrity)?;
        let decoded = self.engine.read_verified(proof, row.revision, envelope)?;
        transaction.commit().storage()?;
        work.check()?;
        Ok(decoded)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request_id: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.save_with_fault(
            token,
            id,
            expected_revision,
            metadata,
            payload,
            request_id,
            CommitFault::None,
        )
    }

    /// Explicit experiment API; fault injection must not ship as production API.
    #[allow(clippy::too_many_arguments)]
    pub fn save_with_fault(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request_id: [u8; 16],
        fault: CommitFault,
    ) -> Result<CommitReceipt> {
        if self.registered.is_some() {
            return self.registered_save(
                token,
                id,
                expected_revision,
                metadata,
                payload,
                request_id,
                fault,
            );
        }
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        let limits = self.engine.limits();
        self.metrics = OperationMetrics::default();
        // Entropy/encryption happen before the write transaction. The draft is
        // scoped to the engine's current session and is not a commit receipt.
        let draft = self
            .engine
            .draft_save(id, expected_revision, metadata, payload, request_id)?;
        let result = (|| {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let (descriptor, old_head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_snapshot(&descriptor, &old_head)?;
            let mut nodes = SqliteNodes::new(&transaction, (2 * MAX_PATH_NODES) as u64);
            let lookup = self.engine.lookup(&mut nodes, &id)?;
            add_stats(&mut self.metrics.index, lookup.stats);
            let old = if lookup.entry().is_some() {
                Some(load_record_admitted(
                    &transaction,
                    &id,
                    true,
                    self.engine.envelope_byte_limit()?,
                    &mut self.metrics,
                )?)
            } else {
                let exists: bool = transaction
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
                        params![id.as_slice()],
                        |row| row.get(0),
                    )
                    .storage()?;
                if exists {
                    return Err(Error::Integrity);
                }
                None
            };
            let previous = match old.as_ref() {
                Some(row) => Some(StoredRecord {
                    revision: row.revision,
                    envelope: row.envelope.as_deref().ok_or(Error::Integrity)?,
                }),
                None => None,
            };
            let plan = self
                .engine
                .stage_save(&draft, lookup, previous, &mut nodes)?;
            add_stats(&mut self.metrics.index, plan.stats);
            if plan.replay {
                work.check()?;
                transaction.commit().storage()?;
                return Ok(plan.receipt);
            }
            self.metrics.record_bytes_written = plan.envelope.len() as u64;
            self.metrics.head_bytes_written = plan.head_bytes.len() as u64;
            work.check()?;
            transaction.execute(
                "INSERT INTO records(id, revision, envelope) VALUES(?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, envelope=excluded.envelope",
                params![id.as_slice(), i64::try_from(plan.revision).map_err(|_| Error::ResourceLimit)?, plan.envelope],
            ).storage()?;
            if transaction
                .execute(
                    "UPDATE vault_state SET head=?1 WHERE id=1 AND head=?2",
                    params![plan.head_bytes, old_head],
                )
                .storage()?
                != 1
            {
                return Err(Error::Conflict);
            }
            for hash in plan.obsolete {
                let deleted = transaction
                    .execute(
                        "DELETE FROM index_nodes WHERE hash=?1",
                        params![hash.as_slice()],
                    )
                    .storage()?;
                if deleted != 1 {
                    return Err(Error::Integrity);
                }
                self.metrics.index_nodes_deleted += deleted as u64;
            }
            if fault == CommitFault::BeforeCommit {
                return Err(Error::InjectedFailure);
            }
            // This last authority check admits commit submission. Revocation
            // after admission may race an in-flight commit and must reconcile.
            work.check()?;
            if fault == CommitFault::RolledBackLostReply {
                let _ = transaction.rollback();
                let _ = self.engine.mark_unknown();
                return Err(Error::OutcomeUnknown { request_id });
            }
            if transaction.commit().is_err() || fault == CommitFault::AfterCommit {
                let _ = self.engine.mark_unknown();
                return Err(Error::OutcomeUnknown { request_id });
            }
            match self.engine.confirm_commit(&plan.head_bytes) {
                Ok(receipt) => Ok(receipt),
                Err(_) => {
                    let _ = self.engine.mark_unknown();
                    Err(Error::OutcomeUnknown { request_id })
                }
            }
        })();
        if result.is_err() {
            let _ = self.engine.abort_prepared();
        }
        result
    }

    /// Change only the encrypted protection around the existing vault root.
    pub fn change_password(
        &mut self,
        token: &SessionToken,
        current_password: &[u8],
        new_password: &[u8],
        request_id: [u8; 16],
    ) -> Result<CredentialReceipt> {
        self.change_password_with_fault(
            token,
            current_password,
            new_password,
            request_id,
            CommitFault::None,
        )
    }

    /// Fault injection remains an experiment-only native surface.
    pub fn change_password_with_fault(
        &mut self,
        token: &SessionToken,
        current_password: &[u8],
        new_password: &[u8],
        request_id: [u8; 16],
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        self.engine.check_session(token)?;
        self.metrics = OperationMetrics::default();
        // Authenticate/rewrap before BEGIN: no KDF work under the SQL writer lock.
        let draft =
            self.engine
                .draft_password_change(current_password, new_password, request_id)?;
        self.apply_credential_draft(draft, request_id, fault)
    }

    /// Raise explicitly admitted KDF costs without changing the password or records.
    pub fn upgrade_kdf(
        &mut self,
        token: &SessionToken,
        password: &[u8],
        target: KdfProfile,
        request_id: [u8; 16],
    ) -> Result<CredentialReceipt> {
        self.upgrade_kdf_with_fault(token, password, target, request_id, CommitFault::None)
    }

    /// Fault injection remains an experiment-only native surface.
    pub fn upgrade_kdf_with_fault(
        &mut self,
        token: &SessionToken,
        password: &[u8],
        target: KdfProfile,
        request_id: [u8; 16],
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        self.engine.check_session(token)?;
        self.metrics = OperationMetrics::default();
        let draft = self
            .engine
            .draft_kdf_upgrade(password, target, request_id)?;
        self.apply_credential_draft(draft, request_id, fault)
    }

    fn apply_credential_draft(
        &mut self,
        draft: CredentialDraft,
        request_id: [u8; 16],
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        if self.registered.is_some() {
            return self.registered_credentials(draft, request_id, fault);
        }
        let limits = self.engine.limits();
        let work = self.engine.begin_host_work()?;
        let result = (|| {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_credential_snapshot(&descriptor, &head)?;
            let plan = self.engine.stage_credential_change(&draft)?;
            if request_id != plan.receipt.request_id {
                return Err(Error::Malformed("credential request identity"));
            }
            if plan.replay {
                work.check()?;
                transaction.commit().storage()?;
                return Ok(CredentialReceipt {
                    receipt: plan.receipt,
                    key_effect: fogvault::KeyEffect::Preserved,
                    session: self.engine.current_session()?,
                });
            }
            work.check()?;
            if transaction
                .execute(
                    "UPDATE vault_state SET descriptor=?1, head=?2
                     WHERE id=1 AND descriptor=?3 AND head=?4",
                    params![
                        plan.descriptor_bytes,
                        plan.head_bytes,
                        plan.prior_descriptor,
                        plan.prior_head,
                    ],
                )
                .storage()?
                != 1
            {
                return Err(Error::Conflict);
            }
            self.metrics.head_bytes_written = plan.head_bytes.len() as u64;
            if fault == CommitFault::BeforeCommit {
                return Err(Error::InjectedFailure);
            }
            work.check()?;
            if fault == CommitFault::RolledBackLostReply {
                let _ = transaction.rollback();
                let _ = self.engine.mark_unknown();
                return Err(Error::OutcomeUnknown { request_id });
            }
            if transaction.commit().is_err() || fault == CommitFault::AfterCommit {
                let _ = self.engine.mark_unknown();
                return Err(Error::OutcomeUnknown { request_id });
            }
            match self
                .engine
                .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            {
                Ok(receipt) => Ok(receipt),
                Err(_) => {
                    // The storage commit completed. A later confirmation error
                    // cannot be described as a known rollback.
                    let _ = self.engine.mark_unknown();
                    Err(Error::OutcomeUnknown { request_id })
                }
            }
        })();
        if result.is_err() {
            // A known SQL abort may discard preparation. The engine rejects this
            // call while uncertain, preserving the candidate needed to reconcile.
            let _ = self.engine.abort_prepared();
        }
        result
    }

    /// Only reconciles the current latest operation; no historical receipt ledger.
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn reconcile_latest(
        &mut self,
        token: &SessionToken,
        request_id: [u8; 16],
    ) -> Result<CommitReceipt> {
        if self.registered.is_some() {
            return self.reconcile_registered(request_id);
        }
        self.engine.check_session(token)?;
        let limits = self.engine.limits();
        self.metrics = OperationMetrics::default();
        let result = (|| {
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine
                .begin_reconcile_snapshot(&descriptor, &head, request_id)?;
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

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}

trait StorageResult<T> {
    fn storage(self) -> Result<T>;
}
impl<T> StorageResult<T> for rusqlite::Result<T> {
    fn storage(self) -> Result<T> {
        self.map_err(|error| match error {
            rusqlite::Error::SqliteFailure(error, _)
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                Error::Capacity
            }
            _ => Error::Storage,
        })
    }
}

fn connect(path: &Path, configure_new: bool) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .storage()?;
    schema::harden(&connection)?;
    if configure_new {
        connection
            .execute_batch("PRAGMA journal_mode=DELETE;")
            .storage()?;
    }
    connection
        .execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
        .storage()?;
    if !configure_new {
        schema::seal(&connection)?;
        let transaction = connection.unchecked_transaction().storage()?;
        schema::admit(&transaction)?;
        transaction.commit().storage()?;
    }
    Ok(connection)
}

fn admitted_length(length: i64, maximum: usize) -> Result<()> {
    if usize::try_from(length).map_err(|_| Error::ResourceLimit)? > maximum {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}

/// Bounded physical fetch only; MAC/context decisions belong to the engine.
fn load_header(
    connection: &Connection,
    limits: Limits,
    metrics: &mut OperationMetrics,
    maximum_descriptor_bytes: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    schema::admit(connection)?;
    let (descriptor_length, head_length): (i64, i64) = connection
        .query_row(
            "SELECT length(descriptor), length(head) FROM vault_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .storage()?
        .ok_or(Error::Integrity)?;
    if descriptor_length < DESCRIPTOR_LEN as i64
        || usize::try_from(descriptor_length).map_err(|_| Error::ResourceLimit)?
            > maximum_descriptor_bytes
    {
        return Err(Error::Integrity);
    }
    admitted_length(head_length, limits.head_bytes()?)?;
    let result: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT descriptor, head FROM vault_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .storage()?;
    metrics.head_bytes_read += result.1.len() as u64;
    Ok(result)
}

struct SqliteNodes<'a> {
    connection: &'a Connection,
    remaining_reads: u64,
}
impl<'a> SqliteNodes<'a> {
    fn new(connection: &'a Connection, maximum_reads: u64) -> Self {
        Self {
            connection,
            remaining_reads: maximum_reads,
        }
    }
}
impl NodeStore for SqliteNodes<'_> {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        self.remaining_reads = self
            .remaining_reads
            .checked_sub(1)
            .ok_or(Error::ResourceLimit)?;
        let length: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(bytes) FROM index_nodes WHERE hash=?1",
                params![hash.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        let Some(length) = length else {
            return Ok(None);
        };
        admitted_length(length, MAX_NODE_BYTES)?;
        Ok(Some(
            self.connection
                .query_row(
                    "SELECT bytes FROM index_nodes WHERE hash=?1",
                    params![hash.as_slice()],
                    |row| row.get(0),
                )
                .storage()?,
        ))
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_NODE_BYTES {
            return Err(Error::ResourceLimit);
        }
        // Hash ownership/canonical construction is checked by the engine. The
        // adapter enforces immutability at an already present physical address.
        let length: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(bytes) FROM index_nodes WHERE hash=?1",
                params![hash.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        if let Some(length) = length {
            admitted_length(length, MAX_NODE_BYTES)?;
            let old: Vec<u8> = self
                .connection
                .query_row(
                    "SELECT bytes FROM index_nodes WHERE hash=?1",
                    params![hash.as_slice()],
                    |row| row.get(0),
                )
                .storage()?;
            if old != bytes {
                return Err(Error::Integrity);
            }
        } else {
            self.connection
                .execute(
                    "INSERT INTO index_nodes(hash,bytes) VALUES(?1,?2)",
                    params![hash.as_slice(), bytes],
                )
                .storage()?;
        }
        Ok(())
    }
}

fn add_stats(target: &mut IndexStats, added: IndexStats) {
    target.nodes_read += added.nodes_read;
    target.nodes_written += added.nodes_written;
    target.bytes_read += added.bytes_read;
    target.bytes_written += added.bytes_written;
    target.peak_path_nodes = target.peak_path_nodes.max(added.peak_path_nodes);
}

struct AdmittedRecord {
    revision: u64,
    length: usize,
    envelope: Option<Vec<u8>>,
}
/// The caller derives this bound from its explicitly admitted descriptor.
/// Admit physical length before copying the BLOB in the caller's snapshot.
fn load_record_admitted(
    connection: &Connection,
    id: &RecordId,
    body: bool,
    maximum_envelope_bytes: usize,
    metrics: &mut OperationMetrics,
) -> Result<AdmittedRecord> {
    let (revision, length): (i64, i64) = connection
        .query_row(
            "SELECT revision,length(envelope) FROM records WHERE id=?1",
            params![id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .storage()?
        .ok_or(Error::Integrity)?;
    metrics.record_rows_read += 1;
    let revision = u64::try_from(revision).map_err(|_| Error::Integrity)?;
    admitted_length(length, maximum_envelope_bytes)?;
    let length = usize::try_from(length).map_err(|_| Error::ResourceLimit)?;
    let envelope = if body {
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT envelope FROM records WHERE id=?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .storage()?;
        metrics.record_bytes_read += bytes.len() as u64;
        Some(bytes)
    } else {
        None
    };
    Ok(AdmittedRecord {
        revision,
        length,
        envelope,
    })
}

/// Drives the engine's one authoritative audit cursor with bounded SQLite I/O.
fn audit_snapshot(
    connection: &Connection,
    engine: &mut Engine,
    _limits: Limits,
    hash_bodies: bool,
    metrics: &mut OperationMetrics,
) -> Result<AuditReport> {
    metrics.full_audits += 1;
    // Each node request is made only after the core accepts its predecessor.
    let mut nodes = SqliteNodes::new(connection, u64::MAX);
    loop {
        match engine.audit_next()? {
            AuditRequest::Node(hash) => {
                let bytes = nodes.get(&hash)?.ok_or(Error::Integrity)?;
                engine.supply_node(&bytes)?;
            }
            AuditRequest::Record { id, .. } => {
                let row = load_record_admitted(
                    connection,
                    &id,
                    hash_bodies,
                    engine.envelope_byte_limit()?,
                    metrics,
                )?;
                engine.supply_record(row.revision, row.length as u64, row.envelope.as_deref())?;
                metrics.records_scanned += 1;
            }
            AuditRequest::Done => break,
        }
    }
    let record_count: i64 = connection
        .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
        .storage()?;
    let node_count: i64 = connection
        .query_row("SELECT count(*) FROM index_nodes", [], |row| row.get(0))
        .storage()?;
    let result = engine.finish_audit(
        u64::try_from(record_count).map_err(|_| Error::Integrity)?,
        u64::try_from(node_count).map_err(|_| Error::Integrity)?,
    )?;
    add_stats(
        &mut metrics.index,
        IndexStats {
            nodes_read: result.nodes_read,
            bytes_read: result.node_bytes,
            peak_path_nodes: result.peak_path_nodes,
            ..IndexStats::default()
        },
    );
    Ok(AuditReport {
        records_checked: result.records_checked,
        index_nodes_checked: result.nodes_read,
    })
}

impl Vault {
    pub fn current_receipt(&self, token: &SessionToken) -> Result<CommitReceipt> {
        self.engine.check_session(token)?;
        self.engine.current_receipt()
    }
}
