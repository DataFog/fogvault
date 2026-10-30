//! Registered full-content replacement. The protected staging database contains
//! ciphertext, authenticated headers and an encrypted checkpoint, never plaintext
//! passwords or keys. One row is transformed at a time. Whole-vault publication
//! uses one SQLite writer transaction under the live independent control fence.
use super::*;
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, ControlOperation, ControlState,
    ControlWriteOutcome, KeyProvider, ProtectivePlan, ProtectiveSource, ProtectiveTransition,
    ProviderIdentity, RecoveryKey, TransitionStore, TrustedControlStore, WorkGuard, INDEX_HEAD_LEN,
};

const TICKET_MAGIC: &[u8; 8] = b"FGVPRO01";
const TICKET_BYTES: usize = 120;
const TABLES: [&str; 5] = [
    "meta",
    "source_records",
    "source_nodes",
    "target_records",
    "index_nodes",
];

/// Exact nonsecret owner receipt. Persist it in trusted caller storage before
/// commit. Accepting bytes from an untrusted vault is not owner authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectionTicket {
    vault: [u8; 16],
    registration: [u8; 16],
    request: [u8; 16],
    commitment: [u8; 32],
    target_descriptor: [u8; 32],
}
impl ProtectionTicket {
    pub fn request_id(&self) -> [u8; 16] {
        self.request
    }
    pub fn encode(&self) -> [u8; TICKET_BYTES] {
        let mut bytes = [0; TICKET_BYTES];
        bytes[..8].copy_from_slice(TICKET_MAGIC);
        bytes[8..24].copy_from_slice(&self.vault);
        bytes[24..40].copy_from_slice(&self.registration);
        bytes[40..56].copy_from_slice(&self.request);
        bytes[56..88].copy_from_slice(&self.commitment);
        bytes[88..120].copy_from_slice(&self.target_descriptor);
        bytes
    }
    /// The caller authenticates the receipt's source independently of the vault.
    pub fn from_trusted_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TICKET_BYTES || &bytes[..8] != TICKET_MAGIC {
            return Err(Error::Malformed("protective owner receipt"));
        }
        Ok(Self {
            vault: bytes[8..24].try_into().map_err(|_| Error::Integrity)?,
            registration: bytes[24..40].try_into().map_err(|_| Error::Integrity)?,
            request: bytes[40..56].try_into().map_err(|_| Error::Integrity)?,
            commitment: bytes[56..88].try_into().map_err(|_| Error::Integrity)?,
            target_descriptor: bytes[88..120].try_into().map_err(|_| Error::Integrity)?,
        })
    }
    fn check(&self, control: &ControlState) -> Result<()> {
        let p = control.pending().ok_or(Error::Conflict)?;
        if control.vault_id() != self.vault
            || control.registration_id() != self.registration
            || p.operation != ControlOperation::ProtectiveTransition
            || p.request_id != self.request
            || p.owner_commitment != self.commitment
            || p.target_descriptor_digest != self.target_descriptor
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// Secret-owning preparation. An uncertain commit leaves this object intact for
/// exact retry; dropping it clears its keys. The durable ticket/checkpoint also
/// permit authenticated restart without retaining the process.
pub struct PreparedProtection {
    transition: Option<ProtectiveTransition>,
    ticket: ProtectionTicket,
    work: WorkGuard,
    plan: Option<ProtectivePlan>,
    submitted: bool,
    authorized: bool,
}
impl PreparedProtection {
    pub fn ticket(&self) -> ProtectionTicket {
        self.ticket
    }
    pub fn key_effect(&self) -> fogvault::KeyEffect {
        fogvault::KeyEffect::FreshRootAndContentKeys
    }
}

fn stage_path(context: &RegisteredContext, ticket: &ProtectionTicket) -> Result<PathBuf> {
    if context.vault_id() != ticket.vault || context.registration_id() != ticket.registration {
        return Err(Error::Conflict);
    }
    let name: String = ticket
        .commitment
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(context
        .vault_path_for_stage()?
        .join(format!("protective-{name}.sqlite")))
}
fn directory_sync(path: &Path) -> Result<()> {
    super::durability::directory_sync(path)
}
fn stored(guard: &mut ControlPublicationGuard<'_>, next: &ControlState) -> Result<()> {
    match guard.compare_exchange(next)? {
        ControlWriteOutcome::Stored => Ok(()),
        ControlWriteOutcome::Conflict => Err(Error::Conflict),
        ControlWriteOutcome::Unknown => Err(Error::OutcomeUnknown {
            request_id: next.pending().map(|p| p.request_id).unwrap_or([0; 16]),
        }),
    }
}
fn initialize_stage(path: &Path) -> Result<Connection> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Exists
        } else {
            Error::Storage
        }
    })?);
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .storage()?;
    db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE meta(key TEXT PRIMARY KEY NOT NULL,value BLOB NOT NULL); CREATE TABLE source_records(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision INTEGER NOT NULL CHECK(revision>0),envelope BLOB NOT NULL); CREATE TABLE target_records(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision INTEGER NOT NULL CHECK(revision>0),envelope BLOB NOT NULL); CREATE TABLE source_nodes(hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32),bytes BLOB NOT NULL CHECK(length(bytes) IN (57,82))); CREATE TABLE index_nodes(hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32),bytes BLOB NOT NULL CHECK(length(bytes) IN (57,82)));").storage()?;
    directory_sync(path.parent().ok_or(Error::Storage)?)?;
    Ok(db)
}
fn open_stage(path: &Path) -> Result<Connection> {
    if std::fs::symlink_metadata(path)
        .map_err(|_| Error::Integrity)?
        .file_type()
        .is_symlink()
    {
        return Err(Error::Integrity);
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| Error::Integrity)?;
    let mut statement = db
        .prepare("SELECT name,type FROM sqlite_schema")
        .storage()?;
    let rows = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .storage()?;
    let mut names = Vec::new();
    for row in rows {
        let (name, kind) = row.storage()?;
        if kind == "table" {
            names.push(name);
        } else if kind != "index" || !name.starts_with("sqlite_autoindex_") {
            return Err(Error::Integrity);
        }
    }
    names.sort();
    let mut expected = TABLES.map(str::to_owned);
    expected.sort();
    if names != expected {
        return Err(Error::Integrity);
    }
    drop(statement);
    Ok(db)
}
fn put_meta(db: &Connection, key: &str, value: &[u8]) -> Result<()> {
    db.execute("INSERT INTO meta VALUES(?1,?2)", params![key, value])
        .storage()?;
    Ok(())
}
fn meta(db: &Connection, key: &str, max: usize) -> Result<Vec<u8>> {
    let length: i64 = db
        .query_row("SELECT length(value) FROM meta WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .map_err(|_| Error::Integrity)?;
    admitted_length(length, max)?;
    db.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .storage()
}
struct StageNodes<'a> {
    db: &'a Connection,
    source: bool,
}
impl NodeStore for StageNodes<'_> {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        let table = if self.source {
            "source_nodes"
        } else {
            "index_nodes"
        };
        let length: Option<i64> = self
            .db
            .query_row(
                &format!("SELECT length(bytes) FROM {table} WHERE hash=?1"),
                [hash.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .storage()?;
        let Some(length) = length else {
            return Ok(None);
        };
        if !matches!(length, 57 | 82) {
            return Err(Error::Integrity);
        }
        let bytes: Vec<u8> = self
            .db
            .query_row(
                &format!("SELECT bytes FROM {table} WHERE hash=?1"),
                [hash.as_slice()],
                |r| r.get(0),
            )
            .storage()?;
        if crate::index::node_hash(&bytes) != *hash {
            return Err(Error::Integrity);
        }
        Ok(Some(bytes))
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if self.source || bytes.len() > MAX_NODE_BYTES || crate::index::node_hash(bytes) != hash {
            return Err(Error::Integrity);
        }
        if let Some(old) = self.get(&hash)? {
            if old != bytes {
                return Err(Error::Integrity);
            }
        } else {
            self.db
                .execute(
                    "INSERT INTO index_nodes VALUES(?1,?2)",
                    params![hash.as_slice(), bytes],
                )
                .storage()?;
        }
        Ok(())
    }
}
impl TransitionStore for StageNodes<'_> {
    fn staged_record(&mut self, id: &RecordId, maximum: usize) -> Result<Option<(u64, Vec<u8>)>> {
        staged_row(self.db, self.source, id, maximum)
    }
}
fn staged_row(
    db: &Connection,
    source: bool,
    id: &RecordId,
    maximum: usize,
) -> Result<Option<(u64, Vec<u8>)>> {
    let table = if source {
        "source_records"
    } else {
        "target_records"
    };
    let row: Option<(i64, i64)> = db
        .query_row(
            &format!("SELECT revision,length(envelope) FROM {table} WHERE id=?1"),
            [id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .storage()?;
    let Some((revision, length)) = row else {
        return Ok(None);
    };
    admitted_length(length, maximum)?;
    let revision = u64::try_from(revision).map_err(|_| Error::Integrity)?;
    if revision == 0 {
        return Err(Error::Integrity);
    }
    let bytes = db
        .query_row(
            &format!("SELECT envelope FROM {table} WHERE id=?1"),
            [id.as_slice()],
            |r| r.get(0),
        )
        .storage()?;
    Ok(Some((revision, bytes)))
}
fn for_each_id(
    db: &Connection,
    table: &str,
    mut visit: impl FnMut(RecordId) -> Result<()>,
) -> Result<()> {
    let mut statement = db
        .prepare(&format!("SELECT length(id),id FROM {table} ORDER BY id"))
        .storage()?;
    let mut rows = statement.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        let length: i64 = row.get(0).storage()?;
        if length != 16 {
            return Err(Error::Integrity);
        }
        let bytes: Vec<u8> = row.get(1).storage()?;
        let id = bytes.try_into().map_err(|_| Error::Integrity)?;
        visit(id)?;
    }
    Ok(())
}

impl Vault {
    fn protection(
        &self,
        transition: ProtectiveTransition,
        request: [u8; 16],
    ) -> Result<PreparedProtection> {
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        let control = context.store.load()?.ok_or(Error::Integrity)?;
        if control.pending().is_some() || control.accepted() != transition.source_snapshot() {
            return Err(Error::Conflict);
        }
        let ticket = ProtectionTicket {
            vault: self.vault_id(),
            registration: context.registration_id(),
            request,
            commitment: transition.owner_commitment(),
            target_descriptor: transition.target_descriptor_digest(),
        };
        Ok(PreparedProtection {
            transition: Some(transition),
            ticket,
            work: self.engine.begin_host_work()?,
            plan: None,
            submitted: false,
            authorized: false,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_device_replacement(
        &self,
        token: &SessionToken,
        source: ProtectiveSource<'_>,
        removed_slots: &[[u8; 16]],
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(PreparedProtection, Option<RecoveryKey>)> {
        self.engine.check_session(token)?;
        let (transition, key) = self.engine.draft_device_replacement(
            source,
            removed_slots,
            password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )?;
        self.protection(transition, request)
            .map(|operation| (operation, key))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_recovery_replacement(
        &self,
        key: &RecoveryKey,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(PreparedProtection, Option<RecoveryKey>)> {
        let (transition, new_key) = self.engine.draft_recovery_replacement(
            key, password, profile, devices, recovery, provider, admission, request,
        )?;
        self.protection(transition, request)
            .map(|operation| (operation, new_key))
    }
    fn stage_protection(
        &mut self,
        draft: &mut PreparedProtection,
        context: &mut RegisteredContext,
    ) -> Result<()> {
        draft.work.check()?;
        let transition = draft.transition.as_mut().ok_or(Error::Conflict)?;
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        if state.pending().is_some() || state.accepted() != transition.source_snapshot() {
            return Err(Error::Conflict);
        }
        // Prepare, submit and complete must all remain representable before the
        // first durable control mutation, including a vault containing no rows.
        state
            .revision()
            .checked_add(3)
            .ok_or(Error::ResourceLimit)?;
        let prepared = state.prepare(
            ControlOperation::ProtectiveTransition,
            draft.ticket.request,
            transition.target_descriptor_digest(),
            transition.owner_commitment(),
        )?;
        let mut guard = context.store.publication_guard(&state)?;
        draft.work.check()?;
        let path = stage_path(context, &draft.ticket)?;
        let stage = initialize_stage(&path)?;
        stored(&mut guard, &prepared)?;
        drop(guard);
        protective_test_pause("after-preparation")?;
        let stage_tx = stage.unchecked_transaction().storage()?;
        let source = self.connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &source,
            self.engine.limits(),
            &mut self.metrics,
            self.engine.descriptor_byte_limit(),
        )?;
        // A recovery candidate intentionally has no ordinary read/session
        // authority. Its already authenticated source bytes still bind this
        // dedicated replacement; do not call the ordinary reader gate.
        if descriptor != self.engine.descriptor_bytes() || head != self.engine.head_bytes() {
            return Err(Error::Conflict);
        }
        if transactions::identity(&descriptor, &head)? != prepared.accepted() {
            return Err(Error::Conflict);
        }
        put_meta(&stage_tx, "ticket", &draft.ticket.encode())?;
        put_meta(&stage_tx, "source_descriptor", &descriptor)?;
        put_meta(&stage_tx, "source_head", &head)?;
        put_meta(
            &stage_tx,
            "target_descriptor",
            transition.target_descriptor_bytes(),
        )?;
        let source_maximum = self.engine.envelope_byte_limit()?;
        put_meta(
            &stage_tx,
            "source_maximum",
            &(source_maximum as u64).to_be_bytes(),
        )?;
        let mut count = 0u64;
        for_each_id(&source, "records", |id| {
            draft.work.check()?;
            count = count.checked_add(1).ok_or(Error::ResourceLimit)?;
            if count > self.engine.limits().max_records as u64 {
                return Err(Error::ResourceLimit);
            }
            let lookup = self
                .engine
                .protective_lookup(&mut SqliteNodes::new(&source, MAX_PATH_NODES as u64), &id)?;
            let row = load_record_admitted(&source, &id, true, source_maximum, &mut self.metrics)?;
            let old = row.envelope.as_deref().ok_or(Error::Integrity)?;
            let encrypted = transition.transform_record(
                &self.engine,
                lookup.entry().ok_or(Error::Integrity)?,
                row.revision,
                old,
                &mut StageNodes {
                    db: &stage_tx,
                    source: false,
                },
                &prepared,
            )?;
            stage_tx
                .execute(
                    "INSERT INTO source_records VALUES(?1,?2,?3)",
                    params![id.as_slice(), row.revision as i64, old],
                )
                .storage()?;
            stage_tx
                .execute(
                    "INSERT INTO target_records VALUES(?1,?2,?3)",
                    params![id.as_slice(), row.revision as i64, encrypted],
                )
                .storage()?;
            Ok(())
        })?;
        let mut statement = source
            .prepare("SELECT hash,length(bytes),bytes FROM index_nodes ORDER BY hash")
            .storage()?;
        let mut rows = statement.query([]).storage()?;
        let mut node_count = 0u64;
        while let Some(row) = rows.next().storage()? {
            draft.work.check()?;
            let hash: Vec<u8> = row.get(0).storage()?;
            let length: i64 = row.get(1).storage()?;
            if hash.len() != 32 || !matches!(length, 57 | 82) {
                return Err(Error::Integrity);
            }
            let bytes: Vec<u8> = row.get(2).storage()?;
            if crate::index::node_hash(&bytes).as_slice() != hash {
                return Err(Error::Integrity);
            }
            stage_tx
                .execute(
                    "INSERT INTO source_nodes VALUES(?1,?2)",
                    params![hash, bytes],
                )
                .storage()?;
            node_count = node_count.checked_add(1).ok_or(Error::ResourceLimit)?;
        }
        drop(rows);
        drop(statement);
        let plan = transition.finish(
            &self.engine,
            &mut StageNodes {
                db: &stage_tx,
                source: false,
            },
            &prepared,
        )?;
        let expected_nodes = plan
            .record_count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        if plan.record_count != count || node_count != expected_nodes {
            return Err(Error::Integrity);
        }
        // Prune staging-only obsolete nodes using a disk-backed reachable set.
        stage_tx
            .execute_batch("CREATE TABLE reachable(hash BLOB PRIMARY KEY NOT NULL)")
            .storage()?;
        let mut cursor = crate::index::AuditCursor::new(plan.index_root, expected_nodes);
        while let Some(hash) = cursor.next_hash()? {
            draft.work.check()?;
            let bytes = StageNodes {
                db: &stage_tx,
                source: false,
            }
            .get(&hash)?
            .ok_or(Error::Integrity)?;
            cursor.supply(&bytes)?;
            stage_tx
                .execute("INSERT INTO reachable VALUES(?1)", [hash.as_slice()])
                .storage()?;
        }
        cursor.finish()?;
        stage_tx.execute_batch("DELETE FROM index_nodes WHERE hash NOT IN (SELECT hash FROM reachable); DROP TABLE reachable;").storage()?;
        put_meta(&stage_tx, "target_head", &plan.head_bytes)?;
        put_meta(
            &stage_tx,
            "checkpoint",
            &transition.checkpoint(&self.engine, &prepared)?,
        )?;
        put_meta(&stage_tx, "record_count", &plan.record_count.to_be_bytes())?;
        source.commit().storage()?;
        stage_tx.commit().storage()?;
        directory_sync(path.parent().ok_or(Error::Storage)?)?;
        draft.plan = Some(plan);
        protective_test_pause("after-stage")?;
        Ok(())
    }
    pub fn commit_protection(
        &mut self,
        draft: &mut PreparedProtection,
    ) -> Result<CredentialReceipt> {
        self.commit_protection_with_fault(draft, CommitFault::None)
    }
    pub fn commit_protection_with_fault(
        &mut self,
        draft: &mut PreparedProtection,
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        let result = self.commit_protection_inner(draft, fault);
        if result.is_err() && draft.submitted {
            Err(Error::OutcomeUnknown {
                request_id: draft.ticket.request,
            })
        } else {
            result
        }
    }
    fn commit_protection_inner(
        &mut self,
        draft: &mut PreparedProtection,
        fault: CommitFault,
    ) -> Result<CredentialReceipt> {
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        draft.work.check()?;
        if draft.plan.is_none() {
            self.stage_protection(draft, &mut context)?;
        }
        let plan = draft.plan.as_ref().ok_or(Error::Conflict)?.clone();
        let transition = draft.transition.as_ref().ok_or(Error::Conflict)?;
        let mut state = context.store.load()?.ok_or(Error::Integrity)?;
        if state.pending().is_none() {
            if state.accepted() != plan.target_snapshot() {
                return Err(Error::Conflict);
            }
        } else {
            draft.ticket.check(&state)?;
            if state.accepted() != transition.source_snapshot() {
                return Err(Error::Conflict);
            }
            if let Some(target) = state.pending().and_then(|p| p.submission()) {
                if target != plan.target_snapshot() {
                    return Err(Error::Conflict);
                }
            } else {
                let mut guard = context.store.publication_guard(&state)?;
                let submitted = state.authorize_submission(plan.target_snapshot())?;
                draft.work.check()?;
                stored(&mut guard, &submitted)?;
                state = submitted;
            }
            // Once a submission is durable, every later failure retains an
            // unknown outcome even if cancellation prevents local authorization.
            draft.submitted = true;
            if !draft.authorized {
                self.engine
                    .authorize_protective_submission(transition, &plan, &state)?;
                draft.authorized = true;
            }
            protective_test_pause("after-submission")?;
        }
        draft.work.check()?;
        let stage_path = stage_path(&context, &draft.ticket)?;
        let stage = open_stage(&stage_path)?;
        let stage_tx = stage.unchecked_transaction().storage()?;
        if meta(&stage_tx, "ticket", TICKET_BYTES)? != draft.ticket.encode()
            || meta(&stage_tx, "target_descriptor", plan.descriptor_bytes.len())?
                != plan.descriptor_bytes
            || meta(&stage_tx, "target_head", INDEX_HEAD_LEN)? != plan.head_bytes
        {
            return Err(Error::Integrity);
        }
        // Validate the entire retained graph using the operation's owned target
        // keys even when the source Engine is blocked by an uncertain outcome.
        // Keep this read snapshot alive through actual vault publication.
        if draft
            .transition
            .as_ref()
            .ok_or(Error::Conflict)?
            .verify_staged_target(&mut StageNodes {
                db: &stage_tx,
                source: false,
            })?
            != plan
        {
            return Err(Error::Integrity);
        }
        let records: i64 = stage_tx
            .query_row("SELECT count(*) FROM target_records", [], |r| r.get(0))
            .storage()?;
        let nodes: i64 = stage_tx
            .query_row("SELECT count(*) FROM index_nodes", [], |r| r.get(0))
            .storage()?;
        let expected_nodes = plan
            .record_count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        if u64::try_from(records).map_err(|_| Error::Integrity)? != plan.record_count
            || u64::try_from(nodes).map_err(|_| Error::Integrity)? != expected_nodes
        {
            return Err(Error::Integrity);
        }
        let result = (|| {
            let mut guard = context.store.publication_guard(&state)?;
            draft.work.check()?;
            if state.pending().is_some() {
                self.publish_protection(&stage_tx, &plan, &draft.work, fault)?;
                let completed = state.confirm_target(plan.target_snapshot())?;
                stored(&mut guard, &completed)?;
                state = completed;
            }
            let transaction = self.connection.transaction().storage()?;
            let (descriptor, head) = load_header(
                &transaction,
                self.engine.limits(),
                &mut self.metrics,
                plan.descriptor_bytes.len(),
            )?;
            if descriptor != plan.descriptor_bytes || head != plan.head_bytes {
                return Err(Error::Integrity);
            }
            transaction.commit().storage()?;
            let transition = draft.transition.take().ok_or(Error::Conflict)?;
            let receipt = self.engine.confirm_protective_transition(
                transition,
                &state,
                &descriptor,
                &head,
            )?;
            Ok(receipt)
        })();
        if result.is_err() && draft.submitted {
            return Err(Error::OutcomeUnknown {
                request_id: draft.ticket.request,
            });
        }
        if result.is_ok() {
            drop(stage_tx);
            drop(stage);
            // Removal is cleanup only, after exact control completion. Failure
            // retains ciphertext but cannot retract a committed replacement.
            let _ = std::fs::remove_file(&stage_path);
            let _ = directory_sync(stage_path.parent().ok_or(Error::Storage)?);
        }
        result
    }
    fn publish_protection(
        &mut self,
        stage: &Connection,
        plan: &ProtectivePlan,
        work: &WorkGuard,
        fault: CommitFault,
    ) -> Result<()> {
        let source_max = u64::from_be_bytes(
            meta(stage, "source_maximum", 8)?
                .try_into()
                .map_err(|_| Error::Integrity)?,
        );
        let source_max = usize::try_from(source_max).map_err(|_| Error::ResourceLimit)?;
        if source_max != self.engine.envelope_byte_limit()? {
            return Err(Error::Conflict);
        }
        let target_max = self
            .engine
            .prepare_reopen_locked(&plan.descriptor_bytes)?
            .envelope_byte_limit()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        let (descriptor, head) = load_header(
            &tx,
            self.engine.limits(),
            &mut self.metrics,
            self.engine
                .descriptor_byte_limit()
                .max(plan.descriptor_bytes.len()),
        )?;
        let already = descriptor == plan.descriptor_bytes && head == plan.head_bytes;
        if !already && (descriptor != plan.prior_descriptor || head != plan.prior_head) {
            return Err(Error::Conflict);
        }
        let table = if already {
            "target_records"
        } else {
            "source_records"
        };
        let maximum = if already { target_max } else { source_max };
        let count: i64 = tx
            .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
            .storage()?;
        if u64::try_from(count).map_err(|_| Error::Integrity)? != plan.record_count {
            return Err(Error::Integrity);
        }
        for_each_id(stage, table, |id| {
            work.check()?;
            let (revision, envelope) =
                staged_row(stage, !already, &id, maximum)?.ok_or(Error::Integrity)?;
            let actual = load_record_admitted(&tx, &id, true, maximum, &mut self.metrics)?;
            if actual.revision != revision
                || actual.envelope.as_deref() != Some(envelope.as_slice())
            {
                return Err(Error::Integrity);
            }
            Ok(())
        })?;
        let node_table = if already {
            "index_nodes"
        } else {
            "source_nodes"
        };
        let expected_nodes = plan
            .record_count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        let count: i64 = tx
            .query_row("SELECT count(*) FROM index_nodes", [], |r| r.get(0))
            .storage()?;
        if u64::try_from(count).map_err(|_| Error::Integrity)? != expected_nodes {
            return Err(Error::Integrity);
        }
        let mut s = stage
            .prepare(&format!("SELECT hash FROM {node_table} ORDER BY hash"))
            .storage()?;
        let mut rows = s.query([]).storage()?;
        let mut seen = 0u64;
        while let Some(row) = rows.next().storage()? {
            work.check()?;
            let h: Vec<u8> = row.get(0).storage()?;
            let hash: NodeHash = h.try_into().map_err(|_| Error::Integrity)?;
            let expected = StageNodes {
                db: stage,
                source: !already,
            }
            .get(&hash)?
            .ok_or(Error::Integrity)?;
            if SqliteNodes::new(&tx, u64::MAX).get(&hash)?.as_deref() != Some(expected.as_slice()) {
                return Err(Error::Integrity);
            }
            seen += 1;
        }
        if seen != expected_nodes {
            return Err(Error::Integrity);
        }
        drop(rows);
        drop(s);
        if !already {
            tx.execute_batch("DELETE FROM records; DELETE FROM index_nodes;")
                .storage()?;
            for_each_id(stage, "target_records", |id| {
                work.check()?;
                let (revision, envelope) =
                    staged_row(stage, false, &id, target_max)?.ok_or(Error::Integrity)?;
                tx.execute(
                    "INSERT INTO records VALUES(?1,?2,?3)",
                    params![id.as_slice(), revision as i64, envelope],
                )
                .storage()?;
                Ok(())
            })?;
            let mut s = stage
                .prepare("SELECT hash,bytes FROM index_nodes ORDER BY hash")
                .storage()?;
            let mut rows = s.query([]).storage()?;
            while let Some(row) = rows.next().storage()? {
                work.check()?;
                let hash: Vec<u8> = row.get(0).storage()?;
                let bytes: Vec<u8> = row.get(1).storage()?;
                if hash.len() != 32
                    || bytes.len() > MAX_NODE_BYTES
                    || crate::index::node_hash(&bytes).as_slice() != hash
                {
                    return Err(Error::Integrity);
                }
                tx.execute(
                    "INSERT INTO index_nodes VALUES(?1,?2)",
                    params![hash, bytes],
                )
                .storage()?;
            }
            tx.execute(
                "UPDATE vault_state SET descriptor=?1,head=?2 WHERE id=1",
                params![plan.descriptor_bytes, plan.head_bytes],
            )
            .storage()?;
        }
        work.check()?;
        if fault == CommitFault::BeforeCommit || fault == CommitFault::RolledBackLostReply {
            return Err(Error::InjectedFailure);
        }
        tx.commit().storage()?;
        protective_test_pause("after-vault-commit")?;
        if fault == CommitFault::AfterCommit {
            return Err(Error::InjectedFailure);
        }
        Ok(())
    }
    pub fn abandon_protection(&mut self, ticket: &ProtectionTicket) -> Result<()> {
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        ticket.check(&state)?;
        if state.pending().and_then(|p| p.submission()).is_some() {
            return Err(Error::OutcomeUnknown {
                request_id: ticket.request,
            });
        }
        let mut guard = context.store.publication_guard(&state)?;
        ticket.check(guard.current())?;
        let next = state.abandon_unsubmitted()?;
        stored(&mut guard, &next)?;
        let path = stage_path(&context, ticket)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Storage),
        }
        directory_sync(path.parent().ok_or(Error::Storage)?)
    }
}

impl Vault {
    /// Reconstruct only the owner-selected exact transition after restart.
    /// Both source authority and target credentials are required. The source
    /// engine is confined behind pending registered control: ordinary operations
    /// remain blocked until the exact replacement is committed/reconciled.
    pub fn resume_protection(
        &mut self,
        ticket: &ProtectionTicket,
        source_auth: ProtectiveSource<'_>,
        source_admission: Option<AccessAdmission>,
        target_auth: AccessPath<'_>,
        target_admission: AccessAdmission,
        provider: &mut dyn KeyProvider,
    ) -> Result<PreparedProtection> {
        let mut context = self
            .registered
            .clone()
            .ok_or(Error::UnsupportedCapability)?;
        let state = context.store.load()?.ok_or(Error::Integrity)?;
        ticket.check(&state)?;
        let path = stage_path(&context, ticket)?;
        let stage = open_stage(&path)?;
        let tx = stage.unchecked_transaction().storage()?;
        if meta(&tx, "ticket", TICKET_BYTES)? != ticket.encode() {
            return Err(Error::Conflict);
        }
        let source_limit = source_admission
            .as_ref()
            .map(|a| a.max_descriptor_bytes)
            .unwrap_or(180);
        let descriptor = meta(&tx, "source_descriptor", source_limit)?;
        let head = meta(&tx, "source_head", INDEX_HEAD_LEN)?;
        let mut engine = if let Some(admission) = source_admission {
            Engine::open_with_access(
                &descriptor,
                self.engine.limits(),
                self.engine.kdf_policy().clone(),
                admission,
            )?
        } else {
            Engine::open_with_kdf_policy(
                &descriptor,
                self.engine.limits(),
                self.engine.kdf_policy().clone(),
            )?
        };
        match source_auth {
            ProtectiveSource::Password(password) => {
                engine.begin_unlock(password)?;
            }
            ProtectiveSource::Access(path) => {
                engine.begin_unlock_access(path, provider)?;
            }
            ProtectiveSource::Recovery(key) => {
                engine.begin_recovery(key)?;
            }
        }
        engine.begin_audit(&head)?;
        loop {
            match engine.audit_next()? {
                AuditRequest::Node(hash) => engine.supply_node(
                    &StageNodes {
                        db: &tx,
                        source: true,
                    }
                    .get(&hash)?
                    .ok_or(Error::Integrity)?,
                )?,
                AuditRequest::Record { id, .. } => {
                    let (revision, envelope) =
                        staged_row(&tx, true, &id, engine.envelope_byte_limit()?)?
                            .ok_or(Error::Integrity)?;
                    engine.supply_record(revision, envelope.len() as u64, Some(&envelope))?;
                }
                AuditRequest::Done => break,
            }
        }
        let records: i64 = tx
            .query_row("SELECT count(*) FROM source_records", [], |r| r.get(0))
            .storage()?;
        let nodes: i64 = tx
            .query_row("SELECT count(*) FROM source_nodes", [], |r| r.get(0))
            .storage()?;
        engine.finish_audit(
            u64::try_from(records).map_err(|_| Error::Integrity)?,
            u64::try_from(nodes).map_err(|_| Error::Integrity)?,
        )?;
        engine.activate_audit()?;
        let target = meta(
            &tx,
            "target_descriptor",
            target_admission.max_descriptor_bytes,
        )?;
        let checkpoint = meta(&tx, "checkpoint", 138)?;
        let transition = ProtectiveTransition::resume(
            &engine,
            &target,
            &checkpoint,
            target_auth,
            provider,
            target_admission,
            &state,
            &mut StageNodes {
                db: &tx,
                source: false,
            },
        )?;
        let plan = transition.finish(
            &engine,
            &mut StageNodes {
                db: &tx,
                source: false,
            },
            &state,
        )?;
        if plan.target_snapshot().descriptor_digest != ticket.target_descriptor
            || transition.owner_commitment() != ticket.commitment
            || meta(&tx, "target_head", INDEX_HEAD_LEN)? != plan.head_bytes
        {
            return Err(Error::Conflict);
        }
        let record_count = u64::from_be_bytes(
            meta(&tx, "record_count", 8)?
                .try_into()
                .map_err(|_| Error::Integrity)?,
        );
        let target_records: i64 = tx
            .query_row("SELECT count(*) FROM target_records", [], |r| r.get(0))
            .storage()?;
        let target_nodes: i64 = tx
            .query_row("SELECT count(*) FROM index_nodes", [], |r| r.get(0))
            .storage()?;
        let expected_nodes = record_count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        if record_count != plan.record_count
            || u64::try_from(target_records).map_err(|_| Error::Integrity)? != record_count
            || u64::try_from(target_nodes).map_err(|_| Error::Integrity)? != expected_nodes
        {
            return Err(Error::Integrity);
        }
        tx.commit().storage()?;
        // Replace only after authentication, complete source/target audit and
        // exact pending-owner checks succeed. Failure leaves the old locked
        // vault handle unchanged.
        self.engine.lock();
        self.engine = engine;
        Ok(PreparedProtection {
            transition: Some(transition),
            ticket: *ticket,
            work: self.engine.begin_host_work()?,
            plan: Some(plan),
            submitted: false,
            authorized: false,
        })
    }
}

#[cfg(test)]
fn protective_test_pause(phase: &str) -> Result<()> {
    if std::env::var("FOGVAULT_PROTECTIVE_PAUSE").ok().as_deref() == Some(phase) {
        use std::io::Write;
        let marker = std::env::var_os("FOGVAULT_PROTECTIVE_MARKER").ok_or(Error::Storage)?;
        std::fs::write(marker, phase).map_err(|_| Error::Storage)?;
        println!("PROTECTIVE_PAUSE_READY {phase}");
        std::io::stdout().flush().map_err(|_| Error::Storage)?;
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
#[cfg(not(test))]
fn protective_test_pause(_: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fogvault::{ProviderCapabilityKind, ProviderContext, ProviderError, ProviderResult};
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };
    use zeroize::Zeroizing;
    struct Provider;
    impl KeyProvider for Provider {
        fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
            ProviderCapabilityKind::RawSecret
        }
        fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
            Err(ProviderError::Unsupported)
        }
        fn unwrap_seed(
            &mut self,
            _: &ProviderContext,
            _: &[u8],
        ) -> ProviderResult<Zeroizing<[u8; 32]>> {
            Err(ProviderError::Unsupported)
        }
    }
    fn limits() -> Limits {
        Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 8,
            max_records: 3,
        }
    }
    fn admission() -> AccessAdmission {
        AccessAdmission {
            allowed_profiles: vec![AccessProfile::Portable],
            providers: vec![],
            max_descriptor_bytes: 276,
            max_device_slots: 0,
            max_provider_blob_bytes: 0,
        }
    }
    const OLD: &[u8] = b"SYNTHETIC-process-source";
    const NEW: &[u8] = b"SYNTHETIC-process-target";
    const REQUEST: [u8; 16] = [0x73; 16];
    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    fn native_protective_process_fixture() {
        let Some(base) = std::env::var_os("FOGVAULT_PROTECTIVE_ROOT") else {
            return;
        };
        let base = PathBuf::from(base);
        let host = NativeHost::create_new(base.join("control")).unwrap();
        let (mut vault, key) = host
            .create_with_access(
                base.join("vault.sqlite"),
                OLD,
                limits(),
                KdfPolicy::baseline(),
                admission(),
                AccessProfile::Portable,
                &[],
                true,
                &mut Provider,
            )
            .unwrap();
        let token = vault
            .unlock_access(AccessPath::Password(OLD), &mut Provider)
            .unwrap();
        for n in 1..=3 {
            vault
                .save(&token, [n; 16], None, &[n], &[n; 8], [n; 16])
                .unwrap();
        }
        let key = key.unwrap();
        vault.lock();
        vault.recover_access(&key).unwrap();
        let (mut draft, _) = vault
            .prepare_recovery_replacement(
                &key,
                NEW,
                AccessProfile::Portable,
                &[],
                true,
                &mut Provider,
                admission(),
                REQUEST,
            )
            .unwrap();
        std::fs::write(base.join("trusted-owner-ticket"), draft.ticket().encode()).unwrap();
        vault.commit_protection(&mut draft).unwrap();
        panic!("selected durable pause was not reached");
    }
    #[test]
    fn maintained_native_bulk_parent_death_resumes_exact_target_at_durable_boundaries() {
        for phase in [
            "after-preparation",
            "after-stage",
            "after-submission",
            "after-vault-commit",
        ] {
            let scratch = tempfile::tempdir().unwrap();
            let marker = scratch.path().join("observed-boundary");
            let mut child = Process(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "native::protective::tests::native_protective_process_fixture",
                        "--nocapture",
                    ])
                    .env("FOGVAULT_PROTECTIVE_ROOT", scratch.path())
                    .env("FOGVAULT_PROTECTIVE_PAUSE", phase)
                    .env("FOGVAULT_PROTECTIVE_MARKER", &marker)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let mut reader = BufReader::new(child.0.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "child exited before durable marker at {phase}"
                );
                if line.contains(&format!("PROTECTIVE_PAUSE_READY {phase}")) {
                    break;
                }
            }
            assert!(marker.is_file());
            child.0.kill().unwrap();
            assert!(!child.0.wait().unwrap().success());
            let ticket = ProtectionTicket::from_trusted_bytes(
                &std::fs::read(scratch.path().join("trusted-owner-ticket")).unwrap(),
            )
            .unwrap();
            let host = NativeHost::open_required(scratch.path().join("control")).unwrap();
            let path = scratch.path().join("vault.sqlite");
            let mut vault = host
                .open_with_access(&path, limits(), KdfPolicy::baseline(), admission())
                .unwrap();
            if phase == "after-preparation" {
                assert!(vault
                    .registered_control_state()
                    .unwrap()
                    .pending()
                    .unwrap()
                    .submission()
                    .is_none());
                vault.abandon_protection(&ticket).unwrap();
                let token = vault
                    .unlock_access(AccessPath::Password(OLD), &mut Provider)
                    .unwrap();
                assert_eq!(
                    vault.read(&token, [3; 16]).unwrap().payload.as_slice(),
                    &[3; 8]
                );
                continue;
            }
            let mut draft = vault
                .resume_protection(
                    &ticket,
                    ProtectiveSource::Password(OLD),
                    Some(admission()),
                    AccessPath::Password(NEW),
                    admission(),
                    &mut Provider,
                )
                .unwrap();
            let receipt = vault.commit_protection(&mut draft).unwrap();
            assert_eq!(
                receipt.key_effect,
                fogvault::KeyEffect::FreshRootAndContentKeys
            );
            for n in 1..=3 {
                assert_eq!(
                    vault
                        .read(&receipt.session, [n; 16])
                        .unwrap()
                        .payload
                        .as_slice(),
                    &[n; 8]
                );
            }
            drop(vault);
            let mut reopened = host
                .open_with_access(&path, limits(), KdfPolicy::baseline(), admission())
                .unwrap();
            assert!(reopened
                .unlock_access(AccessPath::Password(OLD), &mut Provider)
                .is_err());
            reopened
                .unlock_access(AccessPath::Password(NEW), &mut Provider)
                .unwrap();
        }
    }
}
