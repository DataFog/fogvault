//! Child-process fixture driven by scripts/verify-trusted-control.py.
//! One synthetic record proves restart ordering; it is not a bulk adapter.
use super::*;
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, ControlObservation, ControlOperation, KeyProvider,
    ProtectiveSource, ProtectiveTransition, ProviderCapabilityKind, ProviderContext, ProviderError,
    ProviderIdentity, ProviderResult, SnapshotIdentity, TransitionStore, TrustedControlStore,
};
use std::{collections::BTreeMap, io::Read};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"synthetic-control-proof-password";
const PAYLOAD: &[u8] = b"synthetic encrypted control-state restart payload";
const ID: [u8; 16] = [0x41; 16];
const REQUEST: [u8; 16] = [0x42; 16];
const REGISTRATION: [u8; 16] = [0x43; 16];
fn identity() -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [1; 16],
        key_id: [2; 16],
        device_bound: true,
        nonexportable: true,
    }
}
fn admission() -> AccessAdmission {
    AccessAdmission {
        allowed_profiles: vec![
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ],
        providers: vec![identity()],
        max_descriptor_bytes: 388,
        max_device_slots: 1,
        max_provider_blob_bytes: 72,
    }
}
struct Provider;
impl KeyProvider for Provider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, c: &ProviderContext, s: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        if std::env::var_os("FOGVAULT_CONTROL_PROVIDER_UNAVAILABLE").is_some() {
            return Err(ProviderError::Unavailable);
        }
        crate::crypto::seal(&[0x51; 32], &c.authenticated_bytes(), s)
            .map_err(|_| ProviderError::Failure)
    }
    fn unwrap_seed(
        &mut self,
        c: &ProviderContext,
        b: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        if std::env::var_os("FOGVAULT_CONTROL_PROVIDER_UNAVAILABLE").is_some() {
            return Err(ProviderError::Unavailable);
        }
        let value = crate::crypto::open(&[0x51; 32], &c.authenticated_bytes(), b)
            .map_err(|_| ProviderError::InvalidResponse)?;
        Ok(Zeroizing::new(
            value
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::InvalidResponse)?,
        ))
    }
}
const STAGE_MAGIC: &str = "FGV-CONTROL-PROOF1";
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing String");
    }
    output
}
fn payload() -> Vec<u8> {
    if std::env::var_os("FOGVAULT_CONTROL_MAXIMUM").is_some() {
        vec![0x5a; limits().max_payload_bytes]
    } else {
        PAYLOAD.to_vec()
    }
}
fn metadata() -> Vec<u8> {
    if std::env::var_os("FOGVAULT_CONTROL_MAXIMUM").is_some() {
        vec![0x6b; limits().max_metadata_bytes]
    } else {
        vec![]
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 64,
        max_records: 4,
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    records: BTreeMap<RecordId, (u64, Vec<u8>)>,
}
impl NodeStore for Snapshot {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if self.nodes.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, bytes.to_vec());
        Ok(())
    }
}
impl TransitionStore for Snapshot {
    fn staged_record(&mut self, id: &RecordId, maximum: usize) -> Result<Option<(u64, Vec<u8>)>> {
        if self.records.get(id).is_some_and(|(_, b)| b.len() > maximum) {
            return Err(Error::ResourceLimit);
        }
        Ok(self.records.get(id).cloned())
    }
}
fn open_engine(descriptor: &[u8]) -> Result<Engine> {
    if descriptor.get(12..14) == Some([0, 3].as_slice()) {
        Engine::open_epoch_access(
            descriptor,
            limits(),
            fogvault::KdfPolicy::baseline(),
            admission(),
        )
    } else {
        Engine::diagnostic_open_with_access(
            descriptor,
            limits(),
            fogvault::KdfPolicy::baseline(),
            admission(),
        )
    }
}
fn path_for(engine: &Engine) -> Result<AccessPath<'static>> {
    let info = engine.access_info()?;
    if info.profile == AccessProfile::PasswordAndDevice {
        Ok(AccessPath::Device {
            slot_id: info.device_slots.first().ok_or(Error::Integrity)?.0,
            password: Some(PASSWORD),
        })
    } else {
        Ok(AccessPath::Password(PASSWORD))
    }
}
impl Snapshot {
    fn identity(&self) -> Result<SnapshotIdentity> {
        Ok(SnapshotIdentity {
            descriptor_digest: crate::crypto::digest(&self.descriptor),
            head_digest: crate::crypto::digest(&self.head),
            generation: u64::from_be_bytes(
                self.head
                    .get(..8)
                    .ok_or(Error::Integrity)?
                    .try_into()
                    .map_err(|_| Error::Integrity)?,
            ),
        })
    }
    fn read(path: &Path) -> Result<Self> {
        Self::read_admitted(path, None)
    }
    fn read_admitted(path: &Path, maximum: Option<usize>) -> Result<Self> {
        let mut connection = connect(path, false)?;
        let transaction = connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            limits(),
            &mut OperationMetrics::default(),
            admission().max_descriptor_bytes,
        )?;
        let maximum_envelope_bytes = match maximum {
            Some(value) => value,
            None => open_engine(&descriptor)?.envelope_byte_limit()?,
        };
        let record_count: i64 = transaction
            .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
            .storage()?;
        let node_count: i64 = transaction
            .query_row("SELECT count(*) FROM index_nodes", [], |r| r.get(0))
            .storage()?;
        if record_count < 0
            || record_count > limits().max_records as i64
            || node_count < 0
            || node_count > 2 * limits().max_records as i64 - 1
        {
            return Err(Error::ResourceLimit);
        }
        let mut records = BTreeMap::new();
        let mut statement = transaction
            .prepare(
                "SELECT id,revision,length(envelope) FROM records WHERE length(id)=16 ORDER BY id",
            )
            .storage()?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .storage()?;
        for row in rows {
            let (id, revision, length) = row.storage()?;
            admitted_length(length, maximum_envelope_bytes)?;
            let id: RecordId = id.try_into().map_err(|_| Error::Integrity)?;
            let envelope = load_record_admitted(
                &transaction,
                &id,
                true,
                maximum_envelope_bytes,
                &mut OperationMetrics::default(),
            )?
            .envelope
            .ok_or(Error::Integrity)?;
            records.insert(
                id,
                (
                    u64::try_from(revision).map_err(|_| Error::Integrity)?,
                    envelope,
                ),
            );
        }
        drop(statement);
        let mut nodes = BTreeMap::new();
        let mut statement = transaction
            .prepare(
                "SELECT hash,length(bytes) FROM index_nodes WHERE length(hash)=32 ORDER BY hash",
            )
            .storage()?;
        let rows = statement
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
            .storage()?;
        for row in rows {
            let (hash, length) = row.storage()?;
            admitted_length(length, MAX_NODE_BYTES)?;
            let hash: NodeHash = hash.try_into().map_err(|_| Error::Integrity)?;
            let bytes = SqliteNodes::new(&transaction, 1)
                .get(&hash)?
                .ok_or(Error::Integrity)?;
            nodes.insert(hash, bytes);
        }
        drop(statement);
        if records.len() != record_count as usize || nodes.len() != node_count as usize {
            return Err(Error::Integrity);
        }
        transaction.commit().storage()?;
        Ok(Self {
            descriptor,
            head,
            nodes,
            records,
        })
    }
    fn audited_engine(&self) -> Result<Engine> {
        let mut engine = open_engine(&self.descriptor)?;
        let path = path_for(&engine)?;
        engine.begin_unlock_access(path, &mut Provider)?;
        engine.begin_audit(&self.head)?;
        loop {
            match engine.audit_next()? {
                AuditRequest::Node(hash) => {
                    engine.supply_node(self.nodes.get(&hash).ok_or(Error::Integrity)?)?
                }
                AuditRequest::Record { id, .. } => {
                    let (revision, bytes) = self.records.get(&id).ok_or(Error::Integrity)?;
                    engine.supply_record(*revision, bytes.len() as u64, Some(bytes))?;
                }
                AuditRequest::Done => break,
            }
        }
        engine.finish_audit(self.records.len() as u64, self.nodes.len() as u64)?;
        assert!(engine.current_session().is_err()); // No publication during audit.
        Ok(engine)
    }
    fn encoded(&self) -> Vec<u8> {
        let mut lines = vec![
            STAGE_MAGIC.to_string(),
            format!("D:{}", hex(&self.descriptor)),
            format!("H:{}", hex(&self.head)),
        ];
        for (hash, bytes) in &self.nodes {
            lines.push(format!("N:{}:{}", hex(hash), hex(bytes)));
        }
        for (id, (revision, bytes)) in &self.records {
            lines.push(format!("R:{}:{revision}:{}", hex(id), hex(bytes)));
        }
        lines.push("END".into());
        lines.join("\n").into_bytes()
    }
    fn stage(path: &Path) -> Result<Self> {
        // Admit the bounded first descriptor line before selecting a profile's
        // envelope allocation. P2+168 must not reject C3+176 boundary records.
        let mut prefix = Vec::new();
        File::open(path)
            .map_err(|_| Error::Storage)?
            .take((STAGE_MAGIC.len() + 4 + 2 * admission().max_descriptor_bytes + 1) as u64)
            .read_to_end(&mut prefix)
            .map_err(|_| Error::Storage)?;
        let mut header = prefix.splitn(3, |byte| *byte == b'\n');
        if header.next() != Some(STAGE_MAGIC.as_bytes()) {
            return Err(Error::Integrity);
        }
        let descriptor_line = header.next().ok_or(Error::Integrity)?;
        if header.next().is_none() {
            return Err(Error::Integrity);
        }
        let selected_descriptor = decode_hex(
            std::str::from_utf8(
                descriptor_line
                    .strip_prefix(b"D:")
                    .ok_or(Error::Integrity)?,
            )
            .map_err(|_| Error::Integrity)?,
        )?;
        let maximum_envelope_bytes = open_engine(&selected_descriptor)?.envelope_byte_limit()?;
        // Derive the diagnostic frame bound from its selected fixture capacity,
        // exact envelope bound and fixed node widths, including hex expansion.
        let maximum = STAGE_MAGIC.len()
            + 1
            + 2 * admission().max_descriptor_bytes
            + 3
            + 2 * fogvault::INDEX_HEAD_LEN
            + 3
            + (2 * limits().max_records - 1) * (2 * (32 + MAX_NODE_BYTES) + 5)
            + limits().max_records * (2 * (16 + maximum_envelope_bytes) + 20 + 5)
            + 4;
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Error::Storage)?
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.len() > maximum {
            return Err(Error::ResourceLimit);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Integrity)?;
        let mut lines = text.lines();
        if lines.next() != Some(STAGE_MAGIC) {
            return Err(Error::Integrity);
        }
        let descriptor = decode_hex(
            lines
                .next()
                .and_then(|l| l.strip_prefix("D:"))
                .ok_or(Error::Integrity)?,
        )?;
        if descriptor != selected_descriptor {
            return Err(Error::Integrity);
        }
        let head = decode_hex(
            lines
                .next()
                .and_then(|l| l.strip_prefix("H:"))
                .ok_or(Error::Integrity)?,
        )?;
        let mut snapshot = Self {
            descriptor,
            head,
            nodes: BTreeMap::new(),
            records: BTreeMap::new(),
        };
        let mut ended = false;
        for line in lines {
            if ended {
                return Err(Error::Integrity);
            }
            if line == "END" {
                ended = true;
                continue;
            }
            let parts: Vec<_> = line.split(':').collect();
            match parts.as_slice() {
                ["N", hash, body] => {
                    let hash = decode_hex(hash)?.try_into().map_err(|_| Error::Integrity)?;
                    if snapshot.nodes.insert(hash, decode_hex(body)?).is_some() {
                        return Err(Error::Integrity);
                    }
                }
                ["R", id, revision, body] => {
                    let id = decode_hex(id)?.try_into().map_err(|_| Error::Integrity)?;
                    let number = revision.parse::<u64>().map_err(|_| Error::Integrity)?;
                    if number.to_string() != *revision
                        || snapshot
                            .records
                            .insert(id, (number, decode_hex(body)?))
                            .is_some()
                    {
                        return Err(Error::Integrity);
                    }
                }
                _ => return Err(Error::Integrity),
            }
        }
        if !ended
            || snapshot.nodes.len() > 2 * limits().max_records - 1
            || snapshot.records.len() > limits().max_records
        {
            return Err(Error::Integrity);
        }
        if snapshot.encoded() != bytes {
            return Err(Error::Integrity);
        }
        Ok(snapshot)
    }
}
fn decode_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::Integrity);
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let n = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(Error::Integrity),
            };
            Ok(n(p[0])? * 16 + n(p[1])?)
        })
        .collect()
}
fn stored(
    store: &mut ProtectedControlSqliteStore,
    expected: Option<&ControlState>,
    next: &ControlState,
) -> Result<()> {
    match store.compare_exchange(expected, next)? {
        ControlWriteOutcome::Stored => Ok(()),
        ControlWriteOutcome::Conflict => Err(Error::Conflict),
        ControlWriteOutcome::Unknown => Err(Error::OutcomeUnknown {
            request_id: REQUEST,
        }),
    }
}
fn completed(guard: &mut ControlPublicationGuard<'_>, next: &ControlState) -> Result<()> {
    match guard.compare_exchange(next) {
        Ok(ControlWriteOutcome::Stored) => Ok(()),
        _ => Err(Error::OutcomeUnknown {
            request_id: REQUEST,
        }),
    }
}
fn pause(point: &str, root: &Path) {
    if std::env::var("FOGVAULT_CONTROL_PAUSE").ok().as_deref() == Some(point) {
        std::fs::write(root.join(format!("reached-{point}")), b"ready").unwrap();
        loop {
            if std::env::var_os("FOGVAULT_CONTROL_RELEASE_ON_FILE").is_some()
                && root.join(format!("release-{point}")).exists()
            {
                break;
            }
            std::thread::park_timeout(std::time::Duration::from_millis(20));
        }
    }
}
fn publish(
    path: &Path,
    source: &ControlState,
    prior: &Snapshot,
    target: &Snapshot,
    prior_maximum_envelope_bytes: usize,
) -> Result<()> {
    let mut connection = connect(path, false)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .storage()?;
    let (descriptor, head) = load_header(
        &transaction,
        limits(),
        &mut OperationMetrics::default(),
        admission().max_descriptor_bytes,
    )?;
    let live = SnapshotIdentity {
        descriptor_digest: crate::crypto::digest(&descriptor),
        head_digest: crate::crypto::digest(&head),
        generation: u64::from_be_bytes(head[..8].try_into().map_err(|_| Error::Integrity)?),
    };
    if live != source.accepted() {
        return Err(Error::Conflict);
    }
    if source.pending().and_then(|p| p.submission()) != Some(target.identity()?) {
        return Err(Error::Conflict);
    }
    // Recheck the captured complete source inside the atomic writer snapshot.
    for (table, expected) in [
        ("records", prior.records.len()),
        ("index_nodes", prior.nodes.len()),
    ] {
        let sql = format!("SELECT count(*) FROM {table}");
        let count: i64 = transaction.query_row(&sql, [], |r| r.get(0)).storage()?;
        if count != expected as i64 {
            return Err(Error::Integrity);
        }
    }
    for (id, (revision, envelope)) in &prior.records {
        let row = load_record_admitted(
            &transaction,
            id,
            true,
            prior_maximum_envelope_bytes,
            &mut OperationMetrics::default(),
        )?;
        if row.revision != *revision || row.envelope.as_deref() != Some(envelope.as_slice()) {
            return Err(Error::Integrity);
        }
    }
    for (hash, bytes) in &prior.nodes {
        if SqliteNodes::new(&transaction, 1).get(hash)?.as_deref() != Some(bytes.as_slice()) {
            return Err(Error::Integrity);
        }
    }
    transaction.execute("DELETE FROM records", []).storage()?;
    transaction
        .execute("DELETE FROM index_nodes", [])
        .storage()?;
    for (hash, bytes) in &target.nodes {
        transaction
            .execute(
                "INSERT INTO index_nodes VALUES(?1,?2)",
                params![hash, bytes],
            )
            .storage()?;
    }
    for (id, (revision, bytes)) in &target.records {
        transaction
            .execute(
                "INSERT INTO records VALUES(?1,?2,?3)",
                params![id, *revision as i64, bytes],
            )
            .storage()?;
    }
    if transaction
        .execute(
            "UPDATE vault_state SET descriptor=?1,head=?2 WHERE id=1 AND descriptor=?3 AND head=?4",
            params![target.descriptor, target.head, descriptor, head],
        )
        .storage()?
        != 1
    {
        return Err(Error::Conflict);
    }
    transaction.commit().map_err(|_| Error::OutcomeUnknown {
        request_id: REQUEST,
    })
}

fn run(mode: &str, root: &Path, control_database: &Path) -> Result<String> {
    let path = root.join("vault.sqlite");
    let stage = root.join("candidate.stage");
    if mode == "init" {
        let (creation, _) = Vault::diagnostic_prepare_access_creation(
            PASSWORD,
            limits(),
            fogvault::KdfPolicy::baseline(),
            admission(),
            AccessProfile::PasswordOrDevice,
            &[identity()],
            false,
            &mut Provider,
        )?;
        let mut vault = creation.publish(&path, CommitFault::None)?;
        let token = vault.unlock_access(AccessPath::Password(PASSWORD), &mut Provider)?;
        vault.save(&token, ID, None, &metadata(), &payload(), [0x40; 16])?;
    }
    let current = Snapshot::read(&path)?;
    let header_engine = open_engine(&current.descriptor)?;
    let presented_vault = header_engine.vault_id();
    let vault = if mode == "init" {
        presented_vault
    } else {
        let encoded = std::env::var("FOGVAULT_CONTROL_VAULT").map_err(|_| Error::Integrity)?;
        let expected: [u8; 16] = decode_hex(&encoded)?
            .try_into()
            .map_err(|_| Error::Integrity)?;
        if expected != presented_vault {
            return Err(Error::Integrity);
        }
        expected
    };
    let lock_path = PathBuf::from(std::env::var_os("FOGVAULT_CONTROL_LOCK").ok_or(Error::Storage)?);
    if mode == "init" {
        let mut engine = current.audited_engine()?;
        let state = ControlState::register(vault, REGISTRATION, current.identity()?);
        let _store =
            ProtectedControlSqliteStore::create_new(control_database.to_owned(), lock_path, state)?;
        engine.activate_audit()?;
        println!("CONTROL_VAULT={}", hex(&vault));
        return Ok("registered".into());
    }
    let mut store = ProtectedControlSqliteStore::open_required(
        control_database.to_owned(),
        lock_path,
        vault,
        REGISTRATION,
    )?;
    // Missing required state never registers itself from a valid vault.
    let state = store.load()?.ok_or(Error::Integrity)?;
    if mode == "pending" {
        return Ok(match state.pending() {
            Some(p) => format!("pending-request-{}", hex(&p.request_id)),
            None => "no-pending".into(),
        });
    }
    if mode == "anchor" {
        return Ok(format!("anchor-generation-{}", state.accepted().generation));
    }
    state.observe(current.identity()?)?; // Reject unselected snapshots before provider/KDF work.
    let mut engine = current.audited_engine()?;
    if mode == "bad-reset" || mode == "bad-registration" {
        let registration = if mode == "bad-registration" {
            [0x99; 16]
        } else {
            REGISTRATION
        };
        let reset = ControlState::register(vault, registration, state.accepted());
        stored(&mut store, Some(&state), &reset)?;
        return Err(Error::Integrity); // Reset must never be accepted.
    }
    if mode == "advance" {
        if state.observe(current.identity()?)? != ControlObservation::Accepted {
            return Err(Error::Conflict);
        }
        engine.activate_audit()?;
        let work = engine.begin_host_work()?;
        let mut target = current.clone();
        let (revision, envelope) = current.records.get(&ID).ok_or(Error::Integrity)?;
        let plan = engine.prepare_save(
            &mut target,
            ID,
            Some(*revision),
            &metadata(),
            b"synthetic later accepted commit C",
            [0x44; 16],
            Some(fogvault::StoredRecord {
                revision: *revision,
                envelope,
            }),
        )?;
        for obsolete in &plan.obsolete {
            target.nodes.remove(obsolete);
        }
        target.records.insert(ID, (plan.revision, plan.envelope));
        target.head = plan.head_bytes;
        let candidate = target.audited_engine()?; // All provider/KDF work before fence.
        let maximum_envelope_bytes = candidate.envelope_byte_limit()?;
        let source_maximum = engine.envelope_byte_limit()?;
        let prepared = state.prepare(
            ControlOperation::Save,
            [0x44; 16],
            crate::crypto::digest(&target.descriptor),
            crate::crypto::digest(&target.head),
        )?;
        stored(&mut store, Some(&state), &prepared)?;
        let submission = prepared.authorize_submission(target.identity()?)?;
        stored(&mut store, Some(&prepared), &submission)?;
        // Private synchronous prepared Engine is not published while control
        // records Submitted; failures retain that durable host barrier.
        let confirmed = submission.confirm_target(target.identity()?)?;
        let mut guard = store.publication_guard(&submission)?;
        work.check()?;
        publish(&path, &submission, &current, &target, source_maximum)?;
        if Snapshot::read_admitted(&path, Some(maximum_envelope_bytes)).map_err(|_| {
            Error::OutcomeUnknown {
                request_id: [0x44; 16],
            }
        })? != target
        {
            return Err(Error::OutcomeUnknown {
                request_id: [0x44; 16],
            });
        }
        completed(&mut guard, &confirmed)?;
        engine
            .confirm_commit(&target.head)
            .map_err(|_| Error::OutcomeUnknown {
                request_id: [0x44; 16],
            })?;
        return Ok("accepted-later-C".into());
    }
    if mode == "cas-inflight" {
        let id = std::env::var("FOGVAULT_CONTROL_CAS_ID")
            .ok()
            .map(|s| s.parse::<u8>())
            .transpose()
            .map_err(|_| Error::Integrity)?
            .unwrap_or(0x61);
        let next = state.prepare(
            ControlOperation::Save,
            [id; 16],
            state.accepted().descriptor_digest,
            [id; 32],
        )?;
        stored(&mut store, Some(&state), &next)?;
        return Ok("control-update-committed".into());
    }
    if mode == "race" {
        if state.observe(current.identity()?)? != ControlObservation::Accepted {
            return Err(Error::Conflict);
        }
        let request = std::env::var("FOGVAULT_CONTROL_RACE_ID")
            .map_err(|_| Error::Storage)?
            .parse::<u8>()
            .map_err(|_| Error::Integrity)?;
        std::fs::write(root.join(format!("race-ready-{request}")), b"ready")
            .map_err(|_| Error::Storage)?;
        while !root.join("race-go").exists() {
            std::thread::yield_now();
        }
        let next = state.prepare(
            ControlOperation::Save,
            [request; 16],
            state.accepted().descriptor_digest,
            [request; 32],
        )?;
        return Ok(format!(
            "race-{:?}",
            store.compare_exchange(Some(&state), &next)?
        ));
    }
    if mode == "abandon" {
        let next = state.abandon_unsubmitted()?;
        stored(&mut store, Some(&state), &next)?;
        return Ok("abandoned-unsubmitted".into());
    }
    if mode == "prepare" {
        if state.observe(current.identity()?)? != ControlObservation::Accepted {
            return Err(Error::Conflict);
        }
        engine.activate_audit()?;
        let (transition, _) = engine.draft_protective_transition(
            ProtectiveSource::Access(AccessPath::Password(PASSWORD)),
            PASSWORD,
            AccessProfile::PasswordAndDevice,
            &[identity()],
            false,
            &mut Provider,
            admission(),
            REQUEST,
        )?;
        let prepared = state.prepare(
            ControlOperation::ProtectiveTransition,
            REQUEST,
            transition.target_descriptor_digest(),
            transition.owner_commitment(),
        )?;
        stored(&mut store, Some(&state), &prepared)?;
        pause("intent", root);
        let mut transition = transition;
        let mut target = Snapshot {
            descriptor: transition.target_descriptor_bytes().to_vec(),
            head: vec![],
            nodes: BTreeMap::new(),
            records: BTreeMap::new(),
        };
        for (id, (revision, envelope)) in &current.records {
            let mut source_nodes = current.clone();
            let lookup = engine.protective_lookup(&mut source_nodes, id)?;
            let encrypted = transition.transform_record(
                &engine,
                lookup.entry().ok_or(Error::Integrity)?,
                *revision,
                envelope,
                &mut target,
                &prepared,
            )?;
            target.records.insert(*id, (*revision, encrypted));
        }
        let checkpoint = transition.checkpoint(&engine, &prepared)?;
        let plan = transition.finish(&engine, &mut target, &prepared)?;
        target.head = plan.head_bytes;
        persist(&stage, &target.encoded())?;
        persist(&root.join("candidate.checkpoint"), &checkpoint)?;
        File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
        pause("stage", root);
        return finish(
            root, &path, &mut store, prepared, current, engine, transition, target,
        );
    }
    if mode == "resume" || mode == "republish-exact" {
        let pending = state.pending().ok_or(Error::Conflict)?;
        if pending.submission().is_some() && mode != "republish-exact" {
            return Err(Error::OutcomeUnknown {
                request_id: pending.request_id,
            });
        }
        let observation = state.observe(current.identity()?)?;
        if if mode == "republish-exact" {
            !matches!(observation, ControlObservation::StillUnknown { .. })
                || pending.submission().is_none()
        } else {
            observation != ControlObservation::StagingSource
        } {
            return Err(Error::Conflict);
        }
        // Private source authority is confined to the dedicated transition;
        // no ordinary source handle/plaintext is returned while unresolved.
        engine.activate_audit()?;
        let mut target = Snapshot::stage(&stage)?;
        let mut checkpoint = Vec::new();
        File::open(root.join("candidate.checkpoint"))
            .map_err(|_| Error::Storage)?
            .take(139)
            .read_to_end(&mut checkpoint)
            .map_err(|_| Error::Storage)?;
        let target_engine = open_engine(&target.descriptor)?;
        let target_path = path_for(&target_engine)?;
        let transition = ProtectiveTransition::resume(
            &engine,
            &target.descriptor.clone(),
            &checkpoint,
            target_path,
            &mut Provider,
            admission(),
            &state,
            &mut target,
        )?;
        let plan = transition.finish(&engine, &mut target, &state)?;
        if target.head != plan.head_bytes {
            return Err(Error::Integrity);
        }
        return finish(
            root, &path, &mut store, state, current, engine, transition, target,
        );
    }
    if mode == "status" {
        let observation = state.observe(current.identity()?)?;
        if matches!(observation, ControlObservation::StillUnknown { .. }) {
            return Ok("still-unknown-no-activation".into());
        }
        if observation == ControlObservation::StagingSource {
            return Ok("staging-source-no-target-activation".into());
        }
        let maximum_envelope_bytes = engine.envelope_byte_limit()?;
        let completion = if matches!(observation, ControlObservation::TargetObserved { .. }) {
            Some(state.confirm_target(current.identity()?)?)
        } else {
            None
        };
        {
            let mut guard = store.publication_guard(&state)?;
            if Snapshot::read_admitted(&path, Some(maximum_envelope_bytes))? != current {
                return Err(Error::Conflict);
            }
            if let Some(next) = completion {
                completed(&mut guard, &next)?;
            }
            engine.activate_audit()?;
        }
        if let Some((revision, envelope)) = current.records.get(&ID) {
            let mut nodes = current.clone();
            let lookup = engine.lookup(&mut nodes, &ID)?;
            let record = engine.read_verified(
                lookup.entry().ok_or(Error::Integrity)?,
                *revision,
                envelope,
            )?;
            let expected = if *revision == 2 {
                b"synthetic later accepted commit C".to_vec()
            } else {
                payload()
            };
            if record.payload.as_slice() != expected || record.metadata.as_slice() != metadata() {
                return Err(Error::Integrity);
            }
            return Ok(if engine.access_info()?.root_epoch == 0 {
                "accepted-source-readable"
            } else {
                "accepted-target-readable"
            }
            .into());
        }
        return Ok("accepted-source".into());
    }
    Err(Error::Malformed("control proof mode"))
}
fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| Error::Storage)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Storage)
}
#[allow(clippy::too_many_arguments)]
fn finish(
    root: &Path,
    path: &Path,
    store: &mut ProtectedControlSqliteStore,
    state: ControlState,
    source: Snapshot,
    mut engine: Engine,
    transition: ProtectiveTransition,
    mut target: Snapshot,
) -> Result<String> {
    let plan = transition.finish(&engine, &mut target, &state)?;
    if target.head != plan.head_bytes || target.descriptor != plan.descriptor_bytes {
        return Err(Error::Integrity);
    }
    let mut cursor = crate::index::AuditCursor::new(
        plan.index_root,
        plan.record_count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0),
    );
    let mut reachable_nodes = BTreeMap::new();
    let mut reachable_records = BTreeMap::new();
    while let Some(hash) = cursor.next_hash()? {
        let bytes = target.nodes.get(&hash).ok_or(Error::Integrity)?.clone();
        if let Some((id, _)) = cursor.supply(&bytes)? {
            reachable_records.insert(id, target.records.get(&id).ok_or(Error::Integrity)?.clone());
        }
        reachable_nodes.insert(hash, bytes);
    }
    cursor.finish()?;
    if reachable_records.len() as u64 != plan.record_count {
        return Err(Error::Integrity);
    }
    target.nodes = reachable_nodes;
    target.records = reachable_records;
    let target_candidate = target.audited_engine()?;
    let maximum_envelope_bytes = target_candidate.envelope_byte_limit()?;
    let source_maximum = engine.envelope_byte_limit()?;
    let submission = if let Some(exact) = state.pending().and_then(|p| p.submission()) {
        // Reinstall only the original fully authorized B after observing A.
        // This resolves uncertainty without claiming that B never committed.
        if exact != plan.target_snapshot() {
            return Err(Error::Conflict);
        }
        state
    } else {
        let submission = state.authorize_submission(plan.target_snapshot())?;
        stored(store, Some(&state), &submission)?;
        submission
    };
    let confirmed = submission.confirm_target(plan.target_snapshot())?;
    let host_work = engine.begin_host_work()?;
    engine.authorize_protective_submission(&transition, &plan, &submission)?;
    pause("submission", root);
    pause("before-publication", root);
    let mut guard = store.publication_guard(&submission)?;
    host_work.check()?;
    publish(path, &submission, &source, &target, source_maximum)?;
    pause("commit", root);
    let actual = Snapshot::read_admitted(path, Some(maximum_envelope_bytes)).map_err(|_| {
        Error::OutcomeUnknown {
            request_id: REQUEST,
        }
    })?;
    if actual != target {
        return Err(Error::OutcomeUnknown {
            request_id: REQUEST,
        });
    }
    // Exact bytes were cryptographically validated before acquiring the fence.
    // Readback + atomic writer transaction introduces no postcommit KDF/provider.
    completed(&mut guard, &confirmed)?;
    pause("confirmed", root);
    engine
        .confirm_protective_transition(transition, &confirmed, &actual.descriptor, &actual.head)
        .map_err(|_| Error::OutcomeUnknown {
            request_id: REQUEST,
        })?;
    Ok("committed-and-control-confirmed".into())
}

#[test]
fn native_control_process_fixture() {
    let Ok(mode) = std::env::var("FOGVAULT_CONTROL_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("FOGVAULT_CONTROL_ROOT").expect("fixture root"));
    let control_database = PathBuf::from(
        std::env::var_os("FOGVAULT_CONTROL_DATABASE").expect("fixture control database"),
    );
    match run(&mode, &root, &control_database) {
        Ok(result) => println!("CONTROL_RESULT={result}"),
        Err(error) => {
            println!("CONTROL_ERROR={}", error.code());
            panic!("control proof rejected: {}", error.code());
        }
    }
}
