#![cfg(all(feature = "native", not(target_arch = "wasm32")))]
//! Disposable P2 shadow-snapshot/checkpoint proof, not a maintained rotation API.
use fogvault::{KdfPolicy, KdfProfile};
use fogvault_disposable_prototype::{
    crypto,
    format::{self, Descriptor, Entry, IndexHead},
    index, CommitFault, Error, Limits, RecordId, Result, Vault,
};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{collections::BTreeMap, path::Path};
use tempfile::tempdir;
use zeroize::Zeroizing;

const OLD: &[u8] = b"SYNTHETIC-OLD-ROTATION-PASSWORD";
const NEW: &[u8] = b"SYNTHETIC-NEW-ROTATION-PASSWORD";
const OP: [u8; 16] = [0x72; 16];
const MAGIC: &[u8; 8] = b"FGVROT01";
const STAGING_DOMAIN: &[u8] = b"rotation-staging/v1";
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 256,
        max_metadata_bytes: 32,
        max_records: 4,
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct Nodes(BTreeMap<[u8; 32], Vec<u8>>);
impl index::NodeStore for Nodes {
    fn get(&mut self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(hash).cloned())
    }
    fn put(&mut self, hash: [u8; 32], bytes: &[u8]) -> Result<()> {
        if self.0.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.0.insert(hash, bytes.to_vec());
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    rows: BTreeMap<RecordId, (u64, Vec<u8>)>,
    nodes: Nodes,
}
impl Snapshot {
    fn read(path: &Path) -> Self {
        let mut db = Connection::open(path).unwrap();
        let tx = db.transaction().unwrap();
        let value = Self::capture(&tx).unwrap();
        tx.commit().unwrap();
        value
    }
    fn capture(db: &Connection) -> Result<Self> {
        let (descriptor, head) = db
            .query_row(
                "SELECT descriptor,head FROM vault_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Storage)?;
        let rows = db
            .prepare("SELECT id,revision,envelope FROM records ORDER BY id")
            .map_err(|_| Error::Storage)?
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| Error::Storage)?
            .map(|r| {
                let (id, rev, body) = r.map_err(|_| Error::Storage)?;
                Ok((
                    id.as_slice().try_into().map_err(|_| Error::Integrity)?,
                    (u64::try_from(rev).map_err(|_| Error::Integrity)?, body),
                ))
            })
            .collect::<Result<_>>()?;
        let nodes = db
            .prepare("SELECT hash,bytes FROM index_nodes ORDER BY hash")
            .map_err(|_| Error::Storage)?
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|_| Error::Storage)?
            .map(|r| {
                let (hash, body) = r.map_err(|_| Error::Storage)?;
                Ok((
                    hash.as_slice().try_into().map_err(|_| Error::Integrity)?,
                    body,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            descriptor,
            head,
            rows,
            nodes: Nodes(nodes),
        })
    }
    fn validate(&self, descriptor: &Descriptor, root: &[u8; 32]) -> Result<IndexHead> {
        if self.descriptor != descriptor.bytes() {
            return Err(Error::Integrity);
        }
        let key = crypto::derive(root, &descriptor.vault_id, b"head-authentication")?;
        let head = IndexHead::parse(&self.head, descriptor, &key, limits())?;
        let mut nodes = self.nodes.clone();
        let audit = index::audit(&mut nodes, head.root)?;
        let expected_nodes = if head.count == 0 {
            0
        } else {
            head.count
                .checked_mul(2)
                .and_then(|n| n.checked_sub(1))
                .ok_or(Error::ResourceLimit)?
        };
        if head.count != self.rows.len() as u64
            || self.nodes.0.len() as u64 != expected_nodes
            || audit.entries.len() != self.rows.len()
        {
            return Err(Error::Integrity);
        }
        let wrapping = crypto::derive(root, &descriptor.vault_id, b"record-key-wrapping")?;
        for (id, (revision, body)) in &self.rows {
            if audit.entries.get(id)
                != Some(&Entry {
                    revision: *revision,
                    digest: crypto::digest(body),
                })
            {
                return Err(Error::Integrity);
            }
            format::decrypt_record(descriptor, &wrapping, id, *revision, body, limits())?;
        }
        Ok(head)
    }
}
fn seeded(path: &Path) -> Snapshot {
    let mut vault = Vault::diagnostic_create(path, OLD, limits()).unwrap();
    let token = vault.unlock(OLD).unwrap();
    for value in 0..3u8 {
        let payload = format!("SYNTHETIC-ROTATION-RECORD-{value}-NO-PLAINTEXT-STAGING");
        vault
            .save(
                &token,
                [value; 16],
                None,
                b"sensitive-meta",
                payload.as_bytes(),
                [value + 1; 16],
            )
            .unwrap();
    }
    vault.lock();
    drop(vault);
    Snapshot::read(path)
}

#[derive(Clone)]
struct Staged {
    full: bool,
    progress: u64,
    source_count: u64,
    source_generation: u64,
    root: Option<[u8; 32]>,
    rows: BTreeMap<RecordId, (u64, Vec<u8>)>,
    nodes: Nodes,
}
/// A trusted caller-owned commitment minted only during initial preparation.
/// It is nonsecret, but must not be recovered from the untrusted checkpoint or
/// protected solely by the compromised old root. The proof keeps it in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerReceipt([u8; 32]);
impl OwnerReceipt {
    fn prepared(source: &Snapshot, target: &Descriptor, operation: [u8; 16], full: bool) -> Self {
        let mut input = format::frame(b"fogvault/prototype/rotation-owner/v1");
        input.extend_from_slice(&operation);
        input.extend_from_slice(&crypto::digest(&source.descriptor));
        input.extend_from_slice(&crypto::digest(&source.head));
        input.extend_from_slice(&crypto::digest(target.bytes()));
        input.push(u8::from(full));
        Self(crypto::digest(&input))
    }
    fn check(
        &self,
        source: &Snapshot,
        target: &Descriptor,
        operation: [u8; 16],
        full: bool,
    ) -> Result<()> {
        if self != &Self::prepared(source, target, operation, full) {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}
struct Job {
    source: Snapshot,
    old: Descriptor,
    old_root: Zeroizing<[u8; 32]>,
    target: Descriptor,
    new_root: Zeroizing<[u8; 32]>,
    operation: [u8; 16],
    staged: Staged,
}
impl Job {
    fn new(source: Snapshot, full: bool) -> Result<(Self, OwnerReceipt)> {
        Self::new_with_password(source, full, NEW)
    }
    fn new_with_password(
        source: Snapshot,
        full: bool,
        new_password: &[u8],
    ) -> Result<(Self, OwnerReceipt)> {
        let old = Descriptor::parse(&source.descriptor)?;
        let old_root = old.unlock(OLD)?;
        let head = source.validate(&old, &old_root)?;
        let new_root = Zeroizing::new(crypto::random::<32>()?);
        if new_root.as_slice() == old_root.as_slice() {
            return Err(Error::Integrity);
        }
        let target = old.rewrap(
            &new_root,
            new_password,
            KdfProfile::baseline(),
            &KdfPolicy::baseline(),
        )?;
        let job = Self {
            source,
            old,
            old_root,
            target,
            new_root,
            operation: OP,
            staged: Staged {
                full,
                progress: 0,
                source_count: head.count,
                source_generation: head.generation,
                root: None,
                rows: BTreeMap::new(),
                nodes: Nodes::default(),
            },
        };
        let receipt =
            OwnerReceipt::prepared(&job.source, &job.target, job.operation, job.staged.full);
        Ok((job, receipt))
    }
    fn advance(&mut self) -> Result<()> {
        let (id, (revision, body)) = self
            .source
            .rows
            .iter()
            .nth(usize::try_from(self.staged.progress).map_err(|_| Error::ResourceLimit)?)
            .ok_or(Error::NotFound)?;
        let old_wrap = crypto::derive(&self.old_root, &self.old.vault_id, b"record-key-wrapping")?;
        let new_wrap = crypto::derive(
            &self.new_root,
            &self.target.vault_id,
            b"record-key-wrapping",
        )?;
        let rotated = format::rotate_record(
            &self.old,
            &old_wrap,
            &self.target,
            &new_wrap,
            id,
            *revision,
            body,
            limits(),
            self.staged.full,
        )?;
        let change = index::upsert(
            &mut self.staged.nodes,
            self.staged.root,
            *id,
            Entry {
                revision: *revision,
                digest: crypto::digest(&rotated),
            },
        )?;
        for hash in change.obsolete {
            self.staged.nodes.0.remove(&hash);
        }
        self.staged.root = Some(change.root);
        self.staged.rows.insert(*id, (*revision, rotated));
        self.staged.progress += 1;
        Ok(())
    }
    fn checkpoint(&self) -> Result<Vec<u8>> {
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&1u16.to_be_bytes());
        header.extend_from_slice(&self.operation);
        header.extend_from_slice(&crypto::digest(&self.source.descriptor));
        header.extend_from_slice(&crypto::digest(&self.source.head));
        put_blob(&mut header, self.target.bytes());
        let body = encode_body(&self.staged);
        let sealed_length = body.len().checked_add(40).ok_or(Error::ResourceLimit)?;
        header.extend_from_slice(&(sealed_length as u64).to_be_bytes());
        let key = crypto::derive(&self.new_root, &self.target.vault_id, STAGING_DOMAIN)?;
        let mut aad = format::frame(b"fogvault/prototype/rotation-checkpoint/v1");
        aad.extend_from_slice(&header);
        let encrypted = crypto::seal(&key, &aad, &body)?;
        header.extend_from_slice(&encrypted);
        Ok(header)
    }
    fn target_snapshot(&self, receipt: Option<&OwnerReceipt>) -> Result<Snapshot> {
        receipt.ok_or(Error::Conflict)?.check(
            &self.source,
            &self.target,
            self.operation,
            self.staged.full,
        )?;
        validate_stage(&self.staged, &self.source, &self.target, &self.new_root)?;
        if self.staged.progress != self.staged.source_count {
            return Err(Error::Conflict);
        }
        let operation_key =
            crypto::derive(&self.new_root, &self.target.vault_id, b"operation-identity")?;
        let mut intent = format::frame(b"fogvault/prototype/rotate-p2/v1");
        intent.push(u8::from(self.staged.full));
        intent.extend_from_slice(&crypto::digest(&self.source.descriptor));
        intent.extend_from_slice(&crypto::digest(&self.source.head));
        let head = IndexHead {
            generation: self
                .staged
                .source_generation
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?,
            request_id: self.operation,
            operation_digest: crypto::mac(&operation_key, &intent),
            count: self.staged.source_count,
            root: self.staged.root,
        };
        let head_key = crypto::derive(
            &self.new_root,
            &self.target.vault_id,
            b"head-authentication",
        )?;
        Ok(Snapshot {
            descriptor: self.target.bytes().to_vec(),
            head: head.encode(&self.target, &head_key),
            rows: self.staged.rows.clone(),
            nodes: self.staged.nodes.clone(),
        })
    }
    fn commit(
        &self,
        path: &Path,
        fault: CommitFault,
        receipt: Option<&OwnerReceipt>,
    ) -> Result<Snapshot> {
        let target = self.target_snapshot(receipt)?;
        let mut db = Connection::open(path).map_err(|_| Error::Storage)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let current = Snapshot::capture(&tx)?;
        if current.descriptor != self.source.descriptor || current.head != self.source.head {
            return Err(Error::Conflict);
        }
        current.validate(&self.old, &self.old_root)?;
        tx.execute("DELETE FROM records", [])
            .map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM index_nodes", [])
            .map_err(|_| Error::Storage)?;
        for (id, (revision, body)) in &target.rows {
            tx.execute(
                "INSERT INTO records(id,revision,envelope) VALUES(?1,?2,?3)",
                params![
                    id.as_slice(),
                    i64::try_from(*revision).map_err(|_| Error::ResourceLimit)?,
                    body
                ],
            )
            .map_err(|_| Error::Storage)?;
        }
        for (hash, body) in &target.nodes.0 {
            tx.execute(
                "INSERT INTO index_nodes(hash,bytes) VALUES(?1,?2)",
                params![hash.as_slice(), body],
            )
            .map_err(|_| Error::Storage)?;
        }
        if tx.execute("UPDATE vault_state SET descriptor=?1,head=?2 WHERE id=1 AND descriptor=?3 AND head=?4",params![target.descriptor,target.head,self.source.descriptor,self.source.head]).map_err(|_|Error::Storage)?!=1{return Err(Error::Conflict);}
        if fault == CommitFault::BeforeCommit {
            return Err(Error::InjectedFailure);
        }
        tx.commit().map_err(|_| Error::OutcomeUnknown {
            request_id: self.operation,
        })?;
        if fault == CommitFault::AfterCommit {
            return Err(Error::OutcomeUnknown {
                request_id: self.operation,
            });
        }
        Ok(target)
    }
}
fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn encode_body(stage: &Staged) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![u8::from(stage.full)]);
    for value in [stage.progress, stage.source_count, stage.source_generation] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.push(u8::from(stage.root.is_some()));
    out.extend_from_slice(&stage.root.unwrap_or([0; 32]));
    out.extend_from_slice(&(stage.rows.len() as u64).to_be_bytes());
    for (id, (revision, body)) in &stage.rows {
        out.extend_from_slice(id);
        out.extend_from_slice(&revision.to_be_bytes());
        put_blob(&mut out, body);
    }
    out.extend_from_slice(&(stage.nodes.0.len() as u64).to_be_bytes());
    for (hash, body) in &stage.nodes.0 {
        out.extend_from_slice(hash);
        put_blob(&mut out, body);
    }
    out
}
struct Read<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Read<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::Malformed("rotation checkpoint length"))?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Integrity)?,
        ))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Integrity)
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u64()?).map_err(|_| Error::ResourceLimit)?;
        if length > max {
            return Err(Error::ResourceLimit);
        }
        self.take(length)
    }
    fn finish(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Malformed("rotation checkpoint trailing bytes"))
        }
    }
}
fn max_checkpoint() -> Result<usize> {
    // Bound from admitted record count/envelope widths and canonical node widths.
    let records = limits().max_records;
    let rows = records
        .checked_mul(
            32usize
                .checked_add(limits().diagnostic_legacy_envelope_bytes()?)
                .ok_or(Error::ResourceLimit)?,
        )
        .ok_or(Error::ResourceLimit)?;
    let nodes = records
        .checked_mul(2)
        .and_then(|n| n.checked_sub(1))
        .unwrap_or(0)
        .checked_mul(40 + index::MAX_NODE_BYTES)
        .ok_or(Error::ResourceLimit)?;
    236usize
        .checked_add(1 + 24 + 33 + 8 + 8 + 40)
        .and_then(|n| n.checked_add(rows))
        .and_then(|n| n.checked_add(nodes))
        .ok_or(Error::ResourceLimit)
}
struct Header<'a> {
    target: Descriptor,
    operation: [u8; 16],
    aad: Vec<u8>,
    sealed: &'a [u8],
}
fn parse_header<'a>(bytes: &'a [u8], operation: [u8; 16], source: &Snapshot) -> Result<Header<'a>> {
    if bytes.len() > max_checkpoint()? {
        return Err(Error::ResourceLimit);
    }
    let mut r = Read { bytes, offset: 0 };
    if r.take(8)? != MAGIC || r.take(2)? != 1u16.to_be_bytes() {
        return Err(Error::Malformed("rotation checkpoint magic/version"));
    }
    let found = r.array()?;
    let source_descriptor = r.array()?;
    let source_head = r.array()?;
    if found != operation
        || source_descriptor != crypto::digest(&source.descriptor)
        || source_head != crypto::digest(&source.head)
    {
        return Err(Error::Integrity);
    }
    let target = Descriptor::parse(r.blob(format::DESCRIPTOR_LEN)?)?;
    let length = usize::try_from(r.u64()?).map_err(|_| Error::ResourceLimit)?;
    let mut aad = format::frame(b"fogvault/prototype/rotation-checkpoint/v1");
    aad.extend_from_slice(&bytes[..r.offset]);
    let sealed = r.take(length)?;
    r.finish()?;
    Ok(Header {
        target,
        operation: found,
        aad,
        sealed,
    })
}
fn decode_stage(body: &[u8], full: bool) -> Result<Staged> {
    let mut r = Read {
        bytes: body,
        offset: 0,
    };
    let mode = r.u8()?;
    if mode > 1 || mode != u8::from(full) {
        return Err(Error::Integrity);
    }
    let progress = r.u64()?;
    let source_count = r.u64()?;
    let source_generation = r.u64()?;
    if progress > source_count || source_count > limits().max_records as u64 {
        return Err(Error::ResourceLimit);
    }
    let present = r.u8()?;
    let hash = r.array()?;
    let root = match (present, progress, hash) {
        (0, 0, h) if h == [0; 32] => None,
        (1, n, h) if n > 0 => Some(h),
        _ => return Err(Error::Integrity),
    };
    let count = r.u64()?;
    if count != progress {
        return Err(Error::Integrity);
    }
    let mut rows = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = r.array()?;
        if previous.is_some_and(|old| old >= id) {
            return Err(Error::Integrity);
        }
        let revision = r.u64()?;
        let envelope = r
            .blob(limits().diagnostic_legacy_envelope_bytes()?)?
            .to_vec();
        rows.insert(id, (revision, envelope));
        previous = Some(id);
    }
    let count = r.u64()?;
    let expected = if progress == 0 {
        0
    } else {
        progress
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(Error::ResourceLimit)?
    };
    if count != expected {
        return Err(Error::Integrity);
    }
    let mut nodes = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let hash = r.array()?;
        if previous.is_some_and(|old| old >= hash) {
            return Err(Error::Integrity);
        }
        let bytes = r.blob(index::MAX_NODE_BYTES)?.to_vec();
        nodes.insert(hash, bytes);
        previous = Some(hash);
    }
    r.finish()?;
    Ok(Staged {
        full,
        progress,
        source_count,
        source_generation,
        root,
        rows,
        nodes: Nodes(nodes),
    })
}
fn validate_stage(
    stage: &Staged,
    source: &Snapshot,
    target: &Descriptor,
    new_root: &[u8; 32],
) -> Result<()> {
    let expected = source
        .rows
        .iter()
        .take(usize::try_from(stage.progress).map_err(|_| Error::ResourceLimit)?)
        .map(|(id, (revision, _))| (*id, *revision))
        .collect::<BTreeMap<_, _>>();
    if stage.source_count != source.rows.len() as u64
        || stage.rows.len() as u64 != stage.progress
        || stage
            .rows
            .iter()
            .map(|(id, (revision, _))| (*id, *revision))
            .collect::<BTreeMap<_, _>>()
            != expected
    {
        return Err(Error::Integrity);
    }
    let mut nodes = stage.nodes.clone();
    let audit = index::audit(&mut nodes, stage.root)?;
    if audit.entries.len() != stage.rows.len()
        || stage.nodes.0.len() != stage.rows.len().saturating_mul(2).saturating_sub(1)
    {
        return Err(Error::Integrity);
    }
    let wrapping = crypto::derive(new_root, &target.vault_id, b"record-key-wrapping")?;
    for (id, (revision, body)) in &stage.rows {
        if audit.entries.get(id)
            != Some(&Entry {
                revision: *revision,
                digest: crypto::digest(body),
            })
        {
            return Err(Error::Integrity);
        }
        format::decrypt_record(target, &wrapping, id, *revision, body, limits())?;
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn resume(
    path: &Path,
    bytes: &[u8],
    operation: [u8; 16],
    expected_source: &Snapshot,
    full: bool,
    old_password: &[u8],
    new_password: &[u8],
    receipt: Option<&OwnerReceipt>,
) -> Result<Job> {
    let receipt = receipt.ok_or(Error::Conflict)?;
    let header = parse_header(bytes, operation, expected_source)?;
    receipt.check(expected_source, &header.target, operation, full)?;
    let source = Snapshot::read(path);
    if source.descriptor != expected_source.descriptor || source.head != expected_source.head {
        return Err(Error::Conflict);
    }
    let old = Descriptor::parse(&source.descriptor)?;
    if old.vault_id != header.target.vault_id || old.context_hash() != header.target.context_hash()
    {
        return Err(Error::Integrity);
    }
    let old_root = old.unlock(old_password)?;
    let head = source.validate(&old, &old_root)?;
    let new_root = header.target.unlock(new_password)?;
    let key = crypto::derive(&new_root, &header.target.vault_id, STAGING_DOMAIN)?;
    let body = crypto::open(&key, &header.aad, header.sealed)?;
    let staged = decode_stage(&body, full)?;
    if staged.source_generation != head.generation {
        return Err(Error::Integrity);
    }
    validate_stage(&staged, &source, &header.target, &new_root)?;
    Ok(Job {
        source,
        old,
        old_root,
        target: header.target,
        new_root,
        operation: header.operation,
        staged,
    })
}
fn reconcile(
    bytes: &[u8],
    path: &Path,
    source: &Snapshot,
    full: bool,
    receipt: Option<&OwnerReceipt>,
    new_password: &[u8],
) -> Result<Snapshot> {
    let receipt = receipt.ok_or(Error::Conflict)?;
    let header = parse_header(bytes, OP, source)?;
    receipt.check(source, &header.target, OP, full)?;
    let root = header.target.unlock(new_password)?;
    let key = crypto::derive(&root, &header.target.vault_id, STAGING_DOMAIN)?;
    let body = crypto::open(&key, &header.aad, header.sealed)?;
    let staged = decode_stage(&body, full)?;
    validate_stage(&staged, source, &header.target, &root)?;
    let old = Descriptor::parse(&source.descriptor)?;
    let old_root = old.unlock(OLD)?;
    let job = Job {
        source: source.clone(),
        old,
        old_root,
        target: header.target,
        new_root: root,
        operation: OP,
        staged,
    };
    let expected = job.target_snapshot(Some(receipt))?;
    let actual = Snapshot::read(path);
    if actual != expected {
        return Err(Error::Conflict);
    }
    actual.validate(&job.target, &job.new_root)?;
    Ok(actual)
}

#[test]
fn p2_rotation_owner_receipt_rejects_old_root_target_substitution_with_same_password() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("same-password.sqlite");
    let source = seeded(&path);
    let (mut job, receipt) = Job::new_with_password(source.clone(), true, OLD).unwrap();
    // Keep these independent owner-prepared commitments outside the checkpoint
    // and outside each reconstructed Job. No secret getter is added to Engine.
    let expected_descriptor = crypto::digest(job.target.bytes());
    let expected_root = crypto::digest(job.new_root.as_slice());
    let old = Descriptor::parse(&source.descriptor).unwrap();
    let retained_old_root = old.unlock(OLD).unwrap();
    assert_ne!(expected_descriptor, crypto::digest(&source.descriptor));
    assert_ne!(expected_root, crypto::digest(retained_old_root.as_slice()));

    // A holder of the old root needs no password guess to copy its original
    // password-wrapped descriptor and seal a valid, complete checkpoint body
    // under the resulting known staging key. The SAME target password makes
    // that substituted descriptor pass password unwrap and context checks.
    let mut forged = Job {
        source: source.clone(),
        old: Descriptor::parse(&source.descriptor).unwrap(),
        old_root: Zeroizing::new(*retained_old_root),
        target: Descriptor::parse(&source.descriptor).unwrap(),
        new_root: Zeroizing::new(*retained_old_root),
        operation: OP,
        staged: job.staged.clone(),
    };
    while forged.staged.progress < forged.staged.source_count {
        forged.advance().unwrap();
    }
    let malicious = forged.checkpoint().unwrap();
    let header = parse_header(&malicious, OP, &source).unwrap();
    let known_staging_key =
        crypto::derive(&retained_old_root, &old.vault_id, STAGING_DOMAIN).unwrap();
    let body = crypto::open(&known_staging_key, &header.aad, header.sealed).unwrap();
    let decoded = decode_stage(&body, true).unwrap();
    validate_stage(&decoded, &source, &header.target, &retained_old_root).unwrap();
    assert_eq!(
        header.target.unlock(OLD).unwrap().as_slice(),
        retained_old_root.as_slice()
    );
    assert!(matches!(
        resume(
            &path,
            &malicious,
            OP,
            &source,
            true,
            OLD,
            OLD,
            Some(&receipt)
        ),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        forged.commit(&path, CommitFault::None, Some(&receipt)),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        reconcile(&malicious, &path, &source, true, Some(&receipt), OLD),
        Err(Error::Integrity)
    ));
    assert_eq!(Snapshot::read(&path), source);

    let good = job.checkpoint().unwrap();
    assert!(matches!(
        resume(&path, &good, OP, &source, true, OLD, OLD, None),
        Err(Error::Conflict)
    ));
    let (_, another_receipt) = Job::new_with_password(source.clone(), true, OLD).unwrap();
    assert_ne!(receipt, another_receipt);
    assert!(matches!(
        resume(
            &path,
            &good,
            OP,
            &source,
            true,
            OLD,
            OLD,
            Some(&another_receipt)
        ),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        resume(&path, &good, OP, &source, false, OLD, OLD, Some(&receipt)),
        Err(Error::Integrity)
    ));

    for progress in 0..=source.rows.len() {
        let bytes = job.checkpoint().unwrap();
        job = resume(&path, &bytes, OP, &source, true, OLD, OLD, Some(&receipt)).unwrap();
        assert_eq!(job.staged.progress, progress as u64);
        assert_eq!(crypto::digest(job.target.bytes()), expected_descriptor);
        assert_eq!(crypto::digest(job.new_root.as_slice()), expected_root);
        assert_ne!(job.new_root.as_slice(), retained_old_root.as_slice());
        assert_eq!(Snapshot::read(&path), source);
        if progress < source.rows.len() {
            job.advance().unwrap();
        }
    }
    assert!(matches!(
        job.commit(&path, CommitFault::None, None),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        job.commit(&path, CommitFault::None, Some(&another_receipt)),
        Err(Error::Integrity)
    ));
    assert_eq!(Snapshot::read(&path), source);
    let target = job
        .commit(&path, CommitFault::None, Some(&receipt))
        .unwrap();
    assert_eq!(crypto::digest(&target.descriptor), expected_descriptor);
    assert_eq!(
        crypto::digest(
            Descriptor::parse(&target.descriptor)
                .unwrap()
                .unlock(OLD)
                .unwrap()
                .as_slice()
        ),
        expected_root
    );
    assert!(target.validate(&job.target, &retained_old_root).is_err());
    let old_wrap =
        crypto::derive(&retained_old_root, &old.vault_id, b"record-key-wrapping").unwrap();
    for (id, (revision, body)) in &target.rows {
        assert!(
            format::decrypt_record(&job.target, &old_wrap, id, *revision, body, limits()).is_err()
        );
    }
    assert!(reconcile(&job.checkpoint().unwrap(), &path, &source, true, None, OLD).is_err());
    assert_eq!(
        reconcile(
            &job.checkpoint().unwrap(),
            &path,
            &source,
            true,
            Some(&receipt),
            OLD
        )
        .unwrap(),
        target
    );
    let mut current = Vault::diagnostic_open(&path, limits()).unwrap();
    let token = current.unlock(OLD).unwrap();
    assert_eq!(
        current.read(&token, [0; 16]).unwrap().payload.as_slice(),
        b"SYNTHETIC-ROTATION-RECORD-0-NO-PLAINTEXT-STAGING"
    );
}

#[test]
fn p2_rotation_checkpoint_resumes_every_record_and_commits_atomic_shadow_state() {
    for full in [false, true] {
        let scratch = tempdir().unwrap();
        let path = scratch.path().join("rotation.sqlite");
        let checkpoint = scratch.path().join("rotation.stage");
        let backup = scratch.path().join("retained.sqlite");
        let source = seeded(&path);
        std::fs::copy(&path, &backup).unwrap();
        let (mut job, receipt) = Job::new(source.clone(), full).unwrap();
        for progress in 0..=source.rows.len() {
            let bytes = job.checkpoint().unwrap();
            std::fs::write(&checkpoint, &bytes).unwrap();
            assert_eq!(Snapshot::read(&path), source);
            assert!(!bytes
                .windows(32)
                .any(|value| value == job.old_root.as_slice() || value == job.new_root.as_slice()));
            let marker = b"SYNTHETIC-ROTATION-RECORD-0-NO-PLAINTEXT-STAGING";
            assert!(!bytes.windows(marker.len()).any(|value| value == marker));
            job = resume(
                &path,
                &std::fs::read(&checkpoint).unwrap(),
                OP,
                &source,
                full,
                OLD,
                NEW,
                Some(&receipt),
            )
            .unwrap();
            assert_eq!(job.staged.progress, progress as u64);
            if progress < source.rows.len() {
                job.advance().unwrap();
            }
        }
        for (id, (_, before)) in &source.rows {
            let after = &job.staged.rows[id].1;
            assert_eq!(before[104..] == after[104..], !full);
        }
        assert!(matches!(
            job.commit(&path, CommitFault::BeforeCommit, Some(&receipt)),
            Err(Error::InjectedFailure)
        ));
        assert_eq!(Snapshot::read(&path), source);
        assert!(matches!(
            job.commit(&path, CommitFault::AfterCommit, Some(&receipt)),
            Err(Error::OutcomeUnknown { .. })
        ));
        let target = reconcile(
            &std::fs::read(&checkpoint).unwrap(),
            &path,
            &source,
            full,
            Some(&receipt),
            NEW,
        )
        .unwrap();
        assert_eq!(target, job.target_snapshot(Some(&receipt)).unwrap());
        let mut vault = Vault::diagnostic_open(&path, limits()).unwrap();
        assert!(vault.unlock(OLD).is_err());
        let token = vault.unlock(NEW).unwrap();
        for value in 0..3u8 {
            let record = vault.read(&token, [value; 16]).unwrap();
            assert_eq!(record.metadata.as_slice(), b"sensitive-meta");
            assert_eq!(
                record.payload.as_slice(),
                format!("SYNTHETIC-ROTATION-RECORD-{value}-NO-PLAINTEXT-STAGING").as_bytes()
            );
        }
        vault
            .save(
                &token,
                [9; 16],
                None,
                b"future",
                b"fresh after rotation",
                [0x73; 16],
            )
            .unwrap();
        let future = Snapshot::read(&path);
        let old_wrap =
            crypto::derive(&job.old_root, &job.old.vault_id, b"record-key-wrapping").unwrap();
        assert!(format::decrypt_record(
            &job.target,
            &old_wrap,
            &[9; 16],
            1,
            &future.rows[&[9; 16]].1,
            limits()
        )
        .is_err());
        let mut old = Vault::diagnostic_open(&backup, limits()).unwrap();
        let old_token = old.unlock(OLD).unwrap();
        assert!(old.read(&old_token, [0; 16]).is_ok());
        std::fs::remove_file(checkpoint).unwrap();
        assert_eq!(Snapshot::read(&path), future);
    }
}

#[test]
fn p2_rotation_checkpoints_reject_wrong_credentials_context_and_authenticated_bad_progress() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("checkpoint.sqlite");
    let source = seeded(&path);
    let (mut job, receipt) = Job::new(source.clone(), true).unwrap();
    job.advance().unwrap();
    let good = job.checkpoint().unwrap();
    for length in 0..good.len() {
        assert!(parse_header(&good[..length], OP, &source).is_err());
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(parse_header(&trailing, OP, &source).is_err());
    assert!(resume(
        &path,
        &good,
        [9; 16],
        &source,
        true,
        OLD,
        NEW,
        Some(&receipt)
    )
    .is_err());
    assert!(resume(
        &path,
        &good,
        OP,
        &source,
        true,
        b"wrong",
        NEW,
        Some(&receipt)
    )
    .is_err());
    assert!(resume(
        &path,
        &good,
        OP,
        &source,
        true,
        OLD,
        b"wrong",
        Some(&receipt)
    )
    .is_err());
    let mut changed = good.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(resume(&path, &changed, OP, &source, true, OLD, NEW, Some(&receipt)).is_err());
    assert!(resume(&path, &good, OP, &source, false, OLD, NEW, Some(&receipt)).is_err());
    let mut foreign = source.clone();
    foreign.head[0] ^= 1;
    assert!(resume(&path, &good, OP, &foreign, true, OLD, NEW, Some(&receipt)).is_err());
    let saved = job.staged.clone();
    job.staged.progress += 1;
    assert!(resume(
        &path,
        &job.checkpoint().unwrap(),
        OP,
        &source,
        true,
        OLD,
        NEW,
        Some(&receipt),
    )
    .is_err());
    job.staged = saved.clone();
    job.staged.rows.clear();
    assert!(resume(
        &path,
        &job.checkpoint().unwrap(),
        OP,
        &source,
        true,
        OLD,
        NEW,
        Some(&receipt),
    )
    .is_err());
    job.staged = saved;
    job.staged.nodes.0.clear();
    assert!(resume(
        &path,
        &job.checkpoint().unwrap(),
        OP,
        &source,
        true,
        OLD,
        NEW,
        Some(&receipt),
    )
    .is_err());
    assert_eq!(Snapshot::read(&path), source);
}

#[test]
fn p2_rotation_cas_and_orphan_cleanup_never_promote_incomplete_or_stale_stage() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("cas.sqlite");
    let orphan = scratch.path().join("orphan.stage");
    let source = seeded(&path);
    let (mut job, receipt) = Job::new(source.clone(), true).unwrap();
    std::fs::write(&orphan, job.checkpoint().unwrap()).unwrap();
    assert!(job
        .commit(&path, CommitFault::None, Some(&receipt))
        .is_err());
    assert_eq!(Snapshot::read(&path), source);
    while job.staged.progress < job.staged.source_count {
        job.advance().unwrap();
    }
    let mut writer = Vault::diagnostic_open(&path, limits()).unwrap();
    let token = writer.unlock(OLD).unwrap();
    writer
        .save(
            &token,
            [0; 16],
            Some(1),
            b"new",
            b"concurrent writer",
            [0x74; 16],
        )
        .unwrap();
    let changed = Snapshot::read(&path);
    assert!(matches!(
        job.commit(&path, CommitFault::None, Some(&receipt)),
        Err(Error::Conflict)
    ));
    assert_eq!(Snapshot::read(&path), changed);
    std::fs::remove_file(orphan).unwrap();
    assert_eq!(Snapshot::read(&path), changed);
}

#[test]
fn p2_restore_authentication_and_external_anchor_policy_are_distinct() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("anchor.sqlite");
    let source = seeded(&path);
    let (mut job, receipt) = Job::new(source.clone(), true).unwrap();
    while job.staged.progress < job.staged.source_count {
        job.advance().unwrap();
    }
    let target = job
        .commit(&path, CommitFault::None, Some(&receipt))
        .unwrap();
    let old = Descriptor::parse(&source.descriptor).unwrap();
    let root = old.unlock(OLD).unwrap();
    source.validate(&old, &root).unwrap(); // Unanchored old authenticated data is still valid.
    let trusted_latest = crypto::digest(&target.head);
    assert_ne!(crypto::digest(&source.head), trusted_latest);
    enum Freshness {
        Unanchored,
        Required(Option<[u8; 32]>),
    }
    let check = |snapshot: &Snapshot, expected_vault: [u8; 16], policy: Freshness| -> Result<()> {
        if Descriptor::parse(&snapshot.descriptor)?.vault_id != expected_vault {
            return Err(Error::Integrity);
        }
        match policy {
            Freshness::Unanchored => Ok(()),
            Freshness::Required(Some(value)) if value == crypto::digest(&snapshot.head) => Ok(()),
            Freshness::Required(_) => Err(Error::Integrity),
        }
    };
    assert!(check(&source, old.vault_id, Freshness::Unanchored).is_ok());
    assert!(check(
        &source,
        old.vault_id,
        Freshness::Required(Some(trusted_latest))
    )
    .is_err());
    assert!(check(
        &target,
        old.vault_id,
        Freshness::Required(Some(trusted_latest))
    )
    .is_ok());
    assert!(check(&target, old.vault_id, Freshness::Required(None)).is_err());
    assert!(check(&source, [9; 16], Freshness::Unanchored).is_err());
    // A separate explicit owner-approved registration accepts this historical
    // snapshot; it does not silently erase the original required anchor.
    let restored_registration = crypto::random::<16>().unwrap();
    assert_ne!(restored_registration, old.vault_id);
    let restored_anchor = crypto::digest(&source.head);
    check(
        &source,
        old.vault_id,
        Freshness::Required(Some(restored_anchor)),
    )
    .unwrap();
    assert!(check(
        &source,
        old.vault_id,
        Freshness::Required(Some(trusted_latest))
    )
    .is_err());
}
