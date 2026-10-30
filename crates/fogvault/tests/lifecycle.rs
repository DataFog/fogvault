//! Public-API proofs: an adapter supplies ciphertext and atomic I/O, never keys.
use fogvault::{
    AuditRequest, CommitPlan, Engine, Error, Limits, NodeHash, NodeStore, Phase, RecordId, Result,
    StoredRecord,
};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
struct Memory {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    records: BTreeMap<RecordId, (u64, Vec<u8>)>,
}
impl NodeStore for Memory {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if self.nodes.get(&hash).is_some_and(|prior| prior != bytes) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, bytes.to_vec());
        Ok(())
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 256,
        max_records: 16,
    }
}
fn create() -> (Engine, Memory) {
    let mut engine = Engine::create(b"candidate test passphrase", limits()).unwrap();
    assert_eq!(engine.phase(), Phase::Initializing);
    assert!(matches!(engine.current_session(), Err(Error::Locked)));
    let memory = Memory {
        descriptor: engine.descriptor_bytes().to_vec(),
        head: engine.head_bytes().to_vec(),
        ..Memory::default()
    };
    // In a real adapter this follows successful creation transaction completion.
    engine.activate_created().unwrap();
    (engine, memory)
}
fn prepare(
    engine: &mut Engine,
    current: &Memory,
    id: RecordId,
    revision: Option<u64>,
    payload: &[u8],
    request: [u8; 16],
) -> Result<(CommitPlan, Memory)> {
    let mut staged = current.clone();
    engine.check_snapshot(&staged.descriptor, &staged.head)?;
    let previous = staged.records.get(&id).cloned();
    let plan = engine.prepare_save(
        &mut staged,
        id,
        revision,
        b"metadata",
        payload,
        request,
        previous.as_ref().map(|(revision, bytes)| StoredRecord {
            revision: *revision,
            envelope: bytes,
        }),
    )?;
    if !plan.replay {
        for obsolete in &plan.obsolete {
            staged.nodes.remove(obsolete);
        }
        staged
            .records
            .insert(id, (plan.revision, plan.envelope.clone()));
        staged.head = plan.head_bytes.clone();
    }
    Ok((plan, staged))
}
fn save(
    engine: &mut Engine,
    current: &mut Memory,
    id: RecordId,
    revision: Option<u64>,
    payload: &[u8],
    request: [u8; 16],
) {
    let (plan, staged) = prepare(engine, current, id, revision, payload, request).unwrap();
    *current = staged;
    if !plan.replay {
        assert_eq!(engine.confirm_commit(&current.head).unwrap(), plan.receipt);
    }
}
fn read(engine: &Engine, memory: &mut Memory, id: RecordId) -> Result<Vec<u8>> {
    let proof = engine.lookup(memory, &id)?;
    let proof = proof.entry().ok_or(Error::NotFound)?;
    let (revision, bytes) = memory.records.get(&id).ok_or(Error::Integrity)?;
    Ok(engine
        .read_verified(proof, *revision, bytes)?
        .payload
        .to_vec())
}
fn supply_audit(engine: &mut Engine, memory: &Memory) -> Result<()> {
    loop {
        match engine.audit_next()? {
            AuditRequest::Node(hash) => {
                engine.supply_node(memory.nodes.get(&hash).ok_or(Error::Integrity)?)?
            }
            AuditRequest::Record { id, .. } => {
                let (revision, body) = memory.records.get(&id).ok_or(Error::Integrity)?;
                engine.supply_record(*revision, body.len() as u64, Some(body))?;
            }
            AuditRequest::Done => break,
        }
    }
    engine.finish_audit(memory.records.len() as u64, memory.nodes.len() as u64)?;
    Ok(())
}

#[test]
fn portable_create_unlock_save_lock_reopen_read() {
    let (mut engine, mut memory) = create();
    save(
        &mut engine,
        &mut memory,
        [1; 16],
        None,
        b"opaque Core bundle",
        [11; 16],
    );
    let original = engine.current_session().unwrap();
    assert_eq!(
        read(&engine, &mut memory, [1; 16]).unwrap(),
        b"opaque Core bundle"
    );
    engine.lock();
    assert!(matches!(
        read(&engine, &mut memory, [1; 16]),
        Err(Error::Locked)
    ));
    drop(engine);
    let mut reopened = Engine::open(&memory.descriptor, limits()).unwrap();
    reopened.begin_unlock(b"candidate test passphrase").unwrap();
    assert_eq!(reopened.phase(), Phase::Unlocking);
    reopened.begin_audit(&memory.head).unwrap();
    assert!(matches!(reopened.activate_audit(), Err(Error::Conflict)));
    supply_audit(&mut reopened, &memory).unwrap();
    // Audit success alone must not publish authority before host completion.
    assert!(matches!(reopened.current_session(), Err(Error::Locked)));
    assert!(matches!(
        read(&reopened, &mut memory, [1; 16]),
        Err(Error::Locked)
    ));
    reopened.activate_audit().unwrap();
    assert!(matches!(
        reopened.check_session(&original),
        Err(Error::StaleSession)
    ));
    assert_eq!(
        read(&reopened, &mut memory, [1; 16]).unwrap(),
        b"opaque Core bundle"
    );
}

#[test]
fn portable_lock_revokes_drafts_proofs_and_foreign_tokens() {
    let (mut engine, mut memory) = create();
    save(&mut engine, &mut memory, [1; 16], None, b"first", [11; 16]);
    let token = engine.current_session().unwrap();
    let proof = engine.lookup(&mut memory, &[1; 16]).unwrap();
    let draft = engine
        .draft_save([1; 16], Some(1), b"metadata", b"delayed", [12; 16])
        .unwrap();
    let (other, _) = create();
    let (revision, bytes) = &memory.records[&[1; 16]];
    assert!(matches!(
        other.read_verified(proof.entry().unwrap(), *revision, bytes),
        Err(Error::StaleSession)
    ));
    assert!(matches!(
        other.check_session(&token),
        Err(Error::StaleSession)
    ));
    engine.lock();
    assert!(matches!(
        engine.read_verified(proof.entry().unwrap(), *revision, bytes),
        Err(Error::Locked)
    ));
    engine.begin_unlock(b"candidate test passphrase").unwrap();
    engine.begin_audit(&memory.head).unwrap();
    supply_audit(&mut engine, &memory).unwrap();
    engine.activate_audit().unwrap();
    assert!(matches!(
        engine.read_verified(proof.entry().unwrap(), *revision, bytes),
        Err(Error::StaleSession)
    ));
    let fresh = engine.lookup(&mut memory, &[1; 16]).unwrap();
    let previous = memory.records[&[1; 16]].clone();
    assert!(matches!(
        engine.stage_save(
            &draft,
            fresh,
            Some(StoredRecord {
                revision: previous.0,
                envelope: &previous.1
            }),
            &mut memory
        ),
        Err(Error::StaleSession)
    ));
}

#[test]
fn portable_uncertain_commit_requires_successful_reconciliation() {
    let (mut engine, memory) = create();
    let session = engine.current_session().unwrap();
    let (plan, mut durable) = prepare(
        &mut engine,
        &memory,
        [1; 16],
        None,
        b"saved but reply lost",
        [11; 16],
    )
    .unwrap();
    assert_eq!(engine.phase(), Phase::Prepared);
    assert!(matches!(
        engine.confirm_commit(&memory.head),
        Err(Error::Integrity)
    ));
    engine.mark_unknown().unwrap();
    assert_eq!(engine.phase(), Phase::Uncertain);
    assert!(engine.check_session(&session).is_ok()); // needed to authorize reconciliation
    assert!(matches!(
        engine.lookup(&mut durable, &[1; 16]),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        engine.draft_save([2; 16], None, b"", b"", [12; 16]),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        engine.abort_prepared(),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        engine.confirm_commit(&plan.head_bytes),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        engine.begin_reconcile(&durable.head, [12; 16]),
        Err(Error::Conflict)
    ));
    let mut corrupt = durable.clone();
    corrupt.records.get_mut(&[1; 16]).unwrap().1[0] ^= 1;
    engine.begin_reconcile(&corrupt.head, [11; 16]).unwrap();
    assert!(matches!(
        supply_audit(&mut engine, &corrupt),
        Err(Error::Integrity)
    ));
    engine.abort_audit();
    assert_eq!(engine.phase(), Phase::Uncertain);
    engine.begin_reconcile(&durable.head, [11; 16]).unwrap();
    supply_audit(&mut engine, &durable).unwrap();
    assert!(engine.is_uncertain());
    assert_eq!(engine.generation(), Some(0));
    assert_eq!(engine.activate_audit().unwrap(), plan.receipt);
    assert_eq!(engine.phase(), Phase::Ready);
    assert_eq!(
        read(&engine, &mut durable, [1; 16]).unwrap(),
        b"saved but reply lost"
    );
}

#[test]
fn portable_retries_are_idempotent_and_content_bound() {
    let (mut engine, mut memory) = create();
    let (aborted, _) = prepare(
        &mut engine,
        &memory,
        [1; 16],
        None,
        b"uncommitted",
        [10; 16],
    )
    .unwrap();
    engine.abort_prepared().unwrap();
    assert_eq!(engine.phase(), Phase::Ready);
    assert!(matches!(
        engine.confirm_commit(&aborted.head_bytes),
        Err(Error::Conflict)
    ));
    save(&mut engine, &mut memory, [1; 16], None, b"first", [11; 16]);
    let (retry, same) = prepare(&mut engine, &memory, [1; 16], None, b"first", [11; 16]).unwrap();
    assert!(retry.replay);
    assert_eq!(retry.stats.nodes_written, 0);
    assert!(retry.envelope.is_empty());
    assert_eq!(same.nodes, memory.nodes);
    assert_eq!(same.head, memory.head);
    assert_eq!(same.records, memory.records);
    assert!(matches!(
        prepare(&mut engine, &memory, [1; 16], None, b"changed", [11; 16]),
        Err(Error::OperationIdReuse)
    ));
    assert_eq!(engine.phase(), Phase::Ready);
    assert_eq!(engine.generation(), Some(1));
}

#[test]
fn portable_stale_snapshot_and_record_replay_are_rejected() {
    let (mut engine, mut memory) = create();
    save(&mut engine, &mut memory, [1; 16], None, b"first", [11; 16]);
    let old = memory.clone();
    let old_proof = engine.lookup(&mut memory, &[1; 16]).unwrap();
    let old_draft = engine
        .draft_save([1; 16], Some(1), b"metadata", b"late", [12; 16])
        .unwrap();
    save(
        &mut engine,
        &mut memory,
        [1; 16],
        Some(1),
        b"second",
        [13; 16],
    );
    assert!(matches!(
        engine.check_snapshot(&old.descriptor, &old.head),
        Err(Error::Conflict)
    ));
    let old_record = &old.records[&[1; 16]];
    assert!(matches!(
        engine.read_verified(old_proof.entry().unwrap(), old_record.0, &old_record.1),
        Err(Error::Conflict)
    ));
    let current = engine.lookup(&mut memory, &[1; 16]).unwrap();
    assert!(matches!(
        engine.read_verified(current.entry().unwrap(), old_record.0, &old_record.1),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        engine.stage_save(&old_draft, current, None, &mut memory),
        Err(Error::Conflict)
    ));
    assert_eq!(read(&engine, &mut memory, [1; 16]).unwrap(), b"second");
}

#[test]
fn portable_failed_password_revokes_existing_session() {
    let (mut engine, mut memory) = create();
    let session = engine.current_session().unwrap();
    assert!(engine.begin_unlock(b"wrong passphrase").is_err());
    assert_eq!(engine.phase(), Phase::Locked);
    assert!(matches!(engine.check_session(&session), Err(Error::Locked)));
    assert!(matches!(
        engine.lookup(&mut memory, &[1; 16]),
        Err(Error::Locked)
    ));
    engine.begin_unlock(b"candidate test passphrase").unwrap();
    let mut tampered_head = memory.head.clone();
    tampered_head[0] ^= 1;
    assert!(engine.begin_audit(&tampered_head).is_err());
    assert!(matches!(engine.current_session(), Err(Error::Locked)));
    engine.begin_audit(&memory.head).unwrap();
    supply_audit(&mut engine, &memory).unwrap();
    engine.activate_audit().unwrap();
    assert!(matches!(
        engine.check_session(&session),
        Err(Error::StaleSession)
    ));
}
