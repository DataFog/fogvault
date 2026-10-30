use fogvault::{
    AuditRequest, Engine, Error, Limits, NodeHash, NodeStore, RecordId, Result, StoredRecord,
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
        if self.nodes.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, bytes.to_vec());
        Ok(())
    }
}
fn seeded(count: u8) -> (Engine, Memory) {
    let limits = Limits {
        max_payload_bytes: 64,
        max_metadata_bytes: 16,
        max_records: 256,
    };
    let mut engine = Engine::create(b"record-operations-synthetic", limits).unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory {
        descriptor: engine.descriptor_bytes().to_vec(),
        head: engine.head_bytes().to_vec(),
        ..Memory::default()
    };
    for id in 0..count {
        let mut staged = memory.clone();
        let plan = engine
            .prepare_save(
                &mut staged,
                [id; 16],
                None,
                b"meta",
                &[id],
                [id.wrapping_add(1); 16],
                None,
            )
            .unwrap();
        for hash in plan.obsolete {
            staged.nodes.remove(&hash);
        }
        staged
            .records
            .insert([id; 16], (plan.revision, plan.envelope));
        staged.head = plan.head_bytes;
        engine.confirm_commit(&staged.head).unwrap();
        memory = staged;
    }
    (engine, memory)
}
fn delete(engine: &mut Engine, memory: &mut Memory, id: RecordId, request: [u8; 16]) {
    let mut staged = memory.clone();
    let previous = staged.records.get(&id).cloned();
    let plan = engine
        .prepare_delete(
            &mut staged,
            id,
            1,
            request,
            previous.as_ref().map(|(revision, envelope)| StoredRecord {
                revision: *revision,
                envelope,
            }),
        )
        .unwrap();
    if !plan.replay {
        staged.records.remove(&id);
        for hash in plan.obsolete {
            staged.nodes.remove(&hash);
        }
        staged.head = plan.head_bytes;
        engine.confirm_commit(&staged.head).unwrap();
        *memory = staged;
    }
}
fn reconcile(engine: &mut Engine, memory: &Memory, request: [u8; 16]) -> Result<()> {
    engine.begin_reconcile_snapshot(&memory.descriptor, &memory.head, request)?;
    loop {
        match engine.audit_next()? {
            AuditRequest::Node(hash) => {
                engine.supply_node(memory.nodes.get(&hash).ok_or(Error::Integrity)?)?
            }
            AuditRequest::Record { id, .. } => {
                let (revision, envelope) = memory.records.get(&id).ok_or(Error::Integrity)?;
                engine.supply_record(*revision, envelope.len() as u64, Some(envelope))?;
            }
            AuditRequest::Done => break,
        }
    }
    engine.finish_audit(memory.records.len() as u64, memory.nodes.len() as u64)?;
    engine.activate_audit()?;
    Ok(())
}

#[test]
fn portable_delete_authenticates_membership_retries_and_the_empty_root() {
    let (mut engine, mut memory) = seeded(3);
    let old = memory.records[&[1; 16]].clone();
    delete(&mut engine, &mut memory, [1; 16], [100; 16]);
    let receipt = engine.current_receipt().unwrap();
    assert!(engine
        .lookup(&mut memory, &[1; 16])
        .unwrap()
        .entry()
        .is_none());
    let mut replay_store = memory.clone();
    let retry = engine
        .prepare_delete(&mut replay_store, [1; 16], 1, [100; 16], None)
        .unwrap();
    assert!(retry.replay && retry.obsolete.is_empty());
    assert_eq!(retry.receipt, receipt);
    assert_eq!(retry.stats.nodes_written, 0);
    assert!(matches!(
        engine.prepare_delete(
            &mut replay_store,
            [2; 16],
            1,
            [100; 16],
            Some(StoredRecord {
                revision: 1,
                envelope: &memory.records[&[2; 16]].1
            })
        ),
        Err(Error::OperationIdReuse)
    ));
    assert!(engine
        .prepare_delete(
            &mut replay_store,
            [1; 16],
            1,
            [100; 16],
            Some(StoredRecord {
                revision: old.0,
                envelope: &old.1
            })
        )
        .is_err());
    let victim = memory.records[&[2; 16]].clone();
    assert!(matches!(
        engine.prepare_delete(
            &mut replay_store,
            [2; 16],
            2,
            [101; 16],
            Some(StoredRecord {
                revision: victim.0,
                envelope: &victim.1
            })
        ),
        Err(Error::Conflict)
    ));
    delete(&mut engine, &mut memory, [0; 16], [102; 16]);
    delete(&mut engine, &mut memory, [2; 16], [103; 16]);
    assert!(memory.records.is_empty() && memory.nodes.is_empty());
    let mut cursor = engine.begin_records().unwrap();
    let page = engine.record_page(&mut cursor, &mut memory, 1).unwrap();
    assert!(page.complete && page.records.is_empty());
    assert!(matches!(
        engine.record_page(&mut cursor, &mut memory, 1),
        Err(Error::Conflict)
    ));
    reconcile(&mut engine, &memory, [103; 16]).unwrap();
}

#[test]
fn portable_delete_unknown_reconciliation_and_lock_preserve_authority() {
    let (mut engine, mut memory) = seeded(2);
    let draft = engine.draft_delete([0; 16], 1, [110; 16]).unwrap();
    let old = memory.records[&[0; 16]].clone();
    let mut staged = memory.clone();
    let lookup = engine.lookup(&mut staged, &[0; 16]).unwrap();
    let plan = engine
        .stage_delete(
            &draft,
            lookup,
            Some(StoredRecord {
                revision: old.0,
                envelope: &old.1,
            }),
            &mut staged,
        )
        .unwrap();
    for hash in &plan.obsolete {
        staged.nodes.remove(hash);
    }
    staged.records.remove(&[0; 16]);
    staged.head = plan.head_bytes;
    engine.mark_unknown().unwrap();
    assert!(matches!(
        engine.begin_records(),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(engine.abort_prepared().is_err());
    reconcile(&mut engine, &staged, [110; 16]).unwrap();
    memory = staged;
    let draft = engine.draft_delete([1; 16], 1, [111; 16]).unwrap();
    let lookup = engine.lookup(&mut memory, &[1; 16]).unwrap();
    let previous = memory.records[&[1; 16]].clone();
    let mut cursor = engine.begin_records().unwrap();
    engine.lock();
    assert!(engine.record_page(&mut cursor, &mut memory, 1).is_err());
    // A draft cannot gain authority again merely by retaining encrypted objects.
    assert!(engine
        .stage_delete(
            &draft,
            lookup,
            Some(StoredRecord {
                revision: previous.0,
                envelope: &previous.1,
            }),
            &mut memory
        )
        .is_err());
}

#[test]
fn portable_pages_are_bounded_complete_and_bound_to_the_current_head() {
    let (mut engine, mut memory) = seeded(17);
    let mut cursor = engine.begin_records().unwrap();
    let mut visited = Vec::new();
    let mut nodes_read = 0;
    loop {
        let page = engine.record_page(&mut cursor, &mut memory, 3).unwrap();
        assert!(page.records.len() <= 3 && page.peak_frontier_nodes <= 129);
        nodes_read += page.stats.nodes_read;
        for proof in &page.records {
            let (revision, envelope) = &memory.records[&proof.id()];
            assert_eq!(
                engine
                    .read_verified(proof, *revision, envelope)
                    .unwrap()
                    .payload
                    .as_slice(),
                &[proof.id()[0]]
            );
            visited.push(proof.id());
        }
        if page.complete {
            break;
        }
    }
    assert_eq!(visited, memory.records.keys().copied().collect::<Vec<_>>());
    assert_eq!(nodes_read, 33);
    let mut stale = engine.begin_records().unwrap();
    let prefix = engine.record_page(&mut stale, &mut memory, 1).unwrap();
    assert!(!prefix.complete);
    delete(&mut engine, &mut memory, [16; 16], [120; 16]);
    assert!(matches!(
        engine.record_page(&mut stale, &mut memory, 1),
        Err(Error::Conflict)
    ));
    assert!(engine
        .read_verified(&prefix.records[0], 1, &memory.records[&[0; 16]].1)
        .is_err());
    let mut poisoned = engine.begin_records().unwrap();
    let mut missing = memory.clone();
    missing.nodes.clear();
    assert!(engine.record_page(&mut poisoned, &mut missing, 2).is_err());
    assert!(matches!(
        engine.record_page(&mut poisoned, &mut memory, 2),
        Err(Error::Conflict)
    ));
    let mut canceled = engine.begin_records().unwrap();
    canceled.cancel();
    assert!(engine.record_page(&mut canceled, &mut memory, 2).is_err());
}

#[test]
fn portable_prepared_delete_rejects_reinserted_incarnation_and_record_replay() {
    let (mut engine, mut memory) = seeded(1);
    let draft = engine.draft_delete([0; 16], 1, [130; 16]).unwrap();
    let retained = memory.records[&[0; 16]].clone();
    delete(&mut engine, &mut memory, [0; 16], [131; 16]);
    let mut staged = memory.clone();
    let plan = engine
        .prepare_save(
            &mut staged,
            [0; 16],
            None,
            b"new",
            b"new incarnation",
            [132; 16],
            None,
        )
        .unwrap();
    assert_eq!(plan.revision, 1); // P2 stores live versions, not historical tombstones.
    staged
        .records
        .insert([0; 16], (plan.revision, plan.envelope));
    staged.head = plan.head_bytes;
    engine.confirm_commit(&staged.head).unwrap();
    memory = staged;
    let lookup = engine.lookup(&mut memory, &[0; 16]).unwrap();
    assert!(engine
        .read_verified(lookup.entry().unwrap(), retained.0, &retained.1)
        .is_err());
    let current = memory.records[&[0; 16]].clone();
    assert!(matches!(
        engine.stage_delete(
            &draft,
            lookup,
            Some(StoredRecord {
                revision: current.0,
                envelope: &current.1
            }),
            &mut memory
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(memory.records[&[0; 16]].1, current.1);
}

#[test]
fn portable_async_inventory_uses_the_same_authenticated_cursor_and_finality() {
    let (engine, memory) = seeded(17);
    let mut cursor = engine.begin_records().unwrap();
    assert!(engine.finish_records(&mut cursor).is_err());
    let mut ids = Vec::new();
    while let Some(hash) = engine.record_next(&cursor).unwrap() {
        if let Some(proof) = engine
            .supply_record_node(&mut cursor, &memory.nodes[&hash])
            .unwrap()
        {
            let (revision, envelope) = &memory.records[&proof.id()];
            engine.verify_record(&proof, *revision, envelope).unwrap();
            ids.push(proof.id());
        }
        assert!(cursor.peak_frontier_nodes() <= 129);
    }
    assert_eq!(ids, memory.records.keys().copied().collect::<Vec<_>>());
    assert_eq!(cursor.records_checked(), 17);
    assert_eq!(engine.finish_records(&mut cursor).unwrap().nodes_read, 33);
    assert!(engine.record_next(&cursor).is_err());
    assert!(engine.finish_records(&mut cursor).is_err());
}
