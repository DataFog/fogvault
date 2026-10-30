//! Frozen actual current-creation bytes. This test never generates fixtures.
use fogvault::{AuditRequest, Engine, Error, Limits, NodeHash, NodeStore, Result};
use std::{collections::BTreeMap, path::Path};

const PASSWORD: &[u8] = b"SYNTHETIC-fresh-epoch-zero-password";
const ID: [u8; 16] = [0x73; 16];

struct Memory {
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    envelope: Vec<u8>,
}
impl NodeStore for Memory {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, _: NodeHash, _: &[u8]) -> Result<()> {
        Err(Error::UnsupportedCapability)
    }
}
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/fresh-epoch-vectors")
            .join(name),
    )
    .unwrap()
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 1280,
        max_metadata_bytes: 256,
        max_records: 1,
    }
}
fn activate(engine: &mut Engine, head: &[u8], memory: &Memory, count: u64) {
    engine.begin_unlock(PASSWORD).unwrap();
    engine.begin_audit(head).unwrap();
    loop {
        match engine.audit_next().unwrap() {
            AuditRequest::Node(hash) => engine.supply_node(&memory.nodes[&hash]).unwrap(),
            AuditRequest::Record { id, entry, .. } => {
                assert_eq!(id, ID);
                assert_eq!(entry.revision, 1);
                engine
                    .supply_record(1, memory.envelope.len() as u64, Some(&memory.envelope))
                    .unwrap();
            }
            AuditRequest::Done => break,
        }
    }
    engine.finish_audit(count, count).unwrap();
    engine.activate_audit().unwrap();
}

#[test]
fn fixed_fresh_epoch_zero_vectors_unlock_empty_and_first_save_states() {
    let descriptor = fixture("descriptor.bin");
    let initial = fixture("initial-head.bin");
    let head = fixture("head.bin");
    let envelope = fixture("record.bin");
    let root: NodeHash = head[65..97].try_into().unwrap();
    let filename = format!(
        "node-{}.bin",
        root.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let mut memory = Memory {
        nodes: BTreeMap::from([(root, fixture(&filename))]),
        envelope,
    };
    assert_eq!(descriptor.len(), 180);
    assert_eq!(&descriptor[12..14], &3u16.to_be_bytes());
    assert_eq!(&descriptor[30..38], &0u64.to_be_bytes());
    let mut empty = Engine::open(&descriptor, limits()).unwrap();
    activate(&mut empty, &initial, &memory, 0);
    assert!(empty.lookup(&mut memory, &ID).unwrap().entry().is_none());
    empty.lock();
    let mut engine = Engine::open(&descriptor, limits()).unwrap();
    activate(&mut engine, &head, &memory, 1);
    let lookup = engine.lookup(&mut memory, &ID).unwrap();
    let proof = lookup.entry().unwrap();
    let record = engine.read_verified(proof, 1, &memory.envelope).unwrap();
    assert_eq!(record.metadata.as_slice(), b"fresh epoch metadata");
    assert_eq!(
        record.payload.as_slice(),
        b"first record from current default creation"
    );
    let mut changed_epoch = memory.envelope.clone();
    changed_epoch[32..40].copy_from_slice(&1u64.to_be_bytes());
    assert!(engine.read_verified(proof, 1, &changed_epoch).is_err());
    engine.lock();
    assert!(engine.read_verified(proof, 1, &memory.envelope).is_err());
}
