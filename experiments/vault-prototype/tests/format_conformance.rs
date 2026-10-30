//! Fixed vectors constructed outside this Rust implementation. See provenance in
//! conformance/format-vectors.json. No test regenerates or approves expected bytes.

use std::collections::BTreeMap;

use fogvault_disposable_prototype::{
    format::{Descriptor, Entry, IndexHead},
    index::{self, NodeHash, NodeStore},
    Error, Limits, Result,
};

const DESCRIPTOR_P1: &[u8] = include_bytes!("../../../conformance/vectors/descriptor-p1.bin");
const DESCRIPTOR_P2: &[u8] = include_bytes!("../../../conformance/vectors/descriptor-p2.bin");
const LEFT: &[u8] = include_bytes!("../../../conformance/vectors/index-leaf-left.bin");
const RIGHT: &[u8] = include_bytes!("../../../conformance/vectors/index-leaf-right.bin");
const BRANCH: &[u8] = include_bytes!("../../../conformance/vectors/index-branch-root.bin");
const LEFT_HASH: &NodeHash =
    include_bytes!("../../../conformance/vectors/index-leaf-left.nodehash");
const RIGHT_HASH: &NodeHash =
    include_bytes!("../../../conformance/vectors/index-leaf-right.nodehash");
const BRANCH_HASH: &NodeHash =
    include_bytes!("../../../conformance/vectors/index-branch-root.nodehash");
const EMPTY_HEAD: &[u8] = include_bytes!("../../../conformance/vectors/index-head-empty.bin");
const POPULATED_HEAD: &[u8] =
    include_bytes!("../../../conformance/vectors/index-head-populated.bin");

#[derive(Default)]
struct Store(BTreeMap<NodeHash, Vec<u8>>);

impl NodeStore for Store {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(hash).cloned())
    }

    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if self.0.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.0.insert(hash, bytes.to_vec());
        Ok(())
    }
}

fn limits() -> Limits {
    Limits {
        max_payload_bytes: 1024,
        max_metadata_bytes: 1024,
        max_records: 2,
    }
}

#[test]
fn committed_format_vectors_match_implementation() {
    // These suffixes are deliberately synthetic: parsing is tested, not unlock.
    for fixture in [DESCRIPTOR_P1, DESCRIPTOR_P2] {
        let descriptor = Descriptor::parse(fixture).expect("fixed descriptor parses");
        assert_eq!(descriptor.bytes(), fixture);
        assert_eq!(descriptor.vault_id, std::array::from_fn(|i| i as u8));
        for length in 0..fixture.len() {
            assert!(Descriptor::parse(&fixture[..length]).is_err());
        }
        let mut extended = fixture.to_vec();
        extended.push(0);
        assert!(Descriptor::parse(&extended).is_err());
    }

    assert_eq!(index::node_hash(LEFT), *LEFT_HASH);
    assert_eq!(index::node_hash(RIGHT), *RIGHT_HASH);
    assert_eq!(index::node_hash(BRANCH), *BRANCH_HASH);
    let left_id = [0; 16];
    let mut right_id = [0; 16];
    right_id[0] = 0x80;
    let left_entry = Entry {
        revision: 1,
        digest: [0x11; 32],
    };
    let right_entry = Entry {
        revision: 2,
        digest: [0x22; 32],
    };
    let mut store = Store::default();
    let first = index::upsert(&mut store, None, left_id, left_entry.clone()).expect("insert left");
    assert_eq!(first.root, *LEFT_HASH);
    assert_eq!(store.0.get(LEFT_HASH).expect("left leaf bytes"), LEFT);
    let second = index::upsert(&mut store, Some(first.root), right_id, right_entry.clone())
        .expect("insert right");
    assert_eq!(second.root, *BRANCH_HASH);
    assert_eq!(store.0.get(RIGHT_HASH).expect("right leaf bytes"), RIGHT);
    assert_eq!(store.0.get(BRANCH_HASH).expect("root branch bytes"), BRANCH);
    assert_eq!(
        index::lookup(&mut store, Some(*BRANCH_HASH), &left_id)
            .expect("fixed left lookup")
            .entry,
        Some(left_entry)
    );
    assert_eq!(
        index::lookup(&mut store, Some(*BRANCH_HASH), &right_id)
            .expect("fixed right lookup")
            .entry,
        Some(right_entry)
    );

    let descriptor = Descriptor::parse(DESCRIPTOR_P2).expect("P2 descriptor");
    let key = [0x77; 32];
    let empty = IndexHead {
        generation: 0,
        request_id: [0; 16],
        operation_digest: [0; 32],
        count: 0,
        root: None,
    };
    assert_eq!(empty.encode(&descriptor, &key), EMPTY_HEAD);
    let populated = IndexHead {
        generation: 7,
        request_id: [0x33; 16],
        operation_digest: [0x44; 32],
        count: 2,
        root: Some(*BRANCH_HASH),
    };
    assert_eq!(populated.encode(&descriptor, &key), POPULATED_HEAD);
    for (fixture, count, root) in [
        (EMPTY_HEAD, 0, None),
        (POPULATED_HEAD, 2, Some(*BRANCH_HASH)),
    ] {
        let decoded = IndexHead::parse(fixture, &descriptor, &key, limits()).expect("fixed head");
        assert_eq!(decoded.count, count);
        assert_eq!(decoded.root, root);
        assert_eq!(decoded.encode(&descriptor, &key), fixture);
        for length in 0..fixture.len() {
            assert!(IndexHead::parse(&fixture[..length], &descriptor, &key, limits()).is_err());
        }
        let mut extended = fixture.to_vec();
        extended.push(0);
        assert!(IndexHead::parse(&extended, &descriptor, &key, limits()).is_err());
        let mut changed = fixture.to_vec();
        changed[0] ^= 1;
        assert!(IndexHead::parse(&changed, &descriptor, &key, limits()).is_err());
        assert!(IndexHead::parse(fixture, &descriptor, &[0x78; 32], limits()).is_err());
    }
}
