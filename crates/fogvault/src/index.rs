//! Content-addressed compressed binary Merkle index for the disposable P2 design.
//!
//! The caller authenticates the root in its commit head and makes node/head writes
//! atomic. Node hashes alone provide no owner authentication or snapshot freshness.

#[cfg(any(test, feature = "experimental-codecs"))]
use std::collections::BTreeMap;

use crate::{crypto, format::Entry, Error, RecordId, Result};

pub type NodeHash = [u8; 32];
pub const KEY_BITS: usize = 16 * 8;
pub const MAX_PATH_NODES: usize = KEY_BITS + 1;
pub const LEAF_BYTES: usize = 1 + 16 + 8 + 32;
pub const BRANCH_BYTES: usize = 1 + 1 + 16 + 32 + 32;
pub const MAX_NODE_BYTES: usize = BRANCH_BYTES;
const HASH_DOMAIN: &[u8] = b"fogvault/prototype/index-node/v2\0";

/// Implementations admit a node's stored byte length before allocating its BLOB.
/// `put` must preserve immutable content at a hash and be in the caller's commit.
pub trait NodeStore {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()>;
}

/// Node-store calls and canonical byte volumes, excluding payload/SQLite I/O.
/// `nodes_written` counts put attempts; adapters may deduplicate identical bytes.
/// `peak_path_nodes` is traversal depth, not a process-heap/RSS measurement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub nodes_read: u64,
    pub nodes_written: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub peak_path_nodes: usize,
}

impl Stats {
    fn read(&mut self, bytes: usize, depth: usize) -> Result<()> {
        self.nodes_read = self.nodes_read.checked_add(1).ok_or(Error::ResourceLimit)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(bytes as u64)
            .ok_or(Error::ResourceLimit)?;
        self.peak_path_nodes = self.peak_path_nodes.max(depth);
        Ok(())
    }

    fn write(&mut self, bytes: usize) -> Result<()> {
        self.nodes_written = self
            .nodes_written
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(bytes as u64)
            .ok_or(Error::ResourceLimit)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Lookup {
    pub entry: Option<Entry>,
    pub stats: Stats,
}

#[derive(Debug)]
pub struct Change {
    pub root: NodeHash,
    pub previous: Option<Entry>,
    /// Old nodes replaced by this path copy. Retire atomically with the new head.
    pub obsolete: Vec<NodeHash>,
    pub stats: Stats,
}

/// Authenticated path-local removal; an empty final tree has no root hash.
#[derive(Debug)]
pub struct Removal {
    pub root: Option<NodeHash>,
    pub previous: Option<Entry>,
    pub obsolete: Vec<NodeHash>,
    pub stats: Stats,
}

#[cfg(any(test, feature = "experimental-codecs"))]
#[derive(Debug)]
pub struct Audit {
    pub entries: BTreeMap<RecordId, Entry>,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        id: RecordId,
        entry: Entry,
    },
    Branch {
        split: u8,
        prefix: RecordId,
        left: NodeHash,
        right: NodeHash,
    },
}

impl Node {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Leaf { id, entry } => {
                let mut bytes = Vec::with_capacity(LEAF_BYTES);
                bytes.push(0);
                bytes.extend_from_slice(id);
                bytes.extend_from_slice(&entry.revision.to_be_bytes());
                bytes.extend_from_slice(&entry.digest);
                bytes
            }
            Self::Branch {
                split,
                prefix,
                left,
                right,
            } => {
                let mut bytes = Vec::with_capacity(BRANCH_BYTES);
                bytes.extend_from_slice(&[1, *split]);
                bytes.extend_from_slice(prefix);
                bytes.extend_from_slice(left);
                bytes.extend_from_slice(right);
                bytes
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes.first() {
            Some(0) if bytes.len() == LEAF_BYTES => {
                let id = bytes[1..17].try_into().map_err(|_| Error::Integrity)?;
                let revision =
                    u64::from_be_bytes(bytes[17..25].try_into().map_err(|_| Error::Integrity)?);
                let digest = bytes[25..57].try_into().map_err(|_| Error::Integrity)?;
                let entry = Entry { revision, digest };
                validate_entry(&entry)?;
                Ok(Self::Leaf { id, entry })
            }
            Some(1) if bytes.len() == BRANCH_BYTES => {
                let split = bytes[1];
                if usize::from(split) >= KEY_BITS {
                    return Err(Error::Integrity);
                }
                let prefix = bytes[2..18].try_into().map_err(|_| Error::Integrity)?;
                let left = bytes[18..50].try_into().map_err(|_| Error::Integrity)?;
                let right = bytes[50..82].try_into().map_err(|_| Error::Integrity)?;
                if canonical_prefix(&prefix, usize::from(split)) != prefix || left == right {
                    return Err(Error::Integrity);
                }
                Ok(Self::Branch {
                    split,
                    prefix,
                    left,
                    right,
                })
            }
            _ => Err(Error::Malformed("index node tag or exact width")),
        }
    }

    fn representative(&self) -> &RecordId {
        match self {
            Self::Leaf { id, .. } => id,
            Self::Branch { prefix, .. } => prefix,
        }
    }

    fn validate_child(&self, side: bool, child: &Self) -> Result<()> {
        let Self::Branch { split, prefix, .. } = self else {
            return Err(Error::Integrity);
        };
        if let Self::Branch {
            split: child_split, ..
        } = child
        {
            if child_split <= split {
                return Err(Error::Integrity);
            }
        }
        if !matches_prefix(child.representative(), prefix, usize::from(*split))
            || bit(child.representative(), usize::from(*split)) != side
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

fn validate_entry(entry: &Entry) -> Result<()> {
    if entry.revision == 0 || entry.revision > i64::MAX as u64 {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn bit(id: &RecordId, position: usize) -> bool {
    id[position / 8] & (0x80 >> (position % 8)) != 0
}

fn canonical_prefix(id: &RecordId, length: usize) -> RecordId {
    let mut prefix = *id;
    let whole = length / 8;
    let tail = length % 8;
    if tail != 0 {
        prefix[whole] &= 0xff << (8 - tail);
        prefix[whole + 1..].fill(0);
    } else {
        prefix[whole..].fill(0);
    }
    prefix
}

fn matches_prefix(id: &RecordId, prefix: &RecordId, length: usize) -> bool {
    canonical_prefix(id, length) == *prefix
}

fn first_difference(first: &RecordId, second: &RecordId) -> Option<usize> {
    first
        .iter()
        .zip(second)
        .enumerate()
        .find_map(|(index, (a, b))| {
            let difference = a ^ b;
            (difference != 0).then(|| index * 8 + difference.leading_zeros() as usize)
        })
}

pub fn node_hash(bytes: &[u8]) -> NodeHash {
    let mut input = Vec::with_capacity(HASH_DOMAIN.len() + bytes.len());
    input.extend_from_slice(HASH_DOMAIN);
    input.extend_from_slice(bytes);
    crypto::digest(&input)
}

fn load<S: NodeStore + ?Sized>(
    store: &mut S,
    hash: &NodeHash,
    stats: &mut Stats,
    depth: usize,
) -> Result<Node> {
    if depth > MAX_PATH_NODES {
        return Err(Error::Integrity);
    }
    let bytes = store.get(hash)?.ok_or(Error::Integrity)?;
    if bytes.len() > MAX_NODE_BYTES {
        return Err(Error::ResourceLimit);
    }
    stats.read(bytes.len(), depth)?;
    if node_hash(&bytes) != *hash {
        return Err(Error::Integrity);
    }
    Node::decode(&bytes)
}

fn persist<S: NodeStore + ?Sized>(
    store: &mut S,
    node: &Node,
    stats: &mut Stats,
) -> Result<NodeHash> {
    let bytes = node.encode();
    let hash = node_hash(&bytes);
    store.put(hash, &bytes)?;
    stats.write(bytes.len())?;
    Ok(hash)
}

/// Returns a committed entry or an authenticated absence along the selected path.
/// It does not scrub unrelated branches or validate every stored record BLOB.
pub fn lookup<S: NodeStore + ?Sized>(
    store: &mut S,
    root: Option<NodeHash>,
    id: &RecordId,
) -> Result<Lookup> {
    let mut stats = Stats::default();
    let Some(mut hash) = root else {
        return Ok(Lookup { entry: None, stats });
    };
    let mut parent: Option<(Node, bool)> = None;
    let mut depth = 1;
    loop {
        let node = load(store, &hash, &mut stats, depth)?;
        if let Some((previous, side)) = &parent {
            previous.validate_child(*side, &node)?;
        }
        match &node {
            Node::Leaf { id: found, entry } => {
                return Ok(Lookup {
                    entry: (found == id).then(|| entry.clone()),
                    stats,
                })
            }
            Node::Branch {
                split,
                prefix,
                left,
                right,
            } => {
                if !matches_prefix(id, prefix, usize::from(*split)) {
                    return Ok(Lookup { entry: None, stats });
                }
                let side = bit(id, usize::from(*split));
                hash = if side { *right } else { *left };
                parent = Some((node, side));
                depth += 1;
            }
        }
    }
}

/// Path-copies an insert/update. The caller commits new nodes/root and retires
/// `obsolete` together; retaining historical roots requires an explicit pin policy.
pub fn upsert<S: NodeStore + ?Sized>(
    store: &mut S,
    root: Option<NodeHash>,
    id: RecordId,
    entry: Entry,
) -> Result<Change> {
    validate_entry(&entry)?;
    let mut stats = Stats::default();
    let mut path: Vec<(NodeHash, Node, bool)> = Vec::new();
    let mut obsolete = Vec::new();
    let new_leaf = Node::Leaf {
        id,
        entry: entry.clone(),
    };
    let Some(mut hash) = root else {
        let root = persist(store, &new_leaf, &mut stats)?;
        return Ok(Change {
            root,
            previous: None,
            obsolete,
            stats,
        });
    };
    let (mut replacement, previous) = loop {
        let node = load(store, &hash, &mut stats, path.len() + 1)?;
        if let Some((_, parent, side)) = path.last() {
            parent.validate_child(*side, &node)?;
        }
        match &node {
            Node::Leaf {
                id: found,
                entry: old,
            } if *found == id => {
                if *old == entry {
                    return Ok(Change {
                        root: root.ok_or(Error::Integrity)?,
                        previous: Some(old.clone()),
                        obsolete,
                        stats,
                    });
                }
                obsolete.push(hash);
                break (persist(store, &new_leaf, &mut stats)?, Some(old.clone()));
            }
            Node::Branch {
                split,
                prefix,
                left,
                right,
            } if matches_prefix(&id, prefix, usize::from(*split)) => {
                let side = bit(&id, usize::from(*split));
                let next = if side { *right } else { *left };
                path.push((hash, node, side));
                hash = next;
            }
            _ => {
                let split = first_difference(&id, node.representative()).ok_or(Error::Integrity)?;
                let leaf_hash = persist(store, &new_leaf, &mut stats)?;
                let (left, right) = if bit(&id, split) {
                    (hash, leaf_hash)
                } else {
                    (leaf_hash, hash)
                };
                let branch = Node::Branch {
                    split: split as u8,
                    prefix: canonical_prefix(&id, split),
                    left,
                    right,
                };
                branch.validate_child(bit(&id, split), &new_leaf)?;
                branch.validate_child(!bit(&id, split), &node)?;
                break (persist(store, &branch, &mut stats)?, None);
            }
        }
    };
    while let Some((old_hash, parent, side)) = path.pop() {
        let Node::Branch {
            split,
            prefix,
            mut left,
            mut right,
        } = parent
        else {
            return Err(Error::Integrity);
        };
        if side {
            right = replacement;
        } else {
            left = replacement;
        }
        replacement = persist(
            store,
            &Node::Branch {
                split,
                prefix,
                left,
                right,
            },
            &mut stats,
        )?;
        obsolete.push(old_hash);
    }
    Ok(Change {
        root: replacement,
        previous,
        obsolete,
        stats,
    })
}

/// Remove a selected leaf and collapse its parent, preserving canonical shape.
/// The promoted sibling is fetched and validated before publication. Every old
/// path object in `obsolete` must retire atomically with the caller's new head.
pub fn remove<S: NodeStore + ?Sized>(
    store: &mut S,
    root: Option<NodeHash>,
    id: &RecordId,
) -> Result<Removal> {
    let mut stats = Stats::default();
    let Some(mut hash) = root else {
        return Ok(Removal {
            root: None,
            previous: None,
            obsolete: Vec::new(),
            stats,
        });
    };
    let mut path: Vec<(NodeHash, Node, bool)> = Vec::new();
    let previous = loop {
        let node = load(store, &hash, &mut stats, path.len() + 1)?;
        if let Some((_, parent, side)) = path.last() {
            parent.validate_child(*side, &node)?;
        }
        match &node {
            Node::Leaf { id: found, entry } if found == id => break entry.clone(),
            Node::Branch {
                split,
                prefix,
                left,
                right,
            } if matches_prefix(id, prefix, usize::from(*split)) => {
                let side = bit(id, usize::from(*split));
                let next = if side { *right } else { *left };
                path.push((hash, node, side));
                hash = next;
            }
            _ => {
                return Ok(Removal {
                    root,
                    previous: None,
                    obsolete: Vec::new(),
                    stats,
                })
            }
        }
    };
    let mut obsolete = vec![hash];
    let Some((parent_hash, parent, side)) = path.pop() else {
        return Ok(Removal {
            root: None,
            previous: Some(previous),
            obsolete,
            stats,
        });
    };
    let Node::Branch { left, right, .. } = &parent else {
        return Err(Error::Integrity);
    };
    let mut replacement = if side { *left } else { *right };
    let mut replacement_node = load(store, &replacement, &mut stats, path.len() + 2)?;
    parent.validate_child(!side, &replacement_node)?;
    obsolete.push(parent_hash);
    while let Some((old_hash, parent, side)) = path.pop() {
        parent.validate_child(side, &replacement_node)?;
        let Node::Branch {
            split,
            prefix,
            mut left,
            mut right,
        } = parent
        else {
            return Err(Error::Integrity);
        };
        if side {
            right = replacement;
        } else {
            left = replacement;
        }
        replacement_node = Node::Branch {
            split,
            prefix,
            left,
            right,
        };
        replacement = persist(store, &replacement_node, &mut stats)?;
        obsolete.push(old_hash);
    }
    Ok(Removal {
        root: Some(replacement),
        previous: Some(previous),
        obsolete,
        stats,
    })
}

/// Incremental authenticated DFS for asynchronous storage adapters. Only one
/// supplied node is decoded at a time; the retained frontier is key-width bound.
/// The caller authenticates the root/count and validates each returned leaf's
/// record metadata before requesting another node. A failure poisons the cursor.
struct AuditFrame {
    hash: NodeHash,
    parent: Option<(Node, bool)>,
    depth: usize,
}

pub struct AuditCursor {
    stack: Vec<AuditFrame>,
    previous_id: Option<RecordId>,
    maximum_nodes: u64,
    stats: Stats,
    peak_buffered_nodes: usize,
    failed: bool,
}

impl AuditCursor {
    pub fn new(root: Option<NodeHash>, maximum_nodes: u64) -> Self {
        let stack = root
            .map(|hash| {
                vec![AuditFrame {
                    hash,
                    parent: None,
                    depth: 1,
                }]
            })
            .unwrap_or_default();
        let peak_buffered_nodes = stack.len();
        Self {
            stack,
            previous_id: None,
            maximum_nodes,
            stats: Stats::default(),
            peak_buffered_nodes,
            failed: false,
        }
    }

    pub fn next_hash(&self) -> Result<Option<NodeHash>> {
        if self.failed {
            return Err(Error::Integrity);
        }
        Ok(self.stack.last().map(|item| item.hash))
    }

    pub fn supply(&mut self, bytes: &[u8]) -> Result<Option<(RecordId, Entry)>> {
        if self.failed {
            return Err(Error::Integrity);
        }
        let result = self.supply_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn supply_inner(&mut self, bytes: &[u8]) -> Result<Option<(RecordId, Entry)>> {
        if bytes.len() > MAX_NODE_BYTES {
            return Err(Error::ResourceLimit);
        }
        let AuditFrame {
            hash,
            parent,
            depth,
        } = self.stack.pop().ok_or(Error::Integrity)?;
        if depth > MAX_PATH_NODES || self.stats.nodes_read >= self.maximum_nodes {
            return Err(Error::Integrity);
        }
        if node_hash(bytes) != hash {
            return Err(Error::Integrity);
        }
        let node = Node::decode(bytes)?;
        if let Some((parent, side)) = parent {
            parent.validate_child(side, &node)?;
        }
        self.stats.read(bytes.len(), depth)?;
        match &node {
            Node::Leaf { id, entry } => {
                if self.previous_id.is_some_and(|previous| previous >= *id) {
                    return Err(Error::Integrity);
                }
                self.previous_id = Some(*id);
                Ok(Some((*id, entry.clone())))
            }
            Node::Branch { left, right, .. } => {
                self.stack.push(AuditFrame {
                    hash: *right,
                    parent: Some((node.clone(), true)),
                    depth: depth + 1,
                });
                self.stack.push(AuditFrame {
                    hash: *left,
                    parent: Some((node, false)),
                    depth: depth + 1,
                });
                if self.stack.len() > MAX_PATH_NODES {
                    return Err(Error::Integrity);
                }
                self.peak_buffered_nodes = self.peak_buffered_nodes.max(self.stack.len());
                Ok(None)
            }
        }
    }

    #[cfg(any(test, feature = "experimental-codecs"))]
    pub fn buffered_nodes(&self) -> usize {
        self.stack.len()
    }
    pub fn peak_buffered_nodes(&self) -> usize {
        self.peak_buffered_nodes
    }
    /// Work observed so far, including an incomplete traversal.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Completion requires all pending nodes, not only the leaves already seen.
    /// Exact inventory counts remain the authenticated-head adapter's contract.
    pub fn finish(&self) -> Result<Stats> {
        if self.failed || !self.stack.is_empty() {
            return Err(Error::Integrity);
        }
        Ok(self.stats)
    }
}

/// Streams committed leaves in lexical order. Traversal stack is bounded by the
/// 128-bit key width, while a complete audit deliberately reads every live node.
#[cfg(any(test, feature = "experimental-codecs"))]
pub fn audit_visit<S: NodeStore + ?Sized>(
    store: &mut S,
    root: Option<NodeHash>,
    mut visitor: impl FnMut(&RecordId, &Entry) -> Result<()>,
) -> Result<Stats> {
    let mut stats = Stats::default();
    let Some(root) = root else {
        return Ok(stats);
    };
    let mut stack = vec![(root, None::<(Node, bool)>, 1usize)];
    let mut previous_id = None;
    while let Some((hash, parent, depth)) = stack.pop() {
        let node = load(store, &hash, &mut stats, depth)?;
        if let Some((parent, side)) = parent {
            parent.validate_child(side, &node)?;
        }
        match &node {
            Node::Leaf { id, entry } => {
                if previous_id.is_some_and(|previous| previous >= *id) {
                    return Err(Error::Integrity);
                }
                visitor(id, entry)?;
                previous_id = Some(*id);
            }
            Node::Branch { left, right, .. } => {
                stack.push((*right, Some((node.clone(), true)), depth + 1));
                stack.push((*left, Some((node, false)), depth + 1));
            }
        }
    }
    Ok(stats)
}

/// Convenience full materialization for comparisons; use audit_visit to stream.
#[cfg(any(test, feature = "experimental-codecs"))]
pub fn audit<S: NodeStore + ?Sized>(store: &mut S, root: Option<NodeHash>) -> Result<Audit> {
    let mut entries = BTreeMap::new();
    let stats = audit_visit(store, root, |id, entry| {
        if entries.insert(*id, entry.clone()).is_some() {
            return Err(Error::Integrity);
        }
        Ok(())
    })?;
    Ok(Audit { entries, stats })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryStore(BTreeMap<NodeHash, Vec<u8>>);
    impl NodeStore for MemoryStore {
        fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(hash).cloned())
        }
        fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
            match self.0.get(&hash) {
                Some(previous) if previous != bytes => Err(Error::Integrity),
                Some(_) => Ok(()),
                None => {
                    self.0.insert(hash, bytes.to_vec());
                    Ok(())
                }
            }
        }
    }

    fn entry(revision: u64, value: u64) -> Entry {
        Entry {
            revision,
            digest: crypto::digest(&value.to_be_bytes()),
        }
    }

    fn key(value: u64) -> RecordId {
        let hash = crypto::digest(&value.to_be_bytes());
        hash[..16].try_into().unwrap()
    }

    fn apply(
        store: &mut MemoryStore,
        root: Option<NodeHash>,
        id: RecordId,
        value: Entry,
    ) -> Change {
        let change = upsert(store, root, id, value).unwrap();
        for obsolete in &change.obsolete {
            store.0.remove(obsolete);
        }
        change
    }

    #[test]
    fn removal_matches_independent_map_and_canonical_roots_until_empty() {
        let mut store = MemoryStore::default();
        let mut root = None;
        let mut expected = BTreeMap::new();
        for value in 0..=u8::MAX {
            let id = key(u64::from(value));
            let value = entry(1, u64::from(value));
            root = Some(apply(&mut store, root, id, value.clone()).root);
            expected.insert(id, value);
        }
        let absent = remove(&mut store, root, &key(u64::MAX)).unwrap();
        assert_eq!(absent.root, root);
        assert!(absent.previous.is_none() && absent.obsolete.is_empty());
        for value in (0..=u8::MAX).rev() {
            let id = key(u64::from(value));
            let removed = remove(&mut store, root, &id).unwrap();
            assert_eq!(removed.previous, expected.remove(&id));
            assert!(removed.stats.nodes_read <= (MAX_PATH_NODES + 1) as u64);
            assert!(removed.stats.nodes_written <= (MAX_PATH_NODES - 2) as u64);
            for hash in &removed.obsolete {
                assert!(store.0.remove(hash).is_some());
            }
            root = removed.root;
            assert!(lookup(&mut store, root, &id).unwrap().entry.is_none());
            assert_eq!(audit(&mut store, root).unwrap().entries, expected);
            let mut rebuilt = MemoryStore::default();
            let mut canonical = None;
            for (id, value) in &expected {
                canonical = Some(apply(&mut rebuilt, canonical, *id, value.clone()).root);
            }
            assert_eq!(root, canonical);
            assert_eq!(
                store.0.len(),
                expected.len().saturating_mul(2).saturating_sub(1)
            );
        }
        assert!(root.is_none());
        let absent = remove(&mut store, root, &[0; 16]).unwrap();
        assert!(absent.root.is_none() && absent.previous.is_none());
    }

    #[test]
    fn removal_validates_the_promoted_sibling_before_mutation() {
        let left_id = [0; 16];
        let mut right_id = [0; 16];
        right_id[0] = 0x80;
        for variant in 0..3 {
            let mut store = MemoryStore::default();
            let left = Node::Leaf {
                id: left_id,
                entry: entry(1, 1),
            };
            let right = Node::Leaf {
                id: if variant == 2 { [1; 16] } else { right_id },
                entry: entry(1, 2),
            };
            let mut stats = Stats::default();
            let left_hash = persist(&mut store, &left, &mut stats).unwrap();
            let right_hash = persist(&mut store, &right, &mut stats).unwrap();
            let root = persist(
                &mut store,
                &Node::Branch {
                    split: 0,
                    prefix: [0; 16],
                    left: left_hash,
                    right: right_hash,
                },
                &mut stats,
            )
            .unwrap();
            if variant == 0 {
                store.0.remove(&right_hash);
            }
            if variant == 1 {
                store.0.get_mut(&right_hash).unwrap()[1] ^= 1;
            }
            let before = store.0.clone();
            assert!(remove(&mut store, Some(root), &left_id).is_err());
            assert_eq!(store.0, before);
        }
    }

    #[test]
    fn removal_of_deep_boundary_paths_keeps_the_key_width_work_bound() {
        let mut store = MemoryStore::default();
        let mut root = None;
        let mut ids = vec![[0; 16], [0xff; 16]];
        for split in 0..KEY_BITS {
            let mut id = [0; 16];
            id[split / 8] = 0x80 >> (split % 8);
            ids.push(id);
        }
        ids.sort();
        ids.dedup();
        for id in &ids {
            root = Some(apply(&mut store, root, *id, entry(1, 7)).root);
        }
        for id in ids {
            let removed = remove(&mut store, root, &id).unwrap();
            assert!(removed.previous.is_some());
            assert!(removed.stats.nodes_read <= (MAX_PATH_NODES + 1) as u64);
            for hash in removed.obsolete {
                assert!(store.0.remove(&hash).is_some());
            }
            root = removed.root;
            audit(&mut store, root).unwrap();
        }
        assert!(root.is_none() && store.0.is_empty());
    }

    #[test]
    fn index_matches_independent_map_for_insert_update_and_absence() {
        let mut store = MemoryStore::default();
        let mut root = None;
        let mut expected = BTreeMap::new();
        // The entire one-byte namespace supplies a finite exhaustive fixture.
        for value in 0..=u8::MAX {
            let id = key(u64::from(value));
            let value = entry(1, u64::from(value));
            let change = apply(&mut store, root, id, value.clone());
            assert_eq!(change.previous, expected.insert(id, value));
            assert!(change.stats.nodes_read <= MAX_PATH_NODES as u64);
            assert!(change.stats.nodes_written <= MAX_PATH_NODES as u64 + 1);
            root = Some(change.root);
        }
        for (id, value) in &expected {
            assert_eq!(
                lookup(&mut store, root, id).unwrap().entry.as_ref(),
                Some(value)
            );
        }
        for value in 0..=u8::MAX {
            let id = key(u64::from(value));
            let value = entry(2, u64::from(value) + 1);
            let change = apply(&mut store, root, id, value.clone());
            assert_eq!(change.previous, expected.insert(id, value));
            root = Some(change.root);
        }
        assert!(lookup(&mut store, root, &key(u64::MAX))
            .unwrap()
            .entry
            .is_none());
        let audited = audit(&mut store, root).unwrap();
        assert_eq!(audited.entries, expected);
        assert_eq!(audited.stats.nodes_read, (2 * expected.len() - 1) as u64);
        assert_eq!(store.0.len(), 2 * expected.len() - 1);
    }

    #[test]
    fn boundary_keys_and_deep_shared_prefixes_remain_bounded_and_canonical() {
        let mut store = MemoryStore::default();
        let mut root = None;
        let mut expected = BTreeMap::new();
        let mut keys = vec![[0; 16], [0xff; 16]];
        for position in 0..KEY_BITS {
            let mut id = [0; 16];
            id[position / 8] |= 0x80 >> (position % 8);
            keys.push(id);
        }
        keys.sort();
        keys.dedup();
        for id in keys.into_iter().rev() {
            let value = entry(1, u64::from(id[15]));
            let change = apply(&mut store, root, id, value.clone());
            assert!(change.stats.peak_path_nodes <= MAX_PATH_NODES);
            expected.insert(id, value);
            root = Some(change.root);
        }
        let report = audit(&mut store, root).unwrap();
        assert_eq!(report.entries, expected);
        assert!(report.stats.peak_path_nodes <= MAX_PATH_NODES);
        let no_change = upsert(&mut store, root, [0; 16], expected[&[0; 16]].clone()).unwrap();
        assert_eq!(Some(no_change.root), root);
        assert_eq!(no_change.stats.nodes_written, 0);
        assert!(no_change.obsolete.is_empty());
    }

    #[test]
    fn insertion_order_does_not_change_the_committed_map_root() {
        let keys: Vec<_> = (0..=u8::MAX).map(|value| key(u64::from(value))).collect();
        let mut first = MemoryStore::default();
        let mut second = MemoryStore::default();
        let mut left = None;
        let mut right = None;
        for id in &keys {
            left = Some(apply(&mut first, left, *id, entry(1, 9)).root);
        }
        for id in keys.iter().rev() {
            right = Some(apply(&mut second, right, *id, entry(1, 9)).root);
        }
        assert_eq!(left, right);
    }

    #[test]
    fn missing_modified_or_misplaced_nodes_cannot_be_reported_as_absence() {
        let mut store = MemoryStore::default();
        let first = apply(&mut store, None, [0; 16], entry(1, 1));
        let second = apply(&mut store, Some(first.root), [0xff; 16], entry(1, 2));
        let root = Some(second.root);
        let original = store.0[&second.root].clone();
        store.0.get_mut(&second.root).unwrap()[0] ^= 1;
        assert!(lookup(&mut store, root, &[0; 16]).is_err());
        store.0.insert(second.root, original);
        let Node::Branch { left, right, .. } = Node::decode(&store.0[&second.root]).unwrap() else {
            panic!("fixture branch");
        };
        let child = store.0.remove(&left).unwrap();
        assert!(lookup(&mut store, root, &[0; 16]).is_err());
        store.0.insert(left, child);
        let reversed = Node::Branch {
            split: 0,
            prefix: [0; 16],
            left: right,
            right: left,
        };
        let reversed_hash = node_hash(&reversed.encode());
        store.0.insert(reversed_hash, reversed.encode());
        assert!(lookup(&mut store, Some(reversed_hash), &[0; 16]).is_err());
        assert!(audit(&mut store, Some(reversed_hash)).is_err());
    }

    #[test]
    fn exact_node_widths_split_order_and_prefix_encoding_are_validated() {
        let leaf = Node::Leaf {
            id: [0; 16],
            entry: entry(1, 1),
        }
        .encode();
        assert_eq!(leaf.len(), LEAF_BYTES);
        for length in 0..leaf.len() {
            assert!(Node::decode(&leaf[..length]).is_err());
        }
        let mut extended = leaf;
        extended.push(0);
        assert!(Node::decode(&extended).is_err());
        let canonical = Node::Branch {
            split: 127,
            prefix: [0; 16],
            left: [1; 32],
            right: [2; 32],
        }
        .encode();
        assert_eq!(canonical.len(), BRANCH_BYTES);
        assert!(Node::decode(&canonical).is_ok());
        let mut wrong_prefix = canonical.clone();
        wrong_prefix[17] = 1;
        assert!(Node::decode(&wrong_prefix).is_err());
        let mut wrong_split = canonical;
        wrong_split[1] = 128;
        assert!(Node::decode(&wrong_split).is_err());
        let parent = Node::Branch {
            split: 1,
            prefix: [0; 16],
            left: [1; 32],
            right: [2; 32],
        };
        let child = Node::Branch {
            split: 1,
            prefix: [0; 16],
            left: [3; 32],
            right: [4; 32],
        };
        assert!(parent.validate_child(false, &child).is_err());
    }

    #[test]
    fn single_leaf_absence_and_empty_root_need_no_full_scan() {
        let mut store = MemoryStore::default();
        let empty = lookup(&mut store, None, &[1; 16]).unwrap();
        assert_eq!(empty.stats.nodes_read, 0);
        assert!(empty.entry.is_none());
        let change = apply(&mut store, None, [0; 16], entry(1, 1));
        let absent = lookup(&mut store, Some(change.root), &[1; 16]).unwrap();
        assert!(absent.entry.is_none());
        assert_eq!(absent.stats.nodes_read, 1);
        assert_eq!(absent.stats.bytes_read, LEAF_BYTES as u64);
    }

    #[test]
    fn incremental_audit_matches_full_walk_with_bounded_frontier() {
        let mut store = MemoryStore::default();
        let mut root = None;
        let mut expected = BTreeMap::new();
        for number in 0..=u8::MAX {
            let id = key(u64::from(number));
            let value = entry(1, u64::from(number));
            root = Some(apply(&mut store, root, id, value.clone()).root);
            expected.insert(id, value);
        }
        let mut cursor = AuditCursor::new(root, (2 * expected.len() - 1) as u64);
        assert!(cursor.finish().is_err());
        let mut actual = BTreeMap::new();
        while let Some(hash) = cursor.next_hash().unwrap() {
            if let Some((id, entry)) = cursor.supply(&store.0[&hash]).unwrap() {
                assert!(actual.insert(id, entry).is_none());
            }
            assert!(cursor.buffered_nodes() <= MAX_PATH_NODES);
        }
        assert_eq!(actual, expected);
        let stats = cursor.finish().unwrap();
        assert_eq!(stats, audit(&mut store, root).unwrap().stats);
        assert!(cursor.peak_buffered_nodes() <= MAX_PATH_NODES);
        assert_eq!(stats.nodes_read, (2 * expected.len() - 1) as u64);
    }

    #[test]
    fn incremental_audit_rejects_corruption_budget_and_post_completion_input() {
        let leaf = Node::Leaf {
            id: [0; 16],
            entry: entry(1, 1),
        }
        .encode();
        let root = Some(node_hash(&leaf));
        let mut corrupted = AuditCursor::new(root, 1);
        let mut bad = leaf.clone();
        bad[1] ^= 1;
        assert!(corrupted.supply(&bad).is_err());
        assert!(corrupted.supply(&leaf).is_err());
        assert!(corrupted.next_hash().is_err());
        assert!(corrupted.finish().is_err());
        let mut no_budget = AuditCursor::new(root, 0);
        assert!(no_budget.supply(&leaf).is_err());
        let mut exact = AuditCursor::new(root, 1);
        assert!(exact.supply(&leaf).unwrap().is_some());
        assert_eq!(exact.finish().unwrap().nodes_read, 1);
        assert!(exact.supply(&leaf).is_err());
        let empty = AuditCursor::new(None, 0);
        assert!(empty.next_hash().unwrap().is_none());
        assert_eq!(empty.finish().unwrap().nodes_read, 0);
    }
}
