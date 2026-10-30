//! Record removal and bounded inventory traversal under the shared authority.
use super::*;
use crate::NodeHash;

pub struct DeleteDraft {
    id: RecordId,
    expected: u64,
    request: [u8; 16],
    operation_digest: [u8; 32],
    session: SessionToken,
    head_digest: [u8; 32],
}

pub struct DeletePlan {
    pub replay: bool,
    pub receipt: CommitReceipt,
    pub prior_descriptor: Vec<u8>,
    pub prior_head: Vec<u8>,
    pub head_bytes: Vec<u8>,
    pub id: RecordId,
    pub deleted_revision: u64,
    pub obsolete: Vec<[u8; 32]>,
    pub stats: IndexStats,
}

/// An opaque in-process cursor. It grants no historical snapshot or root pin.
pub struct RecordCursor {
    session: SessionToken,
    head_digest: [u8; 32],
    cursor: index::AuditCursor,
    checked: u64,
    expected_count: u64,
    expected_nodes: u64,
    failed: bool,
    complete: bool,
}
impl RecordCursor {
    /// Authenticated snapshot cardinality; not a claim of global freshness.
    pub fn record_count(&self) -> u64 {
        self.expected_count
    }
    pub fn records_checked(&self) -> u64 {
        self.checked
    }
    pub fn stats(&self) -> IndexStats {
        self.cursor.stats()
    }
    pub fn peak_frontier_nodes(&self) -> usize {
        self.cursor.peak_buffered_nodes()
    }
    /// Discard traversal authority after cancellation or an adapter-side error.
    pub fn cancel(&mut self) {
        self.failed = true;
    }
}

/// Every member has a current-head proof. `complete` additionally proves full
/// traversal/count finality; an earlier prefix page is not a full-inventory proof.
pub struct RecordPage {
    pub records: Vec<VerifiedRecord>,
    pub complete: bool,
    pub stats: IndexStats,
    pub peak_frontier_nodes: usize,
}

impl Engine {
    pub fn draft_delete(
        &self,
        id: RecordId,
        expected_revision: u64,
        request: [u8; 16],
    ) -> Result<DeleteDraft> {
        let keys = self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        if expected_revision == 0 || expected_revision > i64::MAX as u64 {
            return Err(Error::ResourceLimit);
        }
        let mut input = format::frame(b"fogvault/prototype/delete/v1");
        input.extend_from_slice(&self.vault_id());
        input.extend_from_slice(&id);
        input.extend_from_slice(&expected_revision.to_be_bytes());
        Ok(DeleteDraft {
            id,
            expected: expected_revision,
            request,
            operation_digest: crypto::mac(&keys.operation, &input),
            session: self.current_session()?,
            head_digest: crypto::digest(&self.head_bytes),
        })
    }

    pub fn stage_delete<S: NodeStore + ?Sized>(
        &mut self,
        draft: &DeleteDraft,
        lookup: VerifiedLookup,
        previous: Option<StoredRecord<'_>>,
        store: &mut S,
    ) -> Result<DeletePlan> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.check_session(&draft.session)?;
        let digest = crypto::digest(&self.head_bytes);
        if draft.head_digest != digest
            || lookup.head_digest != digest
            || lookup.session != draft.session
            || lookup.id != draft.id
        {
            return Err(Error::Conflict);
        }
        let found = lookup.entry.as_ref();
        if self.head.request_id == draft.request {
            if !crypto::tags_match(&self.head.operation_digest, &draft.operation_digest) {
                return Err(Error::OperationIdReuse);
            }
            if found.is_some() || previous.is_some() {
                return Err(Error::Integrity);
            }
            return Ok(DeletePlan {
                replay: true,
                receipt: Self::receipt(&self.head, &self.head_bytes),
                prior_descriptor: self.descriptor_bytes().to_vec(),
                prior_head: self.head_bytes.clone(),
                head_bytes: self.head_bytes.clone(),
                id: draft.id,
                deleted_revision: draft.expected,
                obsolete: Vec::new(),
                stats: IndexStats::default(),
            });
        }
        let proof = found.ok_or(Error::NotFound)?;
        if proof.revision() != draft.expected {
            return Err(Error::Conflict);
        }
        let old = previous.ok_or(Error::Integrity)?;
        self.verify_record(proof, old.revision, old.envelope)?;
        let mut head = self.head.clone();
        head.generation = head.generation.checked_add(1).ok_or(Error::ResourceLimit)?;
        head.count = head.count.checked_sub(1).ok_or(Error::Integrity)?;
        let removal = index::remove(store, head.root, &draft.id)?;
        if removal.previous.as_ref() != Some(&proof.entry)
            || removal.root.is_none() != (head.count == 0)
        {
            return Err(Error::Integrity);
        }
        head.root = removal.root;
        head.request_id = draft.request;
        head.operation_digest = draft.operation_digest;
        let bytes = head.encode(&self.descriptor, &self.raw_keys()?.head);
        let plan = DeletePlan {
            replay: false,
            receipt: Self::receipt(&head, &bytes),
            prior_descriptor: self.descriptor_bytes().to_vec(),
            prior_head: self.head_bytes.clone(),
            head_bytes: bytes.clone(),
            id: draft.id,
            deleted_revision: draft.expected,
            obsolete: removal.obsolete,
            stats: removal.stats,
        };
        self.pending = Some(Pending {
            head,
            bytes,
            unknown: false,
            descriptor: None,
            replacement_session: None,
            access_admission: None,
            protective: false,
            ordinary_binding: Some(control::bind_delete(&plan)?),
        });
        Ok(plan)
    }

    pub fn prepare_delete<S: NodeStore + ?Sized>(
        &mut self,
        store: &mut S,
        id: RecordId,
        expected_revision: u64,
        request: [u8; 16],
        previous: Option<StoredRecord<'_>>,
    ) -> Result<DeletePlan> {
        let draft = self.draft_delete(id, expected_revision, request)?;
        let lookup = self.lookup(store, &id)?;
        self.stage_delete(&draft, lookup, previous, store)
    }

    pub fn begin_records(&self) -> Result<RecordCursor> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let expected_nodes = if self.head.count == 0 {
            0
        } else {
            self.head
                .count
                .checked_mul(2)
                .and_then(|count| count.checked_sub(1))
                .ok_or(Error::ResourceLimit)?
        };
        Ok(RecordCursor {
            session: self.current_session()?,
            head_digest: crypto::digest(&self.head_bytes),
            cursor: index::AuditCursor::new(self.head.root, expected_nodes),
            checked: 0,
            expected_count: self.head.count,
            expected_nodes,
            failed: false,
            complete: false,
        })
    }

    pub fn record_page<S: NodeStore + ?Sized>(
        &self,
        cursor: &mut RecordCursor,
        store: &mut S,
        maximum_records: usize,
    ) -> Result<RecordPage> {
        self.check_record_cursor(cursor)?;
        if maximum_records == 0 {
            return Err(Error::ResourceLimit);
        }
        let result = self.record_page_inner(cursor, store, maximum_records);
        if result.is_err() {
            cursor.failed = true;
        }
        result
    }

    fn check_record_cursor(&self, cursor: &RecordCursor) -> Result<()> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.check_session(&cursor.session)?;
        if cursor.head_digest != crypto::digest(&self.head_bytes)
            || cursor.failed
            || cursor.complete
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Request one hash from the same authenticated cursor used by native pages.
    /// The adapter fetches it inside its coherent snapshot; no JS traversal is needed.
    pub fn record_next(&self, cursor: &RecordCursor) -> Result<Option<NodeHash>> {
        self.check_record_cursor(cursor)?;
        cursor.cursor.next_hash()
    }

    pub fn supply_record_node(
        &self,
        cursor: &mut RecordCursor,
        bytes: &[u8],
    ) -> Result<Option<VerifiedRecord>> {
        self.check_record_cursor(cursor)?;
        let result = (|| {
            let Some((id, entry)) = cursor.cursor.supply(bytes)? else {
                return Ok(None);
            };
            cursor.checked = cursor.checked.checked_add(1).ok_or(Error::ResourceLimit)?;
            if cursor.checked > cursor.expected_count {
                return Err(Error::Integrity);
            }
            Ok(Some(VerifiedRecord {
                id,
                entry,
                session: cursor.session,
                head_digest: cursor.head_digest,
            }))
        })();
        if result.is_err() {
            cursor.failed = true;
        }
        result
    }

    /// Complete inventory proof, after every requested node has been accepted.
    /// Adapters separately validate physical rows and snapshot completion before publishing.
    pub fn finish_records(&self, cursor: &mut RecordCursor) -> Result<IndexStats> {
        self.check_record_cursor(cursor)?;
        let stats = cursor.cursor.finish()?;
        if cursor.checked != cursor.expected_count || stats.nodes_read != cursor.expected_nodes {
            cursor.failed = true;
            return Err(Error::Integrity);
        }
        cursor.complete = true;
        Ok(stats)
    }

    fn record_page_inner<S: NodeStore + ?Sized>(
        &self,
        cursor: &mut RecordCursor,
        store: &mut S,
        maximum_records: usize,
    ) -> Result<RecordPage> {
        let before = cursor.cursor.stats();
        let remaining = cursor
            .expected_count
            .checked_sub(cursor.checked)
            .ok_or(Error::Integrity)?;
        let capacity =
            maximum_records.min(usize::try_from(remaining).map_err(|_| Error::ResourceLimit)?);
        let mut records = Vec::new();
        records
            .try_reserve(capacity)
            .map_err(|_| Error::ResourceLimit)?;
        while records.len() < maximum_records {
            let Some(hash) = self.record_next(cursor)? else {
                break;
            };
            let bytes = store.get(&hash)?.ok_or(Error::Integrity)?;
            if let Some(proof) = self.supply_record_node(cursor, &bytes)? {
                records.push(proof);
            }
        }
        let complete = self.record_next(cursor)?.is_none();
        if complete {
            self.finish_records(cursor)?;
        }
        let after = cursor.cursor.stats();
        Ok(RecordPage {
            records,
            complete,
            stats: IndexStats {
                nodes_read: after
                    .nodes_read
                    .checked_sub(before.nodes_read)
                    .ok_or(Error::Integrity)?,
                nodes_written: 0,
                bytes_read: after
                    .bytes_read
                    .checked_sub(before.bytes_read)
                    .ok_or(Error::Integrity)?,
                bytes_written: 0,
                peak_path_nodes: after.peak_path_nodes,
            },
            peak_frontier_nodes: cursor.cursor.peak_buffered_nodes(),
        })
    }
}
