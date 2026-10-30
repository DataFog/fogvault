//! Transactional record operations around the portable Engine's opaque plans.
use super::*;
use fogvault::{RecordCursor, RecordPage};

impl Vault {
    pub fn delete(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: u64,
        request_id: [u8; 16],
    ) -> Result<CommitReceipt> {
        self.delete_with_fault(token, id, expected_revision, request_id, CommitFault::None)
    }

    pub fn delete_with_fault(
        &mut self,
        token: &SessionToken,
        id: RecordId,
        expected_revision: u64,
        request_id: [u8; 16],
        fault: CommitFault,
    ) -> Result<CommitReceipt> {
        if self.registered.is_some() {
            return self.registered_delete(token, id, expected_revision, request_id, fault);
        }
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        let limits = self.engine.limits();
        self.metrics = OperationMetrics::default();
        let draft = self
            .engine
            .draft_delete(id, expected_revision, request_id)?;
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
            // Lookup plus removal reads at most two selected paths and one
            // promoted sibling: 2*129+1, derived from the index key width.
            let mut nodes = SqliteNodes::new(&transaction, (2 * MAX_PATH_NODES + 1) as u64);
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
                .stage_delete(&draft, lookup, previous, &mut nodes)?;
            add_stats(&mut self.metrics.index, plan.stats);
            if plan.replay {
                work.check()?;
                transaction.commit().storage()?;
                return Ok(plan.receipt);
            }
            work.check()?;
            if transaction
                .execute(
                    "DELETE FROM records WHERE id=?1 AND revision=?2",
                    params![
                        id.as_slice(),
                        i64::try_from(plan.deleted_revision).map_err(|_| Error::ResourceLimit)?
                    ],
                )
                .storage()?
                != 1
            {
                return Err(Error::Conflict);
            }
            if transaction
                .execute(
                    "UPDATE vault_state SET head=?1 WHERE id=1 AND descriptor=?2 AND head=?3",
                    params![plan.head_bytes, plan.prior_descriptor, plan.prior_head],
                )
                .storage()?
                != 1
            {
                return Err(Error::Conflict);
            }
            self.metrics.head_bytes_written = plan.head_bytes.len() as u64;
            for hash in &plan.obsolete {
                let removed = transaction
                    .execute(
                        "DELETE FROM index_nodes WHERE hash=?1",
                        params![hash.as_slice()],
                    )
                    .storage()?;
                if removed != 1 {
                    return Err(Error::Integrity);
                }
                self.metrics.index_nodes_deleted += removed as u64;
            }
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
            match self.engine.confirm_commit(&plan.head_bytes) {
                Ok(receipt) => Ok(receipt),
                Err(_) => {
                    // Submission already completed. Revocation/confirmation
                    // failure cannot be reported as an ordinary aborted write.
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

    pub fn begin_records(&mut self, token: &SessionToken) -> Result<RecordCursor> {
        self.engine.check_session(token)?;
        self.metrics = OperationMetrics::default();
        let mut registration = self.registered.clone();
        let guard = transactions::read_guard(&mut registration)?;
        let transaction = self.connection.transaction().storage()?;
        let (descriptor, head) = load_header(
            &transaction,
            self.engine.limits(),
            &mut self.metrics,
            self.engine.descriptor_byte_limit(),
        )?;
        self.engine.check_snapshot(&descriptor, &head)?;
        transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
        let cursor = self.engine.begin_records()?;
        transaction.commit().storage()?;
        Ok(cursor)
    }

    /// Each page captures one transaction. A commit between pages invalidates
    /// this cursor instead of retaining historical roots or payload versions.
    pub fn record_page(
        &mut self,
        token: &SessionToken,
        cursor: &mut RecordCursor,
        maximum_records: usize,
    ) -> Result<RecordPage> {
        self.engine.check_session(token)?;
        self.metrics = OperationMetrics::default();
        let result = (|| {
            let mut registration = self.registered.clone();
            let guard = transactions::read_guard(&mut registration)?;
            let transaction = self.connection.transaction().storage()?;
            let limits = self.engine.limits();
            let (descriptor, head) = load_header(
                &transaction,
                limits,
                &mut self.metrics,
                self.engine.descriptor_byte_limit(),
            )?;
            self.engine.check_snapshot(&descriptor, &head)?;
            transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
            let mut nodes = SqliteNodes::new(&transaction, u64::MAX);
            let page = self
                .engine
                .record_page(cursor, &mut nodes, maximum_records)?;
            add_stats(&mut self.metrics.index, page.stats);
            for proof in &page.records {
                let row = load_record_admitted(
                    &transaction,
                    &proof.id(),
                    true,
                    self.engine.envelope_byte_limit()?,
                    &mut self.metrics,
                )?;
                self.engine.verify_record(
                    proof,
                    row.revision,
                    row.envelope.as_deref().ok_or(Error::Integrity)?,
                )?;
                self.metrics.records_scanned += 1;
            }
            if page.complete {
                let records: i64 = transaction
                    .query_row("SELECT count(*) FROM records", [], |row| row.get(0))
                    .storage()?;
                let nodes: i64 = transaction
                    .query_row("SELECT count(*) FROM index_nodes", [], |row| row.get(0))
                    .storage()?;
                let expected = cursor.record_count();
                let expected_nodes = if expected == 0 {
                    0
                } else {
                    expected
                        .checked_mul(2)
                        .and_then(|value| value.checked_sub(1))
                        .ok_or(Error::ResourceLimit)?
                };
                if u64::try_from(records).map_err(|_| Error::Integrity)? != expected
                    || u64::try_from(nodes).map_err(|_| Error::Integrity)? != expected_nodes
                {
                    return Err(Error::Integrity);
                }
            }
            transaction.commit().storage()?;
            Ok(page)
        })();
        if result.is_err() {
            cursor.cancel();
        }
        result
    }
}
