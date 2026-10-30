//! Synthetic native growth experiment, not a latency or memory qualification.
//! The counting allocator is confined to this disposable benchmark executable.

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod benchmark {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        env, fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use fogvault_disposable_prototype::{crypto, Error, Limits, OperationMetrics, RecordId, Vault};
    use rusqlite::{Connection, OpenFlags};

    const PASSWORD: &[u8] = b"SYNTHETIC growth fixture: never real secrets";
    const METADATA: [u8; 32] = [b'M'; 32];
    const PAYLOAD: [u8; 256] = [b'P'; 256];
    const UPDATED_PAYLOAD: [u8; 256] = [b'U'; 256];
    // The same explicit two-record caller page used by the browser fixture.
    // This is an experiment input, not a product default or quota.
    const PAGE_RECORDS: usize = 2;

    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    static PAGE_PEAK: AtomicUsize = AtomicUsize::new(0);

    struct CountingAllocator;

    fn allocated(bytes: usize) {
        let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK.fetch_max(live, Ordering::Relaxed);
        PAGE_PEAK.fetch_max(live, Ordering::Relaxed);
    }

    // SAFETY: every operation delegates the original pointer and Layout to System.
    // Counters record only successful requested allocations and never inspect memory.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller provides the GlobalAlloc layout contract.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller provides the GlobalAlloc layout contract.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: the caller supplies a live System allocation and its layout.
            unsafe { System.dealloc(pointer, layout) };
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: the caller supplies the allocation/layout and a valid new size.
            let replacement = unsafe { System.realloc(pointer, layout, size) };
            if !replacement.is_null() {
                if size >= layout.size() {
                    allocated(size - layout.size());
                } else {
                    LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
                }
            }
            // A failed realloc leaves the original allocation and counters intact.
            replacement
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    #[derive(Clone, Copy)]
    struct Measurement {
        elapsed_ns: u128,
        baseline_allocated_bytes: usize,
        peak_allocated_bytes: usize,
        peak_live_allocated_bytes: usize,
    }

    fn measure<T>(
        operation: impl FnOnce() -> Result<T, fogvault_disposable_prototype::Error>,
    ) -> Result<(T, Measurement), fogvault_disposable_prototype::Error> {
        measure_with_peak(&PEAK, operation)
    }

    fn measure_with_peak<T>(
        counter: &AtomicUsize,
        operation: impl FnOnce() -> Result<T, fogvault_disposable_prototype::Error>,
    ) -> Result<(T, Measurement), fogvault_disposable_prototype::Error> {
        // This executable creates no Rust worker threads. Each operation gets a
        // fresh peak above the allocations that were already live at its start.
        let baseline = LIVE.load(Ordering::Relaxed);
        counter.store(baseline, Ordering::Relaxed);
        let started = Instant::now();
        let value = operation()?;
        let elapsed_ns = started.elapsed().as_nanos();
        let peak = counter.load(Ordering::Relaxed);
        Ok((
            value,
            Measurement {
                elapsed_ns,
                baseline_allocated_bytes: baseline,
                peak_allocated_bytes: peak.saturating_sub(baseline),
                peak_live_allocated_bytes: peak,
            },
        ))
    }

    struct Sample {
        operation: &'static str,
        metrics: OperationMetrics,
        measurement: Measurement,
    }

    impl Sample {
        fn json(&self, records: usize) -> String {
            let metrics = self.metrics;
            let measured = self.measurement;
            format!(
                concat!(
                    "{{\"records\":{},\"operation\":\"{}\",\"correctness\":true,",
                    "\"metrics\":{{\"nodes_read\":{},\"nodes_written\":{},",
                    "\"node_bytes_read\":{},\"node_bytes_written\":{},",
                    "\"max_path_depth\":{},\"records_scanned\":{},\"head_bytes\":{},",
                    "\"head_bytes_written\":{},\"record_rows_read\":{},",
                    "\"record_bytes_read\":{},\"record_bytes_written\":{},",
                    "\"index_nodes_deleted\":{},\"full_audits\":{}}},",
                    "\"elapsed_ns\":{},\"baseline_allocated_bytes\":{},",
                    "\"peak_allocated_bytes\":{},\"peak_live_allocated_bytes\":{}}}"
                ),
                records,
                self.operation,
                metrics.index.nodes_read,
                metrics.index.nodes_written,
                metrics.index.bytes_read,
                metrics.index.bytes_written,
                metrics.index.peak_path_nodes.saturating_sub(1),
                metrics.records_scanned,
                metrics.head_bytes_read,
                metrics.head_bytes_written,
                metrics.record_rows_read,
                metrics.record_bytes_read,
                metrics.record_bytes_written,
                metrics.index_nodes_deleted,
                metrics.full_audits,
                measured.elapsed_ns,
                measured.baseline_allocated_bytes,
                measured.peak_allocated_bytes,
                measured.peak_live_allocated_bytes,
            )
        }
    }

    fn record_id(value: u64) -> RecordId {
        crypto::digest(&value.to_be_bytes())[..16]
            .try_into()
            .expect("SHA256 prefix has 16 bytes")
    }

    fn request_id(prefix: &[u8; 8], value: u64) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(prefix);
        bytes[8..].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn add_metrics(total: &mut OperationMetrics, part: OperationMetrics) {
        total.index.nodes_read += part.index.nodes_read;
        total.index.nodes_written += part.index.nodes_written;
        total.index.bytes_read += part.index.bytes_read;
        total.index.bytes_written += part.index.bytes_written;
        total.index.peak_path_nodes = total.index.peak_path_nodes.max(part.index.peak_path_nodes);
        total.head_bytes_read += part.head_bytes_read;
        total.head_bytes_written += part.head_bytes_written;
        total.record_rows_read += part.record_rows_read;
        total.record_bytes_read += part.record_bytes_read;
        total.record_bytes_written += part.record_bytes_written;
        total.index_nodes_deleted += part.index_nodes_deleted;
        total.full_audits += part.full_audits;
        total.records_scanned += part.records_scanned;
    }

    // A constant-space ordered transcript distinguishes exact IDs/revisions.
    // The expected transcript sorts independent fixture IDs before measurement,
    // then drops that O(N) oracle. Enumeration retains only this digest and page.
    fn transcript(previous: [u8; 32], id: RecordId, revision: u64) -> [u8; 32] {
        let mut input = [0; 56];
        input[..32].copy_from_slice(&previous);
        input[32..48].copy_from_slice(&id);
        input[48..].copy_from_slice(&revision.to_be_bytes());
        crypto::digest(&input)
    }

    struct Enumeration {
        sample: Sample,
        begin: Sample,
        page_count: u64,
        last_page_records: usize,
        records_returned_max: usize,
        nodes_read_per_page_max: u64,
        node_bytes_read_per_page_max: u64,
        record_rows_per_page_max: u64,
        record_bytes_per_page_max: u64,
        frontier_nodes_max: usize,
        retained_proofs_max: usize,
        peak_allocated_bytes_per_page_max: usize,
        peak_live_allocated_bytes_per_page_max: usize,
    }

    impl Enumeration {
        fn json(&self, records: usize) -> String {
            format!(
                concat!(
                    "{{\"sample\":{},\"begin\":{},\"page_size\":{},\"page_count\":{},",
                    "\"last_page_records\":{},\"records_returned_max\":{},",
                    "\"nodes_read_per_page_max\":{},\"node_bytes_read_per_page_max\":{},",
                    "\"record_rows_per_page_max\":{},\"record_bytes_per_page_max\":{},",
                    "\"head_bytes_per_page\":129,\"frontier_nodes_max\":{},\"retained_proofs_max\":{},",
                    "\"peak_allocated_bytes_per_page_max\":{},\"peak_live_allocated_bytes_per_page_max\":{},",
                    "\"complete_only_final_page\":true,\"member_identity_revision_digest_matches\":true,",
                    "\"whole_inventory_materialized\":false}}"
                ),
                self.sample.json(records), self.begin.json(records), PAGE_RECORDS, self.page_count,
                self.last_page_records, self.records_returned_max, self.nodes_read_per_page_max,
                self.node_bytes_read_per_page_max, self.record_rows_per_page_max,
                self.record_bytes_per_page_max, self.frontier_nodes_max, self.retained_proofs_max,
                self.peak_allocated_bytes_per_page_max, self.peak_live_allocated_bytes_per_page_max,
            )
        }
    }

    fn enumerate(
        vault: &mut Vault,
        session: &fogvault_disposable_prototype::SessionToken,
        records: usize,
        target: RecordId,
    ) -> Result<Enumeration, Error> {
        let expected = {
            let mut ids = (0..records)
                .map(|n| record_id(n as u64))
                .collect::<Vec<_>>();
            ids.sort_unstable();
            ids.into_iter().fold([0; 32], |prior, id| {
                transcript(prior, id, if id == target { 2 } else { 1 })
            })
        };
        let (mut result, measurement) = measure(|| {
            let (mut cursor, measurement) =
                measure_with_peak(&PAGE_PEAK, || vault.begin_records(session))?;
            let begin = Sample {
                operation: "begin_records",
                metrics: vault.last_metrics(),
                measurement,
            };
            let mut result = Enumeration {
                sample: Sample {
                    operation: "enumerate",
                    metrics: begin.metrics,
                    measurement,
                },
                begin,
                page_count: 0,
                last_page_records: 0,
                records_returned_max: 0,
                nodes_read_per_page_max: 0,
                node_bytes_read_per_page_max: 0,
                record_rows_per_page_max: 0,
                record_bytes_per_page_max: 0,
                frontier_nodes_max: cursor.peak_frontier_nodes(),
                retained_proofs_max: 0,
                peak_allocated_bytes_per_page_max: 0,
                peak_live_allocated_bytes_per_page_max: 0,
            };
            let mut observed = [0; 32];
            let mut checked = 0;
            loop {
                let (page, measured) = measure_with_peak(&PAGE_PEAK, || {
                    vault.record_page(session, &mut cursor, PAGE_RECORDS)
                })?;
                let metrics = vault.last_metrics();
                let returned = page.records.len();
                checked += returned;
                if returned == 0
                    || returned > PAGE_RECORDS
                    || metrics.index.nodes_read > (PAGE_RECORDS * fogvault::MAX_PATH_NODES) as u64
                    || metrics.head_bytes_read != 129
                    || metrics.record_rows_read != returned as u64
                    || metrics.records_scanned != returned as u64
                    || metrics.record_bytes_read
                        != returned as u64 * (176 + METADATA.len() + PAYLOAD.len()) as u64
                    || metrics.index.nodes_written != 0
                    || metrics.index.bytes_written != 0
                    || metrics.record_bytes_written != 0
                    || metrics.head_bytes_written != 0
                    || metrics.index_nodes_deleted != 0
                    || metrics.full_audits != 0
                    || page.peak_frontier_nodes > fogvault::MAX_PATH_NODES
                    || page.complete != (checked == records)
                {
                    return Err(Error::Integrity);
                }
                for proof in &page.records {
                    observed = transcript(observed, proof.id(), proof.revision());
                }
                result.page_count += 1;
                result.last_page_records = returned;
                result.records_returned_max = result.records_returned_max.max(returned);
                result.nodes_read_per_page_max =
                    result.nodes_read_per_page_max.max(metrics.index.nodes_read);
                result.node_bytes_read_per_page_max = result
                    .node_bytes_read_per_page_max
                    .max(metrics.index.bytes_read);
                result.record_rows_per_page_max = result
                    .record_rows_per_page_max
                    .max(metrics.record_rows_read);
                result.record_bytes_per_page_max = result
                    .record_bytes_per_page_max
                    .max(metrics.record_bytes_read);
                result.frontier_nodes_max = result.frontier_nodes_max.max(page.peak_frontier_nodes);
                result.retained_proofs_max = result.retained_proofs_max.max(returned);
                result.peak_allocated_bytes_per_page_max = result
                    .peak_allocated_bytes_per_page_max
                    .max(measured.peak_allocated_bytes);
                result.peak_live_allocated_bytes_per_page_max = result
                    .peak_live_allocated_bytes_per_page_max
                    .max(measured.peak_live_allocated_bytes);
                add_metrics(&mut result.sample.metrics, metrics);
                if page.complete {
                    break;
                }
            }
            if observed != expected || checked != records {
                return Err(Error::Integrity);
            }
            Ok(result)
        })?;
        result.sample.measurement = measurement;
        let metrics = result.sample.metrics;
        if metrics.index.nodes_read != 2 * records as u64 - 1
            || metrics.index.bytes_read != 139 * records as u64 - 82
            || metrics.record_rows_read != records as u64
            || metrics.head_bytes_read != 129 * (result.page_count + 1)
            || result.page_count != records.div_ceil(PAGE_RECORDS) as u64
        {
            return Err(Error::Integrity);
        }
        Ok(result)
    }

    fn logical_size(path: &PathBuf) -> Result<(u64, u64, u64), Box<dyn std::error::Error>> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let descriptor: Vec<u8> =
            connection.query_row("SELECT descriptor FROM vault_state WHERE id=1", [], |row| {
                row.get(0)
            })?;
        if descriptor.get(..8) != Some(b"FGVP0003".as_slice())
            || descriptor.get(12..14) != Some(3u16.to_be_bytes().as_slice())
            || descriptor.get(30..38) != Some(0u64.to_be_bytes().as_slice())
        {
            return Err("growth fixture is not current content-three epoch-zero".into());
        }
        let (nodes, bytes, rows): (i64, i64, i64) = connection.query_row(
            "SELECT count(*), coalesce(sum(length(bytes)), 0), (SELECT count(*) FROM records) FROM index_nodes",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok((nodes.try_into()?, bytes.try_into()?, rows.try_into()?))
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut arguments = env::args_os().skip(1);
        let records: usize = arguments
            .next()
            .ok_or("usage: index-growth RECORDS unused-scratch-db-path")?
            .to_str()
            .ok_or("RECORDS must be UTF-8 decimal")?
            .parse()?;
        let path = PathBuf::from(arguments.next().ok_or("scratch DB path required")?);
        if records == 0 || records >= i64::MAX as usize - 1 || arguments.next().is_some() {
            return Err(
                "RECORDS must be positive and leave two available commit generations".into(),
            );
        }
        let limits = Limits {
            max_payload_bytes: PAYLOAD.len(),
            max_metadata_bytes: METADATA.len(),
            max_records: records,
        };
        let mut vault = Vault::diagnostic_create_current(&path, PASSWORD, limits)?;
        let session = vault.unlock(PASSWORD)?;
        let population_started = Instant::now();
        for value in 0..records {
            vault.save(
                &session,
                record_id(value as u64),
                None,
                &METADATA,
                &PAYLOAD,
                request_id(b"populate", value as u64),
            )?;
        }
        let population_elapsed_ns = population_started.elapsed().as_nanos();
        let target = record_id((records / 2) as u64);
        let (record, measurement) = measure(|| vault.read(&session, target))?;
        let read = Sample {
            operation: "read",
            metrics: vault.last_metrics(),
            measurement,
        };
        if record.revision != 1
            || record.payload.as_slice() != PAYLOAD
            || record.metadata.as_slice() != METADATA
        {
            return Err("point-read correctness failed".into());
        }
        drop(record);
        let (receipt, measurement) = measure(|| {
            vault.save(
                &session,
                target,
                Some(1),
                &METADATA,
                &UPDATED_PAYLOAD,
                request_id(b"measured", 0),
            )
        })?;
        let save = Sample {
            operation: "save",
            metrics: vault.last_metrics(),
            measurement,
        };
        let saved = vault.read(&session, target)?;
        if receipt.generation != records as u64 + 1
            || saved.revision != 2
            || saved.payload.as_slice() != UPDATED_PAYLOAD
            || saved.metadata.as_slice() != METADATA
        {
            return Err("point-update correctness failed".into());
        }
        drop(saved);
        let (report, measurement) = measure(|| vault.audit(&session))?;
        let audit = Sample {
            operation: "audit",
            metrics: vault.last_metrics(),
            measurement,
        };
        let expected_nodes = (records as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or("logical node count overflow")?;
        let expected_bytes = (records as u64)
            .checked_mul(139)
            .and_then(|n| n.checked_sub(82))
            .ok_or("logical byte count overflow")?;
        if report.records_checked != records as u64
            || report.index_nodes_checked != expected_nodes
            || audit.metrics.index.bytes_read != expected_bytes
        {
            return Err("full-audit correctness or growth invariant failed".into());
        }
        vault.lock();
        let (session, measurement) = measure(|| vault.unlock(PASSWORD))?;
        let unlock = Sample {
            operation: "unlock",
            metrics: vault.last_metrics(),
            measurement,
        };
        if unlock.metrics.records_scanned != records as u64
            || unlock.metrics.index.nodes_read != expected_nodes
            || unlock.metrics.index.bytes_read != expected_bytes
        {
            return Err("unlock membership-audit correctness failed".into());
        }
        let reopened = vault.read(&session, target)?;
        if reopened.revision != 2 || reopened.payload.as_slice() != UPDATED_PAYLOAD {
            return Err("post-unlock read correctness failed".into());
        }
        drop(reopened);
        vault.lock();
        drop(vault);
        let (logical_nodes, logical_node_bytes, logical_records) = logical_size(&path)?;
        if logical_nodes != expected_nodes
            || logical_node_bytes != expected_bytes
            || logical_records != records as u64
        {
            return Err("stored index differs from the live binary-tree size invariant".into());
        }
        let physical_db_bytes = fs::metadata(&path)?.len();
        // Keep the original four operation/size observations on their unchanged
        // N-record fixture. Reopen outside the additional operation timers.
        let mut vault = Vault::diagnostic_open_current_with_kdf_policy(
            &path,
            limits,
            fogvault::KdfPolicy::baseline(),
        )?;
        let session = vault.unlock(PASSWORD)?;
        let enumeration = enumerate(&mut vault, &session, records, target)?;
        let (deleted, measurement) = measure(|| {
            vault.delete_at(
                &session,
                receipt.head_digest,
                target,
                2,
                request_id(b"deletion", 0),
            )
        })?;
        let deletion = Sample {
            operation: "delete",
            metrics: vault.last_metrics(),
            measurement,
        };
        let remaining = records as u64 - 1;
        let remaining_nodes = if remaining == 0 { 0 } else { 2 * remaining - 1 };
        let remaining_bytes = if remaining == 0 {
            0
        } else {
            139 * remaining - 82
        };
        let metrics = deletion.metrics;
        if deleted.generation != records as u64 + 2
            || !matches!(vault.read(&session, target), Err(Error::NotFound))
            || metrics.index.nodes_read > (2 * fogvault::MAX_PATH_NODES + 1) as u64
            || metrics.index.nodes_written > (fogvault::MAX_PATH_NODES - 2) as u64
            || metrics.record_rows_read != 1
            || metrics.record_bytes_read != (176 + METADATA.len() + PAYLOAD.len()) as u64
            || metrics.record_bytes_written != 0
            || metrics.head_bytes_read != 129
            || metrics.head_bytes_written != 129
            || metrics.index_nodes_deleted == 0
            || metrics.index_nodes_deleted > fogvault::MAX_PATH_NODES as u64
            || metrics.records_scanned != 0
            || metrics.full_audits != 0
        {
            return Err("measured deletion correctness/work invariant failed".into());
        }
        if records > 1 {
            let untouched = vault.read(&session, record_id(0))?;
            if untouched.revision != 1
                || untouched.payload.as_slice() != PAYLOAD
                || untouched.metadata.as_slice() != METADATA
            {
                return Err("deletion changed an unrelated record".into());
            }
        }
        let checked = vault.audit(&session)?;
        if checked.records_checked != remaining || checked.index_nodes_checked != remaining_nodes {
            return Err("post-deletion full audit failed".into());
        }
        vault.lock();
        drop(vault);
        let (after_nodes, after_bytes, after_rows) = logical_size(&path)?;
        if (after_nodes, after_bytes, after_rows) != (remaining_nodes, remaining_bytes, remaining) {
            return Err("deletion did not preserve canonical physical membership/size".into());
        }
        let deletion_json = format!(
            concat!("{{\"sample\":{},\"remaining_records\":{},\"logical_nodes_before\":{},",
                "\"logical_nodes_after\":{},\"logical_node_bytes_after\":{},\"physical_db_bytes_after\":{},",
                "\"target_absence_verified\":true,\"remaining_inventory_audited\":true,\"unrelated_record_checks\":{},\"unrelated_record_unchanged\":true}}"),
            deletion.json(records), remaining, logical_nodes, after_nodes, after_bytes, fs::metadata(&path)?.len(), usize::from(records > 1),
        );
        let record_operations = format!(
            "{{\"delete\":{},\"enumeration\":{}}}",
            deletion_json,
            enumeration.json(records)
        );
        let samples = [read, save, audit, unlock]
            .iter()
            .map(|sample| sample.json(records))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            concat!(
                "{{\"schema\":\"fogvault-index-growth/v1\",\"key_bits\":128,",
                "\"credential_format\":3,\"content_format\":3,\"root_epoch\":0,\"registered_control\":false,",
                "\"records\":{},\"samples\":[{}],\"logical_nodes\":{},",
                "\"logical_node_bytes\":{},\"physical_db_bytes\":{},",
                "\"population_elapsed_ns\":{},\"release_profile\":{},",
                "\"record_operations\":{},",
                "\"environment\":{{\"os\":\"{}\",\"arch\":\"{}\",\"pointer_bits\":{}}}}}"
            ),
            records,
            samples,
            logical_nodes,
            logical_node_bytes,
            physical_db_bytes,
            population_elapsed_ns,
            !cfg!(debug_assertions),
            record_operations,
            env::consts::OS,
            env::consts::ARCH,
            usize::BITS
        );
        Ok(())
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
fn main() -> std::process::ExitCode {
    match benchmark::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("index-growth failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(feature = "native", not(target_arch = "wasm32"))))]
fn main() {
    eprintln!("index-growth requires the native feature and a native target");
    std::process::exit(1);
}
