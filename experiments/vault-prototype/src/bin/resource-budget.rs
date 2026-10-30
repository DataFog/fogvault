//! Disposable native resource experiment; measured workloads are not production budgets.
//! The counting allocator is confined to this executable, excluding SQLite C allocations.

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod benchmark {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        env, fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        },
        thread,
        time::Instant,
    };

    use fogvault_disposable_prototype::{crypto, Error, Limits, OperationMetrics, Result, Vault};
    use rusqlite::{Connection, OpenFlags};

    const PASSWORD: &[u8] = b"SYNTHETIC resource fixture: never real credentials";
    const SALT: [u8; 16] = [b'S'; 16];
    const METADATA: [u8; 32] = [b'M'; 32];
    const RECORD_ID: [u8; 16] = [b'R'; 16];
    // Mirrors the reviewed exact consumer constant. The Python runner verifies its source.
    const CONSUMER_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    struct CountingAllocator;

    fn allocated(size: usize) {
        let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    // SAFETY: original pointers/layouts delegate unchanged to System; only successful
    // requested sizes are counted. Counters never inspect or retain allocation contents.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the GlobalAlloc caller supplies a valid allocation layout.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the GlobalAlloc caller supplies a valid allocation layout.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: the caller supplies the live allocation and original layout.
            unsafe { System.dealloc(pointer, layout) };
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: the caller supplies the live allocation/layout and valid new size.
            let replacement = unsafe { System.realloc(pointer, layout, size) };
            if !replacement.is_null() {
                if size >= layout.size() {
                    allocated(size - layout.size());
                } else {
                    LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
                }
            }
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
        ending_allocated_bytes: usize,
    }

    fn measure<T>(operation: impl FnOnce() -> Result<T>) -> Result<(T, Measurement)> {
        // Only the explicit concurrency workload starts Rust threads; every join completes
        // before the measurement returns. No measurement resets an active worker's peak.
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let started = Instant::now();
        let value = operation()?;
        let elapsed_ns = started.elapsed().as_nanos();
        let peak = PEAK.load(Ordering::Relaxed);
        Ok((
            value,
            Measurement {
                elapsed_ns,
                baseline_allocated_bytes: baseline,
                peak_allocated_bytes: peak.saturating_sub(baseline),
                peak_live_allocated_bytes: peak,
                ending_allocated_bytes: LIVE.load(Ordering::Relaxed),
            },
        ))
    }

    struct Sample {
        operation: &'static str,
        repetition: usize,
        concurrency: usize,
        metrics: OperationMetrics,
        measurement: Measurement,
    }

    impl Sample {
        fn json(&self, payload_bytes: usize, metadata_bytes: usize) -> String {
            let m = self.metrics;
            let measured = self.measurement;
            format!(
                concat!(
                    "{{\"operation\":\"{}\",\"repetition\":{},\"concurrency\":{},",
                    "\"payload_bytes\":{},\"input_payload_bytes\":{},\"metadata_bytes\":{},\"correctness\":true,",
                    "\"elapsed_ns\":{},\"baseline_allocated_bytes\":{},",
                    "\"peak_allocated_bytes\":{},\"peak_live_allocated_bytes\":{},",
                    "\"ending_allocated_bytes\":{},\"metrics\":{{",
                    "\"nodes_read\":{},\"nodes_written\":{},\"node_bytes_read\":{},",
                    "\"node_bytes_written\":{},\"max_path_depth\":{},",
                    "\"head_bytes\":{},\"head_bytes_written\":{},",
                    "\"record_rows_read\":{},\"record_bytes_read\":{},",
                    "\"record_bytes_written\":{},\"index_nodes_deleted\":{},",
                    "\"full_audits\":{},\"records_scanned\":{}}}}}"
                ),
                self.operation,
                self.repetition,
                self.concurrency,
                payload_bytes,
                if self.operation == "payload_rejected" { payload_bytes + 1 } else { payload_bytes },
                metadata_bytes,
                measured.elapsed_ns,
                measured.baseline_allocated_bytes,
                measured.peak_allocated_bytes,
                measured.peak_live_allocated_bytes,
                measured.ending_allocated_bytes,
                m.index.nodes_read,
                m.index.nodes_written,
                m.index.bytes_read,
                m.index.bytes_written,
                m.index.peak_path_nodes.saturating_sub(1),
                m.head_bytes_read,
                m.head_bytes_written,
                m.record_rows_read,
                m.record_bytes_read,
                m.record_bytes_written,
                m.index_nodes_deleted,
                m.full_audits,
                m.records_scanned,
            )
        }
    }

    fn push(
        samples: &mut Vec<Sample>,
        operation: &'static str,
        repetition: usize,
        concurrency: usize,
        metrics: OperationMetrics,
        measurement: Measurement,
    ) {
        samples.push(Sample {
            operation,
            repetition,
            concurrency,
            metrics,
            measurement,
        });
    }

    fn key() -> Result<zeroize::Zeroizing<[u8; 32]>> {
        Ok(crypto::password_key(
            PASSWORD,
            &SALT,
            crypto::MEMORY_KIB,
            crypto::PASSES,
            crypto::LANES,
        )?)
    }

    fn kdf(repetitions: usize) -> Result<Vec<Sample>> {
        let mut samples = Vec::with_capacity(repetitions * 3);
        let expected = key()?;
        for repetition in 0..repetitions {
            let (derived, measured) = measure(key)?;
            if derived.as_ref() != expected.as_ref() {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "kdf",
                repetition,
                1,
                OperationMetrics::default(),
                measured,
            );
            drop(derived);

            let (keys_match, measured) = measure(|| {
                // Two is the smallest workload demonstrating more than one in-flight KDF.
                // It measures concurrent memory; it does not select a production quota.
                let barrier = Arc::new(Barrier::new(2));
                let worker_barrier = Arc::clone(&barrier);
                let worker = thread::spawn(move || {
                    worker_barrier.wait();
                    key()
                });
                barrier.wait();
                let first = key()?;
                let second = worker.join().map_err(|_| Error::Storage)??;
                Ok(first.as_ref() == second.as_ref() && first.as_ref() == expected.as_ref())
            })?;
            if !keys_match {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "kdf_concurrent",
                repetition,
                2,
                OperationMetrics::default(),
                measured,
            );

            let (rejected, measured) = measure(|| {
                Ok(matches!(
                    crypto::password_key(
                        PASSWORD,
                        &SALT,
                        crypto::MEMORY_KIB + 1,
                        crypto::PASSES,
                        crypto::LANES
                    ),
                    Err(crypto::CryptoError::RejectedKdfParameters)
                ))
            })?;
            if !rejected || measured.peak_allocated_bytes != 0 {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "kdf_rejected",
                repetition,
                1,
                OperationMetrics::default(),
                measured,
            );
        }
        Ok(samples)
    }

    fn payload(
        payload_bytes: usize,
        repetitions: usize,
        scratch: PathBuf,
    ) -> Result<(Vec<Sample>, u64, u64)> {
        let payload = vec![b'P'; payload_bytes];
        let mut samples = Vec::with_capacity(repetitions * 8);
        let limits = Limits {
            max_payload_bytes: payload_bytes,
            max_metadata_bytes: METADATA.len(),
            max_records: 1,
        };
        let envelope_bytes = limits.current_envelope_bytes()? as u64;
        let mut physical_db_bytes = 0;
        for repetition in 0..repetitions {
            let path = scratch.join(format!("PROTOTYPE-WIPE-ME-{repetition}.sqlite"));
            let (mut vault, measured) =
                measure(|| Vault::diagnostic_create_current(&path, PASSWORD, limits))?;
            if vault.is_unlocked() {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "create",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );

            let (session, measured) = measure(|| vault.unlock(PASSWORD))?;
            if vault.last_metrics().records_scanned != 0 {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "unlock_empty",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );

            let (receipt, measured) =
                measure(|| vault.save(&session, RECORD_ID, None, &METADATA, &payload, [b'I'; 16]))?;
            let saved_metrics = vault.last_metrics();
            if receipt.generation != 1
                || saved_metrics.record_bytes_written != envelope_bytes
                || saved_metrics.records_scanned != 0
                || saved_metrics.head_bytes_read != 129
                || saved_metrics.head_bytes_written != 129
            {
                return Err(Error::Integrity);
            }
            push(&mut samples, "save", repetition, 1, saved_metrics, measured);

            let (record, measured) = measure(|| vault.read(&session, RECORD_ID))?;
            if record.revision != 1
                || record.metadata.as_slice() != METADATA
                || record.payload.as_slice() != payload
            {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "read",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );
            drop(record);

            let (receipt, measured) = measure(|| {
                vault.save(
                    &session,
                    RECORD_ID,
                    Some(1),
                    &METADATA,
                    &payload,
                    [b'U'; 16],
                )
            })?;
            if receipt.generation != 2
                || vault.last_metrics().record_bytes_written != envelope_bytes
            {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "update",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );

            let (report, measured) = measure(|| vault.audit(&session))?;
            if report.records_checked != 1
                || report.index_nodes_checked != 1
                || vault.last_metrics().record_bytes_read != envelope_bytes
            {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "audit",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );

            vault.lock();
            let (session, measured) = measure(|| vault.unlock(PASSWORD))?;
            if vault.last_metrics().records_scanned != 1
                || vault.last_metrics().record_bytes_read != 0
            {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "unlock",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );
            let recovered = vault.read(&session, RECORD_ID)?;
            if recovered.revision != 2 || recovered.payload.as_slice() != payload {
                return Err(Error::Integrity);
            }
            drop(recovered);

            // Caller-owned oversized bytes are allocated before measurement: this
            // observes admission work, not the host's creation of rejected input.
            let over_limit = vec![b'X'; payload_bytes + 1];
            let (rejected, measured) = measure(|| {
                Ok(matches!(
                    vault.save(
                        &session,
                        RECORD_ID,
                        Some(2),
                        &METADATA,
                        &over_limit,
                        [b'X'; 16]
                    ),
                    Err(Error::ResourceLimit)
                ))
            })?;
            if !rejected || measured.peak_allocated_bytes != 0 || vault.generation() != Some(2) {
                return Err(Error::Integrity);
            }
            push(
                &mut samples,
                "payload_rejected",
                repetition,
                1,
                vault.last_metrics(),
                measured,
            );
            drop(over_limit);
            vault.lock();
            drop(vault);
            let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|_| Error::Storage)?;
            let descriptor: Vec<u8> = connection
                .query_row("SELECT descriptor FROM vault_state WHERE id=1", [], |row| {
                    row.get(0)
                })
                .map_err(|_| Error::Storage)?;
            if descriptor.get(..8) != Some(b"FGVP0003".as_slice())
                || descriptor.get(12..14) != Some(3u16.to_be_bytes().as_slice())
                || descriptor.get(30..38) != Some(0u64.to_be_bytes().as_slice())
            {
                return Err(Error::Integrity);
            }
            let stored_length: i64 = connection
                .query_row("SELECT length(envelope) FROM records", [], |row| row.get(0))
                .map_err(|_| Error::Storage)?;
            if u64::try_from(stored_length).map_err(|_| Error::Integrity)? != envelope_bytes {
                return Err(Error::Integrity);
            }
            drop(connection);
            physical_db_bytes =
                physical_db_bytes.max(fs::metadata(&path).map_err(|_| Error::Storage)?.len());
        }
        Ok((samples, envelope_bytes, physical_db_bytes))
    }

    pub fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut arguments = env::args_os().skip(1);
        let kind = arguments.next().ok_or(
            "usage: resource-budget kdf REPETITIONS | payload BYTES REPETITIONS SCRATCH_DIR",
        )?;
        let kind = kind.to_str().ok_or("workload must be UTF-8")?;
        let (payload_bytes, repetitions, samples, envelope_bytes, db_bytes) = match kind {
            "kdf" => {
                let repetitions: usize = arguments
                    .next()
                    .ok_or("repetitions required")?
                    .to_str()
                    .ok_or("repetitions must be decimal")?
                    .parse()?;
                if repetitions == 0 || arguments.next().is_some() {
                    return Err("positive repetition count required".into());
                }
                let samples = kdf(repetitions)?;
                (0, repetitions, samples, 0, 0)
            }
            "payload" => {
                let bytes: usize = arguments
                    .next()
                    .ok_or("payload bytes required")?
                    .to_str()
                    .ok_or("payload bytes must be decimal")?
                    .parse()?;
                let repetitions: usize = arguments
                    .next()
                    .ok_or("repetitions required")?
                    .to_str()
                    .ok_or("repetitions must be decimal")?
                    .parse()?;
                let scratch = PathBuf::from(arguments.next().ok_or("scratch directory required")?);
                if repetitions == 0 || bytes > CONSUMER_BUNDLE_BYTES || arguments.next().is_some() {
                    return Err("payload must fit the exact consumer bundle ceiling and repetitions must be positive".into());
                }
                let (samples, envelope, db_bytes) = payload(bytes, repetitions, scratch)?;
                (bytes, repetitions, samples, envelope, db_bytes)
            }
            _ => return Err("unknown resource workload".into()),
        };
        let encoded = samples
            .iter()
            .map(|sample| {
                sample.json(
                    payload_bytes,
                    if kind == "payload" { METADATA.len() } else { 0 },
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            concat!(
                "{{\"schema\":\"fogvault-resource-budgets/v1\",\"kind\":\"{}\",",
                "\"content_format\":{},\"root_epoch\":{},\"registered_control\":false,",
                "\"payload_bytes\":{},\"metadata_bytes\":{},\"records\":{},\"repetitions\":{},",
                "\"envelope_bytes\":{},\"physical_db_bytes\":{},\"samples\":[{}],",
                "\"release_profile\":{},\"kdf\":{{\"memory_kib\":{},\"passes\":{},\"lanes\":{}}}}}"
            ),
            kind,
            if kind == "payload" { "3" } else { "null" },
            if kind == "payload" { "0" } else { "null" },
            payload_bytes,
            if kind == "payload" { METADATA.len() } else { 0 },
            usize::from(kind == "payload"),
            repetitions,
            envelope_bytes,
            db_bytes,
            encoded,
            !cfg!(debug_assertions),
            crypto::MEMORY_KIB,
            crypto::PASSES,
            crypto::LANES
        );
        Ok(())
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
fn main() -> std::process::ExitCode {
    match benchmark::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("resource-budget failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(feature = "native", not(target_arch = "wasm32"))))]
fn main() {
    eprintln!("resource-budget requires the native feature and a native target");
    std::process::exit(1);
}
