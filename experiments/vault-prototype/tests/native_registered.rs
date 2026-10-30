//! Ordinary registered native operations, synthetic namespaces and exact beta.3.
//! Local-file/control isolation is an explicit host assumption, not OS qualification.
#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use datafog_core::workspace::{Workspace, MAX_BUNDLE_BYTES};
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, ControlState, KdfPolicy, KdfProfile, KeyProvider,
    ProviderCapabilityKind, ProviderContext, ProviderError, ProviderIdentity, ProviderResult,
};
use fogvault_disposable_prototype::{CommitFault, Error, Limits, NativeHost, Vault};
use rusqlite::Connection;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"SYNTHETIC-registered-native-password";
const REPLACEMENT: &[u8] = b"SYNTHETIC-registered-native-replacement";
const ID: [u8; 16] = [0x91; 16];

fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 64,
        max_records: 16,
    }
}
fn policy() -> KdfPolicy {
    let base = KdfProfile::baseline();
    let upgraded = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
    KdfPolicy::new(vec![base, upgraded]).unwrap()
}
fn host(root: &Path) -> NativeHost {
    NativeHost::create_new(root.join("independent-control")).unwrap()
}
fn header(path: &Path) -> (Vec<u8>, Vec<u8>) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT descriptor,head FROM vault_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}
fn assert_accepted(vault: &Vault, path: &Path, generation: u64) -> ControlState {
    let state = vault.registered_control_state().unwrap();
    let (descriptor, head) = header(path);
    assert!(state.pending().is_none());
    assert_eq!(state.vault_id(), vault.vault_id());
    assert_eq!(state.accepted().generation, generation);
    assert_eq!(
        state.accepted().descriptor_digest,
        fogvault_disposable_prototype::crypto::digest(&descriptor)
    );
    assert_eq!(
        state.accepted().head_digest,
        fogvault_disposable_prototype::crypto::digest(&head)
    );
    state
}
fn content(path: &Path) -> Vec<Vec<u8>> {
    let db = Connection::open(path).unwrap();
    let mut result = Vec::new();
    for sql in [
        "SELECT envelope FROM records ORDER BY id",
        "SELECT bytes FROM index_nodes ORDER BY hash",
    ] {
        result.extend(
            db.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|row| row.unwrap()),
        );
    }
    result
}
fn unknown<T>(value: Result<T, Error>, request: [u8; 16]) {
    assert!(matches!(value, Err(Error::OutcomeUnknown { request_id }) if request_id == request));
}

#[test]
fn registered_native_save_delete_and_reopen_track_exact_anchor() {
    let scratch = tempfile::tempdir().unwrap();
    let host = host(scratch.path());
    let path = scratch.path().join("records.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    assert_accepted(&vault, &path, 0);
    let token = vault.unlock(PASSWORD).unwrap();
    let first = vault
        .save(&token, ID, None, b"meta", b"first", [1; 16])
        .unwrap();
    assert_accepted(&vault, &path, first.generation);
    assert_eq!(vault.last_metrics().records_scanned, 0);
    assert_eq!(vault.last_metrics().full_audits, 0);
    let second = vault
        .save_at(
            &token,
            first.head_digest,
            ID,
            Some(1),
            b"meta",
            b"second",
            [2; 16],
        )
        .unwrap();
    assert_accepted(&vault, &path, second.generation);
    assert_eq!(vault.last_metrics().records_scanned, 0);
    assert_eq!(vault.last_metrics().full_audits, 0);
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"second"
    );
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    assert_eq!(vault.read(&token, ID).unwrap().revision, 2);
    let deleted = vault
        .delete_at(&token, second.head_digest, ID, 2, [3; 16])
        .unwrap();
    assert_accepted(&vault, &path, deleted.generation);
    assert_eq!(vault.last_metrics().records_scanned, 0);
    assert_eq!(vault.last_metrics().full_audits, 0);
    assert!(matches!(vault.read(&token, ID), Err(Error::NotFound)));
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::NotFound)));
    assert_accepted(&vault, &path, deleted.generation);
}

#[test]
fn registered_native_password_and_kdf_changes_preserve_record_bytes() {
    let scratch = tempfile::tempdir().unwrap();
    let host = host(scratch.path());
    let path = scratch.path().join("credentials.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"meta", b"content", [4; 16])
        .unwrap();
    let before = content(&path);
    let changed = vault
        .change_password(&token, PASSWORD, REPLACEMENT, [5; 16])
        .unwrap();
    assert_accepted(&vault, &path, changed.receipt.generation);
    assert_eq!(before, content(&path));
    assert_eq!(vault.last_metrics().records_scanned, 0);
    assert_eq!(vault.last_metrics().record_bytes_written, 0);
    let base = KdfProfile::baseline();
    let target = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
    let upgraded = vault
        .upgrade_kdf(&changed.session, REPLACEMENT, target, [6; 16])
        .unwrap();
    assert_accepted(&vault, &path, upgraded.receipt.generation);
    assert_eq!(before, content(&path));
    assert_eq!(vault.last_metrics().records_scanned, 0);
    assert_eq!(vault.last_metrics().record_bytes_written, 0);
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    assert!(vault.unlock(PASSWORD).is_err());
    let token = vault.unlock(REPLACEMENT).unwrap();
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"content"
    );
}

struct NoDevice;
impl KeyProvider for NoDevice {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::ConvenienceCache
    }
    fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        Err(ProviderError::Unavailable)
    }
    fn unwrap_seed(
        &mut self,
        _: &ProviderContext,
        _: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        Err(ProviderError::Unavailable)
    }
}
fn admission() -> AccessAdmission {
    AccessAdmission {
        allowed_profiles: vec![AccessProfile::Portable],
        providers: vec![],
        max_descriptor_bytes: 276,
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    }
}

#[test]
fn registered_native_access_setup_and_recovery_repair_are_anchored() {
    let scratch = tempfile::tempdir().unwrap();
    let host = host(scratch.path());
    let path = scratch.path().join("recovery.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"meta", b"content", [7; 16])
        .unwrap();
    let before = content(&path);
    let mut provider = NoDevice;
    let (draft, recovery) = vault
        .prepare_access_setup_maintenance(
            &token,
            PASSWORD,
            None,
            PASSWORD,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            admission(),
            [8; 16],
        )
        .unwrap();
    let recovery = recovery.unwrap();
    let receipt = vault
        .commit_access_change(draft, [8; 16], CommitFault::None)
        .unwrap();
    assert_accepted(&vault, &path, receipt.receipt.generation);
    assert_eq!(before, content(&path));
    vault.lock();
    drop(vault);
    let mut vault = host
        .open_with_access(&path, limits(), policy(), admission())
        .unwrap();
    vault.recover_access(&recovery).unwrap();
    let (repair, _) = vault
        .prepare_recovery_maintenance(
            &recovery,
            REPLACEMENT,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            [9; 16],
        )
        .unwrap();
    let receipt = vault
        .commit_access_change(repair, [9; 16], CommitFault::None)
        .unwrap();
    assert_accepted(&vault, &path, receipt.receipt.generation);
    assert_eq!(before, content(&path));
    assert_eq!(
        vault.read(&receipt.session, ID).unwrap().payload.as_slice(),
        b"content"
    );
    vault.lock();
    drop(vault);
    let mut vault = host
        .open_with_access(&path, limits(), policy(), admission())
        .unwrap();
    let token = vault
        .unlock_access(AccessPath::Password(REPLACEMENT), &mut provider)
        .unwrap();
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"content"
    );
}

#[test]
fn registered_native_beta3_bundle_survives_lock_reopen() {
    let scratch = tempfile::tempdir().unwrap();
    let host = host(scratch.path());
    let path = scratch.path().join("beta3.sqlite");
    let namespace = [0xa1; 16];
    let mut workspace = Workspace::create(namespace, [0xa2; 16]).unwrap();
    let head = workspace.head().unwrap();
    let bundle = Zeroizing::new(workspace.export_bundle().unwrap());
    let mut metadata = namespace.to_vec();
    metadata.extend_from_slice(&head.revision.to_be_bytes());
    metadata.extend_from_slice(&head.commit_id);
    let limits = Limits {
        max_payload_bytes: MAX_BUNDLE_BYTES,
        max_metadata_bytes: metadata.len(),
        max_records: 1,
    };
    let mut vault = host.create(&path, PASSWORD, limits, policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let receipt = vault
        .save(&token, ID, None, &metadata, &bundle, [0xa3; 16])
        .unwrap();
    assert_accepted(&vault, &path, receipt.generation);
    workspace.close();
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits, policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let record = vault.read(&token, ID).unwrap();
    assert_eq!(record.metadata.as_slice(), metadata);
    assert_eq!(record.payload.as_slice(), bundle.as_slice());
    let mut restored = Workspace::open_bundle(&record.payload).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), head);
    restored.close();
    vault.lock();
    assert!(vault.read(&token, ID).is_err());
}

#[test]
fn registered_native_unknown_outcomes_retain_exact_target_and_recover() {
    for fault in [
        CommitFault::BeforeCommit,
        CommitFault::RolledBackLostReply,
        CommitFault::AfterCommit,
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let host = host(scratch.path());
        let path = scratch.path().join("unknown.sqlite");
        let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        let request = [0xb1; 16];
        // Exercise the exact admitted envelope bound through durable target
        // retention, restart parsing and republication, not only a small row.
        let payload = vec![0xb5; limits().max_payload_bytes];
        let metadata = vec![0xb6; limits().max_metadata_bytes];
        unknown(
            vault.save_with_fault(&token, ID, None, &metadata, &payload, request, fault),
            request,
        );
        let submitted = vault.registered_control_state().unwrap();
        let pending = submitted.pending().unwrap();
        assert_eq!(pending.request_id, request);
        assert!(pending.submission().is_some());
        unknown(vault.abandon_registered_preparation(request), request);
        assert_eq!(vault.registered_control_state().unwrap(), submitted);
        unknown(
            vault.save(&token, [0xb2; 16], None, b"", b"no blind retry", [0xb3; 16]),
            request,
        );
        drop(vault); // Erases process-local Engine pending state; durable intent must survive.
        let mut vault = host.open(&path, limits(), policy()).unwrap();
        assert!(!vault.is_unlocked());
        unknown(vault.unlock(PASSWORD), request);
        assert!(vault.reconcile_registered([0xb4; 16]).is_err());
        let receipt = vault.reconcile_registered(request).unwrap();
        assert_eq!(receipt.request_id, request);
        assert_eq!(
            receipt.head_digest,
            pending.submission().unwrap().head_digest
        );
        assert!(!vault.is_unlocked());
        assert_accepted(&vault, &path, receipt.generation);
        let token = vault.unlock(PASSWORD).unwrap();
        assert_eq!(vault.read(&token, ID).unwrap().payload.as_slice(), payload);
        assert_eq!(
            vault.read(&token, ID).unwrap().metadata.as_slice(),
            metadata
        );
        assert_eq!(vault.read(&token, ID).unwrap().revision, 1);
        assert!(matches!(
            vault.read(&token, [0xb2; 16]),
            Err(Error::NotFound)
        ));
    }
}

#[test]
fn registered_native_credential_unknown_restarts_use_exact_admitted_target() {
    for operation in ["password", "kdf", "setup", "recovery"] {
        let scratch = tempfile::tempdir().unwrap();
        let host = host(scratch.path());
        let path = scratch.path().join("credential-restart.sqlite");
        let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        vault
            .save(&token, ID, None, b"meta", b"unchanged record", [0xe1; 16])
            .unwrap();
        let before = content(&path);
        let request = [0xe2; 16];
        let mut provider = NoDevice;
        let password_after = match operation {
            "password" => {
                unknown(
                    vault.change_password_with_fault(
                        &token,
                        PASSWORD,
                        REPLACEMENT,
                        request,
                        CommitFault::AfterCommit,
                    ),
                    request,
                );
                REPLACEMENT
            }
            "kdf" => {
                let base = KdfProfile::baseline();
                let target = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
                unknown(
                    vault.upgrade_kdf_with_fault(
                        &token,
                        PASSWORD,
                        target,
                        request,
                        CommitFault::RolledBackLostReply,
                    ),
                    request,
                );
                PASSWORD
            }
            "setup" => {
                let (draft, _) = vault
                    .prepare_access_setup_maintenance(
                        &token,
                        PASSWORD,
                        None,
                        REPLACEMENT,
                        AccessProfile::Portable,
                        &[],
                        true,
                        &mut provider,
                        admission(),
                        request,
                    )
                    .unwrap();
                unknown(
                    vault.commit_access_change(draft, request, CommitFault::AfterCommit),
                    request,
                );
                REPLACEMENT
            }
            "recovery" => {
                let (draft, recovery) = vault
                    .prepare_access_setup_maintenance(
                        &token,
                        PASSWORD,
                        None,
                        PASSWORD,
                        AccessProfile::Portable,
                        &[],
                        true,
                        &mut provider,
                        admission(),
                        [0xe3; 16],
                    )
                    .unwrap();
                vault
                    .commit_access_change(draft, [0xe3; 16], CommitFault::None)
                    .unwrap();
                let recovery = recovery.unwrap();
                vault.lock();
                vault.recover_access(&recovery).unwrap();
                let (draft, _) = vault
                    .prepare_recovery_maintenance(
                        &recovery,
                        REPLACEMENT,
                        AccessProfile::Portable,
                        &[],
                        true,
                        &mut provider,
                        request,
                    )
                    .unwrap();
                unknown(
                    vault.commit_access_change(draft, request, CommitFault::RolledBackLostReply),
                    request,
                );
                REPLACEMENT
            }
            _ => unreachable!(),
        };
        let pending = vault.registered_control_state().unwrap();
        let target = pending.pending().unwrap().submission().unwrap();
        assert_eq!(pending.pending().unwrap().request_id, request);
        assert_eq!(before, content(&path));
        drop(vault);
        if operation == "kdf" {
            // Source is still baseline after the deliberate lost rollback
            // reply. Its retained target must not bypass a new host's allowlist.
            let source_bytes = std::fs::read(&path).unwrap();
            if let Ok(mut unadmitted) = host.open(&path, limits(), KdfPolicy::baseline()) {
                assert!(unadmitted.reconcile_registered(request).is_err());
                assert_eq!(unadmitted.registered_control_state().unwrap(), pending);
            }
            assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
        }
        let access = matches!(operation, "setup" | "recovery");
        let mut vault = if access {
            host.open_with_access(&path, limits(), policy(), admission())
                .unwrap()
        } else {
            host.open(&path, limits(), policy()).unwrap()
        };
        let receipt = vault.reconcile_registered(request).unwrap();
        assert_eq!(receipt.head_digest, target.head_digest);
        assert!(!vault.is_unlocked());
        assert_eq!(before, content(&path));
        assert_accepted(&vault, &path, target.generation);
        let token = if access {
            vault
                .unlock_access(AccessPath::Password(password_after), &mut provider)
                .unwrap()
        } else {
            vault.unlock(password_after).unwrap()
        };
        assert_eq!(
            vault.read(&token, ID).unwrap().payload.as_slice(),
            b"unchanged record"
        );
    }
}

#[test]
fn registered_native_point_update_stays_path_local_at_existing_growth_populations() {
    // These are the existing conformance/vault-contract.json index_growth
    // populations. They are experiment inputs, not product capacities.
    for records in [1usize, 16, 256, 4096] {
        let scratch = tempfile::tempdir().unwrap();
        let host = host(scratch.path());
        let path = scratch.path().join("registered-growth.sqlite");
        let limits = Limits {
            max_payload_bytes: 8,
            max_metadata_bytes: 0,
            max_records: records,
        };
        let mut vault = Vault::diagnostic_create_current(&path, PASSWORD, limits).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        let id = |n: usize| (n as u128).to_be_bytes();
        for n in 0..records {
            vault
                .save(
                    &token,
                    id(n),
                    None,
                    b"",
                    &[0x11; 8],
                    (n as u128 + 1).to_be_bytes(),
                )
                .unwrap();
        }
        // Enrollment is explicitly audited bulk work, outside the measured
        // ordinary operation. The subsequent update uses the same Vault API.
        host.register_existing(&mut vault, &token).unwrap();
        let target = id(records / 2);
        let untouched = |path: &Path| {
            let db = Connection::open(path).unwrap();
            let values = db
                .prepare("SELECT id,revision,envelope FROM records WHERE id != ?1 ORDER BY id")
                .unwrap()
                .query_map([target.as_slice()], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            values
        };
        let before = untouched(&path);
        let anchor = vault.registered_control_state().unwrap().accepted();
        let started = std::time::Instant::now();
        let receipt = vault
            .save_at(
                &token,
                anchor.head_digest,
                target,
                Some(1),
                b"",
                &[0x22; 8],
                [0xf1; 16],
            )
            .unwrap();
        let elapsed = started.elapsed();
        let metrics = vault.last_metrics();
        assert_eq!(metrics.records_scanned, 0);
        assert_eq!(metrics.full_audits, 0);
        // Preparation, exact source recheck, and exact committed-row readback
        // may each read the one changed row; population never appears here.
        assert!(metrics.record_rows_read <= 3);
        assert!(metrics.index.nodes_read <= 2 * fogvault::MAX_PATH_NODES as u64);
        assert!(metrics.index.nodes_written <= fogvault::MAX_PATH_NODES as u64 + 1);
        assert!(metrics.index_nodes_deleted <= fogvault::MAX_PATH_NODES as u64);
        assert_eq!(before, untouched(&path));
        assert_accepted(&vault, &path, records as u64 + 1);
        assert_eq!(
            vault.read(&token, target).unwrap().payload.as_slice(),
            &[0x22; 8]
        );
        println!("REGISTERED_GROWTH records={records} elapsed_ns={} record_rows_read={} nodes_read={} nodes_written={} nodes_deleted={} head_bytes_read={} head_bytes_written={}",elapsed.as_nanos(),metrics.record_rows_read,metrics.index.nodes_read,metrics.index.nodes_written,metrics.index_nodes_deleted,metrics.head_bytes_read,metrics.head_bytes_written);
        assert_eq!(receipt.generation, records as u64 + 1);
    }
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(namespace: &Path, path: &Path) -> Process {
    let mut process = Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "registered_native_process_fixture",
                "--nocapture",
            ])
            .env("FOGVAULT_REGISTERED_CHILD_NAMESPACE", namespace)
            .env("FOGVAULT_REGISTERED_CHILD_VAULT", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(process.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "registered child exited before readiness"
        );
        if line.trim_end().ends_with("REGISTERED_WRITER_READY") {
            break;
        }
    }
    process.0.stdout = Some(reader.into_inner());
    process
}

#[test]
fn registered_native_process_fixture() {
    let Some(namespace) = std::env::var_os("FOGVAULT_REGISTERED_CHILD_NAMESPACE") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("FOGVAULT_REGISTERED_CHILD_VAULT").unwrap());
    let host = NativeHost::open_required(namespace).unwrap();
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let expected = vault
        .registered_control_state()
        .unwrap()
        .accepted()
        .head_digest;
    println!("REGISTERED_WRITER_READY");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0; 1]).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::Conflict)));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(matches!(
        vault.save_at(
            &token,
            expected,
            ID,
            Some(1),
            b"",
            b"stale child",
            [0xc4; 16]
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let metrics = vault.last_metrics();
    assert_eq!(metrics.record_bytes_written, 0);
    assert_eq!(metrics.index.nodes_written, 0);
    assert_eq!(metrics.head_bytes_written, 0);
}

#[test]
fn registered_native_real_process_stale_save_at_rejects_replayed_source_before_writes() {
    let scratch = tempfile::tempdir().unwrap();
    let namespace = scratch.path().join("independent-control");
    let host = NativeHost::create_new(&namespace).unwrap();
    let path = scratch.path().join("replayed.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"", b"source A", [0xc1; 16])
        .unwrap();
    let source_a = std::fs::read(&path).unwrap();
    let mut stale = child(&namespace, &path);
    vault
        .save(&token, ID, Some(1), b"", b"accepted B", [0xc2; 16])
        .unwrap();
    vault
        .save(&token, ID, Some(2), b"", b"accepted C", [0xc3; 16])
        .unwrap();
    let anchor_c = assert_accepted(&vault, &path, 3);
    let accepted_c = std::fs::read(&path).unwrap();
    drop(vault);
    std::fs::write(&path, &source_a).unwrap(); // The explicitly hostile vault-file actor.
    stale.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert!(stale.0.wait().unwrap().success());
    assert_eq!(std::fs::read(&path).unwrap(), source_a);
    // This host boundary refuses a completed-anchor replay before returning
    // even a locked candidate; Submitted source/target opening is separate.
    assert!(host.open(&path, limits(), policy()).is_err());
    std::fs::write(&path, &accepted_c).unwrap();
    let mut reopened = host.open(&path, limits(), policy()).unwrap();
    assert_eq!(reopened.registered_control_state().unwrap(), anchor_c);
    let token = reopened.unlock(PASSWORD).unwrap();
    assert_eq!(
        reopened.read(&token, ID).unwrap().payload.as_slice(),
        b"accepted C"
    );
}

#[test]
fn registered_native_required_registration_refuses_diagnostic_and_missing_control() {
    let scratch = tempfile::tempdir().unwrap();
    let namespace = scratch.path().join("independent-control");
    let host = NativeHost::create_new(&namespace).unwrap();
    let path = scratch.path().join("registered.sqlite");
    let vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    let original = vault.registered_control_state().unwrap();
    let before = std::fs::read(&path).unwrap();
    drop(vault);
    assert!(host
        .open_unanchored_diagnostic(&path, limits(), policy())
        .is_err());
    let alias = scratch.path().join("vault-copy.sqlite");
    std::fs::copy(&path, &alias).unwrap();
    assert!(host
        .open_unanchored_diagnostic(&alias, limits(), policy())
        .is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(host);
    let moved = scratch.path().join("lost-independent-control");
    std::fs::rename(&namespace, &moved).unwrap();
    assert!(NativeHost::open_required(&namespace).is_err());
    assert!(!namespace.exists());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::rename(&moved, &namespace).unwrap();
    let host = NativeHost::open_required(&namespace).unwrap();
    let vault = host.open(&path, limits(), policy()).unwrap();
    assert_eq!(vault.registered_control_state().unwrap(), original);
}
