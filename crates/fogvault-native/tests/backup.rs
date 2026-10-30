#![cfg(feature = "backup")]
use fogvault_backup::{Identity, Policy};
use fogvault_native::{Error, Host, KdfPolicy, Limits, RestoreOptions};
use std::io::Cursor;
use tempfile::tempdir;

const PASSWORD: &[u8] = b"SYNTHETIC-native-backup-password";
const NEW_PASSWORD: &[u8] = b"SYNTHETIC-new-restored-password";
fn limits() -> Limits {
    Limits {
        max_records: 8,
        max_metadata_bytes: 128,
        max_payload_bytes: 4096,
    }
}
fn policy() -> Policy {
    Policy {
        header_bytes: 4096,
        stanzas: 8,
        ciphertext_bytes: 64 * 1024,
        total_plaintext_bytes: 32 * 1024,
        records: 8,
        schema_bytes: 0,
        metadata_bytes: 128,
        payload_bytes: 4096,
    }
}
fn options(request: [u8; 16]) -> RestoreOptions {
    RestoreOptions {
        limits: limits(),
        kdf: KdfPolicy::baseline(),
        backup: policy(),
        request_id: request,
    }
}

#[test]
fn native_backup_restore_is_fresh_atomic_restartable_and_preserves_records() {
    let temp = tempdir().unwrap();
    let control = temp.path().join("control");
    let host = Host::create_new(&control).unwrap();
    let source_path = temp.path().join("source.sqlite");
    let target = temp.path().join("restored.sqlite");
    let mut source = host
        .create(&source_path, PASSWORD, limits(), KdfPolicy::baseline())
        .unwrap();
    let session = source.unlock(PASSWORD).unwrap();
    source
        .save(
            &session,
            [1; 16],
            None,
            b"opaque-metadata",
            b"first-revision",
            [1; 16],
        )
        .unwrap();
    source
        .save(
            &session,
            [1; 16],
            Some(1),
            b"opaque-metadata",
            b"current-payload",
            [2; 16],
        )
        .unwrap();
    source
        .save(
            &session,
            [2; 16],
            None,
            b"second",
            b"second-payload",
            [3; 16],
        )
        .unwrap();
    let key = Identity::generate();
    let mut cipher = Vec::new();
    let (snapshot, receipt) = source
        .export_backup(&session, &key.to_public(), &mut cipher, policy())
        .unwrap();
    assert_eq!(snapshot.records(), 2);
    assert_eq!(snapshot.vault_id(), source.vault_id());
    let ticket = host
        .prepare_password_restore(
            &target,
            Cursor::new(&cipher),
            &key,
            snapshot.clone(),
            receipt.ciphertext_sha256,
            NEW_PASSWORD,
            options([8; 16]),
        )
        .unwrap();
    assert!(!target.exists());
    assert_ne!(ticket.vault_id(), source.vault_id());
    assert!(ticket.origin_verified());
    assert_eq!(ticket.source(), &snapshot);
    drop(host);
    let restarted = Host::open(&control).unwrap();
    let (mut restored, finished) = restarted
        .publish_password_restore(
            &target,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline(),
        )
        .unwrap();
    assert_eq!(finished.vault_id(), ticket.vault_id());
    assert!(!restored.is_unlocked());
    let session = restored.unlock(NEW_PASSWORD).unwrap();
    let first = restored.read(&session, [1; 16]).unwrap();
    assert_eq!(&*first.payload, b"current-payload");
    assert_eq!(&*first.metadata, b"opaque-metadata");
    assert_eq!(first.revision, 1);
    assert_eq!(
        &*restored.read(&session, [2; 16]).unwrap().payload,
        b"second-payload"
    );
    drop(restored);
    let (mut replay, _) = restarted
        .publish_password_restore(
            &target,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline(),
        )
        .unwrap();
    let session = replay.unlock(NEW_PASSWORD).unwrap();
    replay
        .save(
            &session,
            [1; 16],
            Some(1),
            b"changed",
            b"new-target-write",
            [9; 16],
        )
        .unwrap();
    drop(replay);
    assert!(matches!(
        restarted.publish_password_restore(
            &target,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline()
        ),
        Err(Error::Conflict)
    ));
}

#[test]
fn native_restore_rejects_wrong_origin_and_existing_targets_without_modification() {
    let temp = tempdir().unwrap();
    let host = Host::create_new(temp.path().join("control")).unwrap();
    let mut source = host
        .create(
            temp.path().join("source.sqlite"),
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
        )
        .unwrap();
    let session = source.unlock(PASSWORD).unwrap();
    source
        .save(&session, [1; 16], None, b"m", b"payload", [1; 16])
        .unwrap();
    let key = Identity::generate();
    let mut cipher = Vec::new();
    let (snapshot, receipt) = source
        .export_backup(&session, &key.to_public(), &mut cipher, policy())
        .unwrap();
    let destination = temp.path().join("restore.sqlite");
    assert!(matches!(
        host.prepare_password_restore(
            &destination,
            Cursor::new(&cipher),
            &key,
            snapshot.clone(),
            [0; 32],
            NEW_PASSWORD,
            options([2; 16])
        ),
        Err(Error::Integrity)
    ));
    assert!(!destination.exists());
    std::fs::write(&destination, b"occupied-sentinel").unwrap();
    assert!(matches!(
        host.prepare_password_restore(
            &destination,
            Cursor::new(&cipher),
            &key,
            snapshot,
            receipt.ciphertext_sha256,
            NEW_PASSWORD,
            options([3; 16])
        ),
        Err(Error::Exists)
    ));
    assert_eq!(std::fs::read(destination).unwrap(), b"occupied-sentinel");
    assert_eq!(
        &*source.read(&session, [1; 16]).unwrap().payload,
        b"payload"
    );
}

#[test]
fn native_restore_cancellation_is_pre_submission_only_and_missing_control_is_not_recreated() {
    let temp = tempdir().unwrap();
    let control = temp.path().join("control");
    let host = Host::create_new(&control).unwrap();
    let mut source = host
        .create(
            temp.path().join("source.sqlite"),
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
        )
        .unwrap();
    let session = source.unlock(PASSWORD).unwrap();
    let key = Identity::generate();
    let mut cipher = Vec::new();
    let (snapshot, receipt) = source
        .export_backup(&session, &key.to_public(), &mut cipher, policy())
        .unwrap();
    let cancelled = temp.path().join("cancelled.sqlite");
    let ticket = host
        .prepare_password_restore(
            &cancelled,
            Cursor::new(&cipher),
            &key,
            snapshot.clone(),
            receipt.ciphertext_sha256,
            NEW_PASSWORD,
            options([4; 16]),
        )
        .unwrap();
    host.discard_prepared_restore(&cancelled, ticket.request_id())
        .unwrap();
    assert!(!cancelled.exists());
    assert!(matches!(
        host.publish_password_restore(
            &cancelled,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline()
        ),
        Err(Error::NotFound)
    ));
    let target = temp.path().join("restore.sqlite");
    let ticket = host
        .prepare_password_restore(
            &target,
            Cursor::new(&cipher),
            &key,
            snapshot,
            receipt.ciphertext_sha256,
            NEW_PASSWORD,
            options([5; 16]),
        )
        .unwrap();
    let (vault, _) = host
        .publish_password_restore(
            &target,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline(),
        )
        .unwrap();
    drop(vault);
    assert!(matches!(
        host.discard_prepared_restore(&target, ticket.request_id()),
        Err(Error::OutcomeUnknown { .. })
    ));
    let registry = rusqlite::Connection::open(control.join("registry.sqlite")).unwrap();
    let registration: Vec<u8> = registry
        .query_row(
            "SELECT registration FROM registrations WHERE vault=?1",
            [ticket.vault_id().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    drop(registry);
    let name = registration
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let control_file = control.join(format!("{name}.control.sqlite"));
    assert!(control_file.exists());
    std::fs::remove_file(&control_file).unwrap();
    assert!(matches!(
        host.publish_password_restore(
            &target,
            ticket.request_id(),
            NEW_PASSWORD,
            limits(),
            KdfPolicy::baseline()
        ),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(!control_file.exists());
}

#[test]
fn native_export_rejects_uncommitted_orphan_membership_and_closed_sessions() {
    let temp = tempdir().unwrap();
    let host = Host::create_new(temp.path().join("control")).unwrap();
    let path = temp.path().join("source.sqlite");
    let mut source = host
        .create(&path, PASSWORD, limits(), KdfPolicy::baseline())
        .unwrap();
    let session = source.unlock(PASSWORD).unwrap();
    source
        .save(&session, [1; 16], None, b"m", b"payload", [1; 16])
        .unwrap();
    let key = Identity::generate();
    source.lock();
    assert!(matches!(
        source.export_backup(&session, &key.to_public(), Vec::new(), policy()),
        Err(Error::Locked) | Err(Error::StaleSession)
    ));
    let session = source.unlock(PASSWORD).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "INSERT INTO records(id,revision,envelope) VALUES(?1,1,?2)",
        rusqlite::params![[8u8; 16].as_slice(), vec![0u8; 176]],
    )
    .unwrap();
    assert!(matches!(
        source.export_backup(&session, &key.to_public(), Vec::new(), policy()),
        Err(Error::Integrity)
    ));
}
