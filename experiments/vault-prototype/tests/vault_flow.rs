#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use std::{fs, process::Command};

use fogvault_disposable_prototype::{crypto, CommitFault, Error, Limits, Vault};
use rusqlite::{params, Connection};
use tempfile::tempdir;

const PASSWORD: &[u8] = b"SYNTHETIC-PASSWORD-FOR-EXPERIMENT-ONLY";
const META: &[u8] = b"SYNTHETIC-METADATA-MUST-NOT-BE-PERSISTED-PLAIN";
const SECRET: &[u8] = b"SYNTHETIC-SECRET-MUST-NOT-BE-PERSISTED-PLAIN";
const ID: [u8; 16] = [7; 16];
const REQUEST: [u8; 16] = [8; 16];

fn limits() -> Limits {
    // Bounds derive from this fixture's data, not a proposed production policy.
    Limits {
        max_payload_bytes: SECRET.len(),
        max_metadata_bytes: META.len(),
        max_records: 1,
    }
}

fn seeded(path: &std::path::Path) -> (Vault, fogvault_disposable_prototype::SessionToken) {
    let mut vault = Vault::diagnostic_create(path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault.save(&token, ID, None, META, SECRET, REQUEST).unwrap();
    (vault, token)
}

fn envelope(path: &std::path::Path) -> Vec<u8> {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT envelope FROM records WHERE id=?1",
            params![ID.as_slice()],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn create_unlock_save_lock_reopen_read_and_revoke_stale_session() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    assert!(!vault.is_unlocked());
    assert!(vault.unlock(b"wrong password").is_err());
    assert!(!vault.is_unlocked());
    let first = vault.unlock(PASSWORD).unwrap();
    let receipt = vault.save(&first, ID, None, META, SECRET, REQUEST).unwrap();
    assert_eq!(receipt.generation, 1);
    vault.lock();
    assert!(matches!(vault.read(&first, ID), Err(Error::Locked)));
    let second = vault.unlock(PASSWORD).unwrap();
    assert!(matches!(vault.read(&first, ID), Err(Error::StaleSession)));
    let record = vault.read(&second, ID).unwrap();
    assert_eq!(record.payload.as_slice(), SECRET);
    assert_eq!(record.metadata.as_slice(), META);
    assert!(!format!("{record:?}").contains("MUST-NOT"));
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    assert!(!reopened.is_unlocked());
    let token = reopened.unlock(PASSWORD).unwrap();
    assert_eq!(
        reopened.read(&token, ID).unwrap().payload.as_slice(),
        SECRET
    );
}

#[test]
fn command_proves_reopen_and_read_in_a_second_os_process() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let output = Command::new(env!("CARGO_BIN_EXE_vault-prototype"))
        .arg("demo")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("PASS second-process reopen"));
    assert!(stdout.contains("PASS create -> unlock -> save -> lock -> reopen -> read"));
}

#[test]
fn persisted_main_db_and_live_journal_do_not_contain_synthetic_plaintext() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (_vault, _token) = seeded(&path);
    for entry in fs::read_dir(scratch.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(path).unwrap();
        for sentinel in [PASSWORD, META, SECRET] {
            assert!(!bytes
                .windows(sentinel.len())
                .any(|window| window == sentinel));
        }
    }
}

#[test]
fn exclusive_creation_preserves_an_existing_destination() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("occupied");
    fs::write(&path, b"existing unrelated bytes").unwrap();
    assert!(matches!(
        Vault::diagnostic_create(&path, PASSWORD, limits()),
        Err(Error::Exists)
    ));
    assert_eq!(fs::read(path).unwrap(), b"existing unrelated bytes");
}

#[test]
fn opening_an_unrelated_sqlite_database_does_not_change_its_journal_mode() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("unrelated.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('retain me');").unwrap();
    assert!(Vault::diagnostic_open(&path, limits()).is_err());
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let value: String = connection
        .query_row("SELECT value FROM unrelated", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    assert_eq!(value, "retain me");
}

#[test]
fn ciphertext_modification_is_detected_before_plaintext_release() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let mut altered = envelope(&path);
    *altered.last_mut().unwrap() ^= 1;
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE records SET envelope=?1", [altered])
        .unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::Integrity)));
}

#[test]
fn deletion_and_missing_manifest_are_not_empty_vaults() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM records", [])
        .unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::Integrity)));
    vault.lock();
    assert!(matches!(vault.unlock(PASSWORD), Err(Error::Integrity)));
    assert!(!vault.is_unlocked());
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE vault_state SET head=zeroblob(0)", [])
        .unwrap();
    assert!(vault.unlock(PASSWORD).is_err());
    assert!(!vault.is_unlocked());
}

#[test]
fn selective_old_ciphertext_replay_fails_but_complete_snapshot_rollback_is_not_claimed() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let old_envelope = envelope(&path);
    let connection = Connection::open(&path).unwrap();
    let old_nodes: Vec<(Vec<u8>, Vec<u8>)> = connection
        .prepare("SELECT hash, bytes FROM index_nodes ORDER BY hash")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    let old_head: Vec<u8> = connection
        .query_row("SELECT head FROM vault_state", [], |row| row.get(0))
        .unwrap();
    vault
        .save(&token, ID, Some(1), META, b"replacement", [9; 16])
        .unwrap();
    connection
        .execute("UPDATE records SET envelope=?1", [old_envelope.clone()])
        .unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::Integrity)));
    connection
        .execute("UPDATE records SET revision=1", [])
        .unwrap();
    connection
        .execute("UPDATE vault_state SET head=?1", [old_head])
        .unwrap();
    // Complete P2 snapshot replay includes the old index, whose path was retired.
    connection.execute("DELETE FROM index_nodes", []).unwrap();
    for (hash, bytes) in old_nodes {
        connection
            .execute(
                "INSERT INTO index_nodes(hash,bytes) VALUES(?1,?2)",
                params![hash, bytes],
            )
            .unwrap();
    }
    assert!(matches!(vault.read(&token, ID), Err(Error::Conflict)));
    vault.lock();
    drop(vault);
    // Reopening loses the process-local accepted-head anchor: entire old state is authentic.
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    let token = reopened.unlock(PASSWORD).unwrap();
    assert_eq!(
        reopened.read(&token, ID).unwrap().payload.as_slice(),
        SECRET
    );
}

#[test]
fn before_commit_failure_rolls_back_and_lost_acknowledgment_requires_reconciliation() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    assert!(matches!(
        vault.save_with_fault(
            &token,
            ID,
            Some(1),
            META,
            b"new",
            [9; 16],
            CommitFault::BeforeCommit
        ),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(vault.generation(), Some(1));
    assert_eq!(vault.read(&token, ID).unwrap().payload.as_slice(), SECRET);
    assert!(matches!(
        vault.save_with_fault(
            &token,
            ID,
            Some(1),
            META,
            b"new",
            [10; 16],
            CommitFault::AfterCommit
        ),
        Err(Error::OutcomeUnknown {
            request_id: [10, ..]
        })
    ));
    assert!(matches!(
        vault.read(&token, ID),
        Err(Error::OutcomeUnknown { .. })
    ));
    let receipt = vault.reconcile_latest(&token, [10; 16]).unwrap();
    assert_eq!(receipt.generation, 2);
    assert_eq!(vault.read(&token, ID).unwrap().payload.as_slice(), b"new");
}

#[test]
fn latest_identical_retry_is_idempotent_and_changed_contents_are_rejected() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let before = envelope(&path);
    let receipt = vault.save(&token, ID, None, META, SECRET, REQUEST).unwrap();
    assert_eq!(receipt.generation, 1);
    assert_eq!(envelope(&path), before);
    assert!(matches!(
        vault.save(&token, ID, None, META, b"different", REQUEST),
        Err(Error::OperationIdReuse)
    ));
    assert_eq!(vault.read(&token, ID).unwrap().payload.as_slice(), SECRET);
}

#[test]
fn stale_second_connection_cannot_overwrite_the_accepted_head() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut first, token) = seeded(&path);
    let mut second = Vault::diagnostic_open(&path, limits()).unwrap();
    let second_token = second.unlock(PASSWORD).unwrap();
    first
        .save(&token, ID, Some(1), META, b"winner", [9; 16])
        .unwrap();
    assert!(matches!(
        second.save(&second_token, ID, Some(1), META, b"stale", [10; 16]),
        Err(Error::Conflict)
    ));
    assert_eq!(
        first.read(&token, ID).unwrap().payload.as_slice(),
        b"winner"
    );
}

#[test]
fn resource_policy_and_untrusted_kdf_costs_are_rejected_without_state_change() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let oversized = vec![0u8; SECRET.len() + 1];
    assert!(matches!(
        vault.save(&token, ID, Some(1), META, &oversized, [9; 16]),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(vault.generation(), Some(1));
    let connection = Connection::open(&path).unwrap();
    let mut descriptor: Vec<u8> = connection
        .query_row("SELECT descriptor FROM vault_state", [], |row| row.get(0))
        .unwrap();
    descriptor[14..18].copy_from_slice(&u32::MAX.to_be_bytes());
    connection
        .execute("UPDATE vault_state SET descriptor=?1", [descriptor])
        .unwrap();
    assert!(matches!(
        Vault::diagnostic_open(&path, limits()),
        Err(Error::Crypto(crypto::CryptoError::RejectedKdfParameters))
    ));
}

#[test]
fn oversized_database_blobs_are_rejected_by_length_admission() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE records SET envelope=zeroblob(?1)",
            [i64::try_from(limits().diagnostic_legacy_envelope_bytes().unwrap() + 1).unwrap()],
        )
        .unwrap();
    assert!(matches!(vault.read(&token, ID), Err(Error::ResourceLimit)));
    connection
        .execute("UPDATE vault_state SET descriptor=zeroblob(131)", [])
        .unwrap();
    assert!(matches!(
        Vault::diagnostic_open(&path, limits()),
        Err(Error::Malformed("descriptor length"))
    ));
}

#[test]
fn record_keys_and_ciphertexts_change_for_each_revision_and_other_vaults_cannot_use_them() {
    let scratch = tempdir().unwrap();
    let first_path = scratch.path().join("first.sqlite");
    let second_path = scratch.path().join("second.sqlite");
    let (mut first, token) = seeded(&first_path);
    let old = envelope(&first_path);
    first
        .save(&token, ID, Some(1), META, SECRET, [9; 16])
        .unwrap();
    let new = envelope(&first_path);
    assert_ne!(&old[32..104], &new[32..104]);
    assert_ne!(&old[112..], &new[112..]);
    let (mut second, second_token) = seeded(&second_path);
    assert!(matches!(second.read(&token, ID), Err(Error::StaleSession)));
    Connection::open(&second_path)
        .unwrap()
        .execute("UPDATE records SET envelope=?1", [new])
        .unwrap();
    assert!(matches!(
        second.read(&second_token, ID),
        Err(Error::Integrity)
    ));
}
