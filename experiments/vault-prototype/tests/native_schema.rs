//! Hostile schema is persisted input, not trusted adapter code.
use std::fs;

use fogvault_disposable_prototype::{CommitFault, Error, Limits, Vault};
use rusqlite::Connection;
use tempfile::tempdir;

const PASSWORD: &[u8] = b"schema-admission-synthetic-password";
const ID: [u8; 16] = [0x51; 16];
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 128,
        max_metadata_bytes: 32,
        max_records: 8,
    }
}

#[test]
fn native_schema_rejects_trigger_false_save_success_without_mutation() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("hostile-trigger.sqlite");
    drop(Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER discard_new_ciphertext AFTER INSERT ON records
         BEGIN DELETE FROM records WHERE id=NEW.id; END;",
        )
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Vault::diagnostic_open(&path, limits()),
        Err(Error::Integrity)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    let generation: Vec<u8> = db
        .query_row("SELECT head FROM vault_state", [], |r| r.get(0))
        .unwrap();
    assert_eq!(&generation[..8], &[0; 8]);
    let count: i64 = db
        .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn native_schema_rechecks_every_operation_after_external_schema_change() {
    for table in ["records", "vault_state", "index_nodes"] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            let scratch = tempdir().unwrap();
            let path = scratch.path().join("changed-schema.sqlite");
            let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
            let token = vault.unlock(PASSWORD).unwrap();
            vault
                .save(&token, ID, None, b"", b"accepted", [1; 16])
                .unwrap();
            Connection::open(&path)
                .unwrap()
                .execute_batch(&format!(
                    "CREATE TRIGGER hostile AFTER {action} ON {table}
                 BEGIN DELETE FROM records; END;"
                ))
                .unwrap();
            let before = fs::read(&path).unwrap();
            assert!(
                matches!(
                    vault.save(&token, ID, Some(1), b"", b"lost", [2; 16]),
                    Err(Error::Integrity)
                ),
                "{table}/{action}"
            );
            assert!(matches!(
                vault.delete(&token, ID, 1, [3; 16]),
                Err(Error::Integrity)
            ));
            assert!(matches!(vault.read(&token, ID), Err(Error::Integrity)));
            assert!(matches!(
                vault.change_password_with_fault(
                    &token,
                    PASSWORD,
                    b"replacement",
                    [4; 16],
                    CommitFault::None
                ),
                Err(Error::Integrity)
            ));
            assert!(matches!(
                vault.reconcile_latest(&token, [1; 16]),
                Err(Error::Integrity)
            ));
            assert_eq!(fs::read(&path).unwrap(), before, "{table}/{action}");
            drop(vault);
            assert!(matches!(
                Vault::diagnostic_open(&path, limits()),
                Err(Error::Integrity)
            ));
            assert_eq!(fs::read(&path).unwrap(), before);
        }
    }
}

#[test]
fn native_schema_rejects_views_columns_constraints_and_extra_objects() {
    for modification in [
        "ALTER TABLE records RENAME TO hidden_records; CREATE VIEW records AS SELECT * FROM hidden_records;",
        "ALTER TABLE records ADD COLUMN ignored BLOB;",
        "DROP TABLE records; CREATE TABLE records(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision INTEGER NOT NULL CHECK(revision>=0),envelope BLOB NOT NULL);",
        "DROP TABLE records; CREATE TABLE records(id BLOB PRIMARY KEY,revision INTEGER,envelope BLOB);",
        "CREATE INDEX extra_index ON records(revision);",
        "CREATE TABLE extra_table(value BLOB);",
    ] {
        let scratch = tempdir().unwrap();
        let path = scratch.path().join("unsupported-schema.sqlite");
        drop(Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap());
        Connection::open(&path).unwrap().execute_batch(modification).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(Vault::diagnostic_open(&path, limits()).is_err(), "{modification}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn native_schema_accepts_both_existing_creation_spellings() {
    let scratch = tempdir().unwrap();
    let direct = scratch.path().join("direct.sqlite");
    let prepared = scratch.path().join("prepared.sqlite");
    let legacy_compact = scratch.path().join("legacy-compact.sqlite");
    drop(Vault::diagnostic_create(&direct, PASSWORD, limits()).unwrap());
    // Preserve compatibility with the prepared-creation spelling from the
    // review candidate, rather than merely testing the new shared initializer.
    let source = Connection::open(&direct).unwrap();
    let header: (Vec<u8>, Vec<u8>) = source
        .query_row("SELECT descriptor,head FROM vault_state", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let legacy = Connection::open(&legacy_compact).unwrap();
    legacy.execute_batch("CREATE TABLE vault_state(id INTEGER PRIMARY KEY CHECK(id=1),descriptor BLOB NOT NULL,head BLOB NOT NULL);
        CREATE TABLE records(id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),revision INTEGER NOT NULL CHECK(revision>0),envelope BLOB NOT NULL);
        CREATE TABLE index_nodes(hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash)=32),bytes BLOB NOT NULL CHECK(length(bytes)<=82));").unwrap();
    legacy
        .execute(
            "INSERT INTO vault_state VALUES(1,?1,?2)",
            rusqlite::params![header.0, header.1],
        )
        .unwrap();
    drop(legacy);
    drop(source);
    drop(
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), fogvault::KdfPolicy::baseline())
            .unwrap()
            .publish(&prepared, CommitFault::None)
            .unwrap(),
    );
    for path in [direct, prepared, legacy_compact] {
        let mut vault = Vault::diagnostic_open(&path, limits()).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        vault
            .save(&token, ID, None, b"", b"persisted", [1; 16])
            .unwrap();
        assert_eq!(
            vault.read(&token, ID).unwrap().payload.as_slice(),
            b"persisted"
        );
    }
}

#[test]
fn native_schema_rejects_unqualified_journal_mode_without_reconfiguring_file() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("wal.sqlite");
    drop(Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap());
    let db = Connection::open(&path).unwrap();
    let mode: String = db
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(db);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        Vault::diagnostic_open(&path, limits()),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    let mode: String = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn native_schema_rejects_aliased_storage_roots() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("aliased-root.sqlite");
    drop(Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap());
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA writable_schema=ON;
        UPDATE sqlite_schema SET rootpage=(SELECT rootpage FROM sqlite_schema WHERE name='index_nodes') WHERE name='records';
        PRAGMA writable_schema=OFF;").unwrap();
    drop(db);
    let before = fs::read(&path).unwrap();
    match Vault::diagnostic_open(&path, limits()) {
        Err(Error::Integrity) => {}
        Ok(mut vault) => {
            let token = vault.unlock(PASSWORD).unwrap();
            let receipt = vault.save(&token, ID, None, b"", b"payload", [1; 16]);
            panic!(
                "aliased schema admitted; save={receipt:?}; read={:?}; audit={:?}",
                vault.read(&token, ID).map(|r| r.revision),
                vault.audit(&token)
            );
        }
        Err(error) => panic!("wrong admission error: {error:?}"),
    }
    assert_eq!(fs::read(&path).unwrap(), before);
}
