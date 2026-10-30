#![cfg(all(feature = "native", not(target_arch = "wasm32")))]
use fogvault_disposable_prototype::{CommitFault, Error, Limits, SessionToken, Vault};
use rusqlite::{params, Connection};
use std::path::Path;
use tempfile::tempdir;

const PASSWORD: &[u8] = b"synthetic-record-operation-password";
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 128,
        max_metadata_bytes: 32,
        max_records: 256,
    }
}
fn seeded(path: &Path, count: u8) -> (Vault, SessionToken) {
    let mut vault = Vault::diagnostic_create(path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    for id in 0..count {
        vault
            .save(
                &token,
                [id; 16],
                None,
                b"meta",
                &[id],
                [id.wrapping_add(1); 16],
            )
            .unwrap();
    }
    (vault, token)
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    records: Vec<(Vec<u8>, i64, Vec<u8>)>,
    nodes: Vec<(Vec<u8>, Vec<u8>)>,
}
fn snapshot(path: &Path) -> Snapshot {
    let db = Connection::open(path).unwrap();
    let (descriptor, head) = db
        .query_row("SELECT descriptor,head FROM vault_state", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    let records = db
        .prepare("SELECT id,revision,envelope FROM records ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let nodes = db
        .prepare("SELECT hash,bytes FROM index_nodes ORDER BY hash")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    Snapshot {
        descriptor,
        head,
        records,
        nodes,
    }
}

#[test]
fn native_delete_retries_empty_root_and_retained_backups_have_exact_semantics() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("records.sqlite");
    let backup = scratch.path().join("retained-before-delete.sqlite");
    let (mut vault, token) = seeded(&path, 2);
    // A controlled idle committed fixture, not a general live backup API.
    std::fs::copy(&path, &backup).unwrap();
    let before = snapshot(&path);
    let old = before.records[0].clone();
    let receipt = vault.delete(&token, [0; 16], 1, [100; 16]).unwrap();
    assert!(matches!(vault.read(&token, [0; 16]), Err(Error::NotFound)));
    assert_eq!(vault.last_metrics().record_bytes_written, 0);
    let current = snapshot(&path);
    assert_eq!(current.descriptor, before.descriptor);
    assert_eq!(
        vault.delete(&token, [0; 16], 1, [100; 16]).unwrap(),
        receipt
    );
    assert_eq!(snapshot(&path), current);
    assert_eq!(vault.last_metrics().index.nodes_written, 0);
    assert!(matches!(
        vault.delete(&token, [1; 16], 1, [100; 16]),
        Err(Error::OperationIdReuse)
    ));
    let db = Connection::open(&path).unwrap();
    db.execute(
        "INSERT INTO records(id,revision,envelope) VALUES(?1,?2,?3)",
        params![old.0, old.1, old.2],
    )
    .unwrap();
    assert!(matches!(vault.read(&token, [0; 16]), Err(Error::NotFound)));
    assert!(vault.audit(&token).is_err());
    assert!(vault.delete(&token, [0; 16], 1, [100; 16]).is_err());
    db.execute(
        "DELETE FROM records WHERE id=?1",
        params![[0u8; 16].as_slice()],
    )
    .unwrap();
    drop(db);
    vault.delete(&token, [1; 16], 1, [101; 16]).unwrap();
    let empty = snapshot(&path);
    assert!(empty.records.is_empty() && empty.nodes.is_empty());
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    let token = reopened.unlock(PASSWORD).unwrap();
    let mut cursor = reopened.begin_records(&token).unwrap();
    assert!(
        reopened
            .record_page(&token, &mut cursor, 1)
            .unwrap()
            .complete
    );
    let mut retained = Vault::diagnostic_open(&backup, limits()).unwrap();
    let old_token = retained.unlock(PASSWORD).unwrap();
    assert_eq!(
        retained
            .read(&old_token, [0; 16])
            .unwrap()
            .payload
            .as_slice(),
        &[0]
    );
}

#[test]
fn native_delete_abort_unknown_reconcile_and_stale_writers_are_safe() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("faults.sqlite");
    let (mut vault, token) = seeded(&path, 2);
    let mut stale = Vault::diagnostic_open(&path, limits()).unwrap();
    let stale_token = stale.unlock(PASSWORD).unwrap();
    let before = snapshot(&path);
    assert!(matches!(
        vault.delete_with_fault(&token, [0; 16], 1, [110; 16], CommitFault::BeforeCommit),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(snapshot(&path), before);
    assert_eq!(
        vault.read(&token, [0; 16]).unwrap().payload.as_slice(),
        &[0]
    );
    assert!(matches!(
        vault.delete_with_fault(&token, [0; 16], 1, [110; 16], CommitFault::AfterCommit),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(vault.read(&token, [1; 16]).is_err());
    assert!(vault.begin_records(&token).is_err());
    let receipt = vault.reconcile_latest(&token, [110; 16]).unwrap();
    assert_eq!(
        vault.delete(&token, [0; 16], 1, [110; 16]).unwrap(),
        receipt
    );
    let committed = snapshot(&path);
    assert!(stale.delete(&stale_token, [1; 16], 1, [111; 16]).is_err());
    assert_eq!(snapshot(&path), committed);
    assert!(matches!(
        vault.delete(&token, [1; 16], 2, [112; 16]),
        Err(Error::Conflict)
    ));
    assert_eq!(snapshot(&path), committed);
    vault.lock();
    assert!(vault.delete(&token, [1; 16], 1, [113; 16]).is_err());
}

#[test]
fn native_paged_inventory_is_exact_bounded_and_rejects_changed_snapshots() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("pages.sqlite");
    let (mut vault, token) = seeded(&path, 17);
    let mut cursor = vault.begin_records(&token).unwrap();
    let mut ids = Vec::new();
    let mut node_reads = 0;
    loop {
        let page = vault.record_page(&token, &mut cursor, 3).unwrap();
        assert!(page.records.len() <= 3 && page.peak_frontier_nodes <= 129);
        node_reads += page.stats.nodes_read;
        ids.extend(page.records.iter().map(|proof| proof.id()));
        if page.complete {
            break;
        }
    }
    assert_eq!(ids, (0..17).map(|id| [id; 16]).collect::<Vec<_>>());
    assert_eq!(node_reads, 33);
    let mut stale_cursor = vault.begin_records(&token).unwrap();
    assert!(
        !vault
            .record_page(&token, &mut stale_cursor, 1)
            .unwrap()
            .complete
    );
    let mut writer = Vault::diagnostic_open(&path, limits()).unwrap();
    let writer_token = writer.unlock(PASSWORD).unwrap();
    writer
        .save(
            &writer_token,
            [16; 16],
            Some(1),
            b"meta",
            b"changed",
            [120; 16],
        )
        .unwrap();
    assert!(vault.record_page(&token, &mut stale_cursor, 1).is_err());
    vault.lock();
    assert!(vault.record_page(&token, &mut stale_cursor, 1).is_err());
}

#[test]
fn native_page_errors_cannot_skip_corrupt_members_or_report_false_completion() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("corrupt-page.sqlite");
    let (mut vault, token) = seeded(&path, 6);
    let original = snapshot(&path).records[2].2.clone();
    let mut cursor = vault.begin_records(&token).unwrap();
    vault.record_page(&token, &mut cursor, 2).unwrap();
    let db = Connection::open(&path).unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    db.execute(
        "UPDATE records SET envelope=?1 WHERE id=?2",
        params![corrupt, [2u8; 16].as_slice()],
    )
    .unwrap();
    assert!(vault.record_page(&token, &mut cursor, 2).is_err());
    db.execute(
        "UPDATE records SET envelope=?1 WHERE id=?2",
        params![original, [2u8; 16].as_slice()],
    )
    .unwrap();
    assert!(vault.record_page(&token, &mut cursor, 2).is_err());
    let mut cursor = vault.begin_records(&token).unwrap();
    db.execute(
        "INSERT INTO index_nodes(hash,bytes) VALUES(?1,?2)",
        params![[0xeeu8; 32].as_slice(), [0u8].as_slice()],
    )
    .unwrap();
    assert!(vault.record_page(&token, &mut cursor, 6).is_err());
    assert!(vault.record_page(&token, &mut cursor, 1).is_err());
}
