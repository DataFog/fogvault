//! Real SQLite quota failure, with no production quota-control API.
use super::*;

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    records: Vec<(Vec<u8>, i64, Vec<u8>)>,
    nodes: Vec<(Vec<u8>, Vec<u8>)>,
}

fn snapshot(connection: &Connection) -> Snapshot {
    let (descriptor, head) = connection
        .query_row(
            "SELECT descriptor, head FROM vault_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let records = connection
        .prepare("SELECT id, revision, envelope FROM records ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let nodes = connection
        .prepare("SELECT hash, bytes FROM index_nodes ORDER BY hash")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
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
fn sqlite_capacity_failure_rolls_back_and_preserves_accepted_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("quota.db");
    // A test caller's explicit budget, not a proposed product limit.
    let limits = Limits {
        max_payload_bytes: 1024 * 1024,
        max_metadata_bytes: 32,
        max_records: 4,
    };
    let mut vault = Vault::diagnostic_create(&path, b"synthetic quota password", limits).unwrap();
    let token = vault.unlock(b"synthetic quota password").unwrap();
    let id = [17; 16];
    vault
        .save(
            &token,
            id,
            None,
            b"old metadata",
            b"old committed payload",
            [18; 16],
        )
        .unwrap();
    let before = snapshot(&vault.connection);
    let receipt = vault.engine.current_receipt().unwrap();
    let page_count: u32 = vault
        .connection
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let page_size: u32 = vault
        .connection
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap();
    // SQLite enforces this on the actual writer connection. The replacement
    // exceeds the entire current file footprint, so existing free pages cannot
    // hide the quota failure. No synthetic storage error is injected.
    let payload = vec![
        0x5a;
        usize::try_from(
            page_count
                .checked_mul(page_size)
                .unwrap()
                .checked_mul(2)
                .unwrap()
        )
        .unwrap()
    ];
    assert!(payload.len() <= limits.max_payload_bytes);
    vault
        .connection
        .pragma_update(None, "max_page_count", page_count)
        .unwrap();
    let error = vault
        .save(&token, id, Some(1), b"new metadata", &payload, [19; 16])
        .unwrap_err();
    assert!(matches!(error, Error::Capacity), "{error:?}");
    assert_eq!(error.code(), "Capacity");
    assert!(vault.connection.is_autocommit());
    assert_eq!(snapshot(&vault.connection), before);
    assert_eq!(
        vault.engine.current_receipt().unwrap().head_digest,
        receipt.head_digest
    );
    let old = vault.read(&token, id).unwrap();
    assert_eq!(old.metadata.as_slice(), b"old metadata");
    assert_eq!(old.payload.as_slice(), b"old committed payload");
    vault.audit(&token).unwrap();

    // The same intent can be retried after the owner increases capacity: a
    // failed attempt did not leave a receipt or dirty Engine prepared state.
    vault
        .connection
        .pragma_update(None, "max_page_count", page_count * 4)
        .unwrap();
    vault
        .save(&token, id, Some(1), b"new metadata", &payload, [19; 16])
        .unwrap();
    assert_eq!(vault.read(&token, id).unwrap().payload.as_slice(), payload);
}
