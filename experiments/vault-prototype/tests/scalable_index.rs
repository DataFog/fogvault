//! Independent adapter acceptance cases for the P2 index candidate.
//! These use synthetic data and direct hostile-store edits, not production credentials.
#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use std::{collections::BTreeMap, fs, path::Path};

use datafog_core::workspace::{Workspace, MAX_BUNDLE_BYTES};
use fogvault_disposable_prototype::{
    format::INDEX_HEAD_LEN, index::MAX_PATH_NODES, CommitFault, Error, Limits, RecordId,
    SessionToken, Vault,
};
use rusqlite::{params, Connection};
use tempfile::tempdir;

const PASSWORD: &[u8] = b"SYNTHETIC-SCALABLE-INDEX-ACCEPTANCE-ONLY";
const IDS: [RecordId; 4] = [
    0u128.to_be_bytes(),
    1u128.to_be_bytes(),
    (1u128 << 127).to_be_bytes(),
    u128::MAX.to_be_bytes(),
];

fn limits() -> Limits {
    // Authority is the four boundary-key records in this fixture, not product policy.
    Limits {
        max_payload_bytes: 2,
        max_metadata_bytes: 1,
        max_records: IDS.len(),
    }
}

fn seeded(path: &Path) -> (Vault, SessionToken) {
    let mut vault = Vault::diagnostic_create(path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    for (i, id) in IDS[..3].iter().enumerate() {
        vault
            .save(
                &token,
                *id,
                None,
                &[i as u8],
                &[i as u8, 0xa5],
                (100 + i as u128).to_be_bytes(),
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
    let connection = Connection::open(path).unwrap();
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
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let nodes = connection
        .prepare("SELECT hash, bytes FROM index_nodes ORDER BY hash")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    Snapshot {
        descriptor,
        head,
        records,
        nodes,
    }
}

fn check_map(
    vault: &mut Vault,
    token: &SessionToken,
    expected: &BTreeMap<RecordId, (u64, Vec<u8>, Vec<u8>)>,
) {
    for (id, (revision, metadata, payload)) in expected {
        let record = vault.read(token, *id).unwrap();
        assert_eq!(record.revision, *revision);
        assert_eq!(record.metadata.as_slice(), metadata);
        assert_eq!(record.payload.as_slice(), payload);
        let logical = vault.last_metrics();
        assert_eq!(logical.full_audits, 0);
        assert_eq!(logical.records_scanned, 0);
        assert_eq!(logical.record_rows_read, 1);
        assert_eq!(logical.head_bytes_read, INDEX_HEAD_LEN as u64);
        assert!(logical.index.nodes_read <= MAX_PATH_NODES as u64);
    }
    let report = vault.audit(token).unwrap();
    assert_eq!(report.records_checked, expected.len() as u64);
    assert_eq!(report.index_nodes_checked, (expected.len() * 2 - 1) as u64);
    let logical = vault.last_metrics();
    assert_eq!(logical.full_audits, 1);
    assert_eq!(logical.records_scanned, expected.len() as u64);
    assert_eq!(logical.record_rows_read, expected.len() as u64);
    assert_eq!(logical.index.nodes_read, report.index_nodes_checked);
    assert!(logical.record_bytes_read > 0);
}

fn check_point_save_metrics(vault: &Vault) {
    let logical = vault.last_metrics();
    // These are format-derived logical work bounds, not physical-I/O or timing budgets.
    assert_eq!(logical.full_audits, 0);
    assert_eq!(logical.records_scanned, 0);
    assert!(logical.record_rows_read <= 1);
    assert_eq!(logical.head_bytes_read, INDEX_HEAD_LEN as u64);
    assert_eq!(logical.head_bytes_written, INDEX_HEAD_LEN as u64);
    assert!(logical.index.nodes_read <= 2 * MAX_PATH_NODES as u64);
    assert!(logical.index.nodes_written <= MAX_PATH_NODES as u64);
    assert!(logical.index_nodes_deleted <= MAX_PATH_NODES as u64);
}

#[test]
fn boundary_keys_updates_and_latest_retry_match_an_independent_map() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let initial_head_length = snapshot(&path).head.len();
    let mut expected = BTreeMap::new();
    for (i, id) in IDS.iter().enumerate() {
        let metadata = vec![i as u8];
        let payload = vec![i as u8, 0xa5];
        vault
            .save(
                &token,
                *id,
                None,
                &metadata,
                &payload,
                (100 + i as u128).to_be_bytes(),
            )
            .unwrap();
        check_point_save_metrics(&vault);
        expected.insert(*id, (1, metadata, payload));
        check_map(&mut vault, &token, &expected);
        let stored = snapshot(&path);
        assert_eq!(stored.head.len(), initial_head_length);
        assert_eq!(stored.nodes.len(), expected.len() * 2 - 1);
    }
    let mut latest = None;
    for (i, id) in IDS.iter().enumerate() {
        let payload = vec![i as u8, 0x5a];
        let receipt = vault
            .save(
                &token,
                *id,
                Some(1),
                &[i as u8],
                &payload,
                (200 + i as u128).to_be_bytes(),
            )
            .unwrap();
        check_point_save_metrics(&vault);
        expected.get_mut(id).unwrap().0 = 2;
        expected.get_mut(id).unwrap().2 = payload;
        latest = Some(receipt);
        check_map(&mut vault, &token, &expected);
        assert_eq!(snapshot(&path).nodes.len(), IDS.len() * 2 - 1);
    }
    let before_retry = snapshot(&path);
    let retry = vault
        .save(
            &token,
            IDS[3],
            Some(1),
            &[3],
            &[3, 0x5a],
            203u128.to_be_bytes(),
        )
        .unwrap();
    assert_eq!(Some(retry), latest);
    let logical = vault.last_metrics();
    assert_eq!(logical.full_audits, 0);
    assert_eq!(logical.records_scanned, 0);
    assert_eq!(logical.index.nodes_written, 0);
    assert_eq!(logical.index_nodes_deleted, 0);
    assert_eq!(logical.head_bytes_written, 0);
    assert_eq!(logical.record_bytes_written, 0);
    assert_eq!(snapshot(&path), before_retry);
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    let token = reopened.unlock(PASSWORD).unwrap();
    let logical = reopened.last_metrics();
    assert_eq!(logical.full_audits, 1);
    assert_eq!(logical.records_scanned, IDS.len() as u64);
    assert_eq!(logical.record_bytes_read, 0);
    check_map(&mut reopened, &token, &expected);
}

#[test]
fn point_proof_distinguishes_absence_from_loss_and_full_audit_checks_membership() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let mut connection = Connection::open(&path).unwrap();
    let victim: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM records WHERE id=?1",
            params![IDS[1].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute(
            "DELETE FROM records WHERE id=?1",
            params![IDS[1].as_slice()],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO records(id,revision,envelope) VALUES(?1,1,?2)",
            params![IDS[3].as_slice(), victim],
        )
        .unwrap();
    transaction.commit().unwrap();

    // Same SQL count cannot hide one missing committed member plus one extra row.
    assert_eq!(
        vault.read(&token, IDS[0]).unwrap().payload.as_slice(),
        &[0, 0xa5]
    );
    assert!(matches!(vault.read(&token, IDS[1]), Err(Error::Integrity)));
    assert!(matches!(vault.read(&token, IDS[3]), Err(Error::NotFound)));
    assert!(matches!(vault.audit(&token), Err(Error::Integrity)));
    vault.lock();
    assert!(matches!(vault.unlock(PASSWORD), Err(Error::Integrity)));
    assert!(!vault.is_unlocked());
}

#[test]
fn committed_missing_or_modified_node_never_becomes_an_absent_record() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let connection = Connection::open(&path).unwrap();
    // P2's leaf encoding deliberately binds the ID at bytes 1..17.
    let (hash, original): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT hash,bytes FROM index_nodes WHERE length(bytes)=57 AND substr(bytes,2,16)=?1",
            params![IDS[0].as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE index_nodes SET bytes=?1 WHERE hash=?2",
            params![changed, hash],
        )
        .unwrap();
    assert!(matches!(vault.read(&token, IDS[0]), Err(Error::Integrity)));
    assert!(matches!(vault.audit(&token), Err(Error::Integrity)));
    connection
        .execute(
            "UPDATE index_nodes SET bytes=?1 WHERE hash=?2",
            params![original, hash],
        )
        .unwrap();
    assert!(vault.read(&token, IDS[0]).is_ok());
    connection
        .execute("DELETE FROM index_nodes WHERE hash=?1", params![hash])
        .unwrap();
    assert!(matches!(vault.read(&token, IDS[0]), Err(Error::Integrity)));
    assert!(matches!(vault.audit(&token), Err(Error::Integrity)));
}

#[test]
fn transaction_failure_preserves_record_head_and_exact_live_node_set() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let before = snapshot(&path);
    assert!(matches!(
        vault.save_with_fault(
            &token,
            IDS[0],
            Some(1),
            &[0],
            &[0, 0x5a],
            500u128.to_be_bytes(),
            CommitFault::BeforeCommit,
        ),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(snapshot(&path), before);
    assert_eq!(
        vault.read(&token, IDS[0]).unwrap().payload.as_slice(),
        &[0, 0xa5]
    );
    let report = vault.audit(&token).unwrap();
    assert_eq!(report.records_checked, 3);
    assert_eq!(report.index_nodes_checked, 5);
}

#[test]
fn latest_receipt_recovery_and_retry_do_not_confirm_a_missing_committed_record() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let (mut vault, token) = seeded(&path);
    let request = 700u128.to_be_bytes();
    assert!(matches!(
        vault.save_with_fault(
            &token,
            IDS[2],
            Some(1),
            &[2],
            &[2, 0x5a],
            request,
            CommitFault::AfterCommit,
        ),
        Err(Error::OutcomeUnknown { .. })
    ));
    let connection = Connection::open(&path).unwrap();
    let envelope: Vec<u8> = connection
        .query_row(
            "SELECT envelope FROM records WHERE id=?1",
            params![IDS[2].as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM records WHERE id=?1",
            params![IDS[2].as_slice()],
        )
        .unwrap();
    assert!(matches!(
        vault.reconcile_latest(&token, request),
        Err(Error::Integrity)
    ));
    connection
        .execute(
            "INSERT INTO records(id,revision,envelope) VALUES(?1,2,?2)",
            params![IDS[2].as_slice(), envelope],
        )
        .unwrap();
    vault.reconcile_latest(&token, request).unwrap();
    let logical = vault.last_metrics();
    assert_eq!(logical.full_audits, 1);
    assert_eq!(logical.records_scanned, 3);
    assert_eq!(logical.record_bytes_read, 0);
    connection
        .execute(
            "DELETE FROM records WHERE id=?1",
            params![IDS[2].as_slice()],
        )
        .unwrap();
    assert!(matches!(
        vault.save(&token, IDS[2], Some(1), &[2], &[2, 0x5a], request),
        Err(Error::Integrity)
    ));
}

#[test]
fn legacy_p1_fixture_is_rejected_without_silent_reinterpretation_or_modification() {
    let scratch = tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/PROTOTYPE-WIPE-ME.sqlite");
    let retained_bytes = fs::read(&source).unwrap();
    let copy = scratch.path().join("P1-READ-ONLY-COPY.sqlite");
    fs::write(&copy, &retained_bytes).unwrap();
    assert!(matches!(
        Vault::diagnostic_open(&copy, limits()),
        Err(Error::Malformed(_))
    ));
    assert_eq!(fs::read(&copy).unwrap(), retained_bytes);
    assert_eq!(fs::read(source).unwrap(), retained_bytes);
}

#[test]
fn exact_beta3_consumer_keeps_two_workspace_namespaces_separate_after_reopen() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite");
    let domain = b"datafog-core:workspace:0.5.0-beta.3\0";
    let metadata_bytes = domain.len() + 16 + (8 + 16) * 2;
    let policy = Limits {
        max_payload_bytes: MAX_BUNDLE_BYTES,
        max_metadata_bytes: metadata_bytes,
        max_records: 2,
    };
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, policy).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let mut expected = BTreeMap::new();
    for (i, record_id) in IDS[..2].iter().enumerate() {
        let namespace = [40 + i as u8; 16];
        let mut workspace = Workspace::create(namespace, [50 + i as u8; 16]).unwrap();
        let head = workspace.head().unwrap();
        let mut metadata = domain.to_vec();
        metadata.extend_from_slice(&namespace);
        // An initial save binds the complete parent and saved Core Heads.
        for _ in 0..2 {
            metadata.extend_from_slice(&head.revision.to_le_bytes());
            metadata.extend_from_slice(&head.commit_id);
        }
        vault
            .save(
                &token,
                *record_id,
                None,
                &metadata,
                &workspace.export_bundle().unwrap(),
                (600 + i as u128).to_be_bytes(),
            )
            .unwrap();
        expected.insert(*record_id, (namespace, head, metadata));
        workspace.close();
        assert!(workspace.namespace().is_err());
    }
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, policy).unwrap();
    let token = reopened.unlock(PASSWORD).unwrap();
    for (record_id, (namespace, head, metadata)) in expected {
        let record = reopened.read(&token, record_id).unwrap();
        assert_eq!(record.metadata.as_slice(), metadata);
        let mut workspace = Workspace::open_bundle(&record.payload).unwrap();
        assert_eq!(workspace.namespace().unwrap(), namespace);
        assert_eq!(workspace.head().unwrap(), head);
        workspace.close();
    }
    assert_eq!(reopened.audit(&token).unwrap().records_checked, 2);
}
