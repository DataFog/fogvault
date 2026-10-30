#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

//! Credentials change the root wrapper and authenticated head, never record data.
use std::path::Path;

use fogvault::{CredentialReceipt, KdfPolicy, KdfProfile};
use fogvault_disposable_prototype::{CommitFault, Error, Limits, SessionToken, Vault};
use rusqlite::{params, Connection};
use tempfile::tempdir;

const OLD: &[u8] = b"SYNTHETIC-OLD-PASSPHRASE";
const NEW: &[u8] = b"SYNTHETIC-NEW-PASSPHRASE";
const META: &[u8] = b"meta";
const PAYLOAD: &[u8] = b"payload";
const FIRST: [u8; 16] = [0x11; 16];
const SECOND: [u8; 16] = [0x22; 16];
const CHANGE: [u8; 16] = [0x33; 16];
const UPGRADE: [u8; 16] = [0x44; 16];

fn limits() -> Limits {
    Limits {
        max_payload_bytes: PAYLOAD.len(),
        max_metadata_bytes: META.len(),
        max_records: 2,
    }
}
fn target() -> KdfProfile {
    let old = KdfProfile::baseline();
    // The smallest strict pass-count increase is an explicit experiment input,
    // not a new product default or a physical-device budget recommendation.
    KdfProfile::argon2id(old.memory_kib(), old.passes() + 1).unwrap()
}
fn policy() -> KdfPolicy {
    KdfPolicy::new(vec![KdfProfile::baseline(), target()]).unwrap()
}
fn seeded(path: &Path) -> (Vault, SessionToken) {
    let mut vault =
        Vault::diagnostic_create_with_kdf_policy(path, OLD, limits(), policy()).unwrap();
    let token = vault.unlock(OLD).unwrap();
    for (id, request) in [(FIRST, [0x01; 16]), (SECOND, [0x02; 16])] {
        vault
            .save(&token, id, None, META, PAYLOAD, request)
            .unwrap();
    }
    (vault, token)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    descriptor: Vec<u8>,
    head: Vec<u8>,
    records: Vec<(Vec<u8>, i64, Vec<u8>)>,
    nodes: Vec<(Vec<u8>, Vec<u8>)>,
}
fn snapshot(path: &Path) -> Snapshot {
    let db = Connection::open(path).unwrap();
    let (descriptor, head) = db
        .query_row("SELECT descriptor, head FROM vault_state", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let records = db
        .prepare("SELECT id, revision, envelope FROM records ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let nodes = db
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
fn assert_unchanged_content(before: &Snapshot, after: &Snapshot) {
    assert_eq!(before.records, after.records);
    assert_eq!(before.nodes, after.nodes);
}
fn assert_no_record_work(vault: &Vault) {
    let metrics = vault.last_metrics();
    assert_eq!(metrics.index.nodes_read, 0);
    assert_eq!(metrics.index.nodes_written, 0);
    assert_eq!(metrics.record_rows_read, 0);
    assert_eq!(metrics.record_bytes_read, 0);
    assert_eq!(metrics.record_bytes_written, 0);
    assert_eq!(metrics.index_nodes_deleted, 0);
    assert_eq!(metrics.full_audits, 0);
    assert_eq!(metrics.records_scanned, 0);
}
fn assert_payloads(vault: &mut Vault, token: &SessionToken) {
    for id in [FIRST, SECOND] {
        let record = vault.read(token, id).unwrap();
        assert_eq!(record.revision, 1);
        assert_eq!(record.metadata.as_slice(), META);
        assert_eq!(record.payload.as_slice(), PAYLOAD);
    }
}
/// Observe externally committed changes without adding executable schema.
/// data_version is compared only on this one long-lived connection; it is not
/// a persisted operation counter or evidence against hostile snapshot replay.
struct StoreObserver(Connection);
impl StoreObserver {
    fn new(path: &Path) -> Self {
        Self(Connection::open(path).unwrap())
    }
    fn version(&self) -> i64 {
        self.0
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .unwrap()
    }
}
fn assert_changed_session(vault: &mut Vault, old: &SessionToken, receipt: &CredentialReceipt) {
    assert!(matches!(vault.read(old, FIRST), Err(Error::StaleSession)));
    assert_payloads(vault, &receipt.session);
}

#[test]
fn native_password_change_rewraps_without_record_or_index_work() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("credential-rewrap.sqlite");
    let (mut vault, old_session) = seeded(&path);
    let before = snapshot(&path);
    let changed = vault
        .change_password(&old_session, OLD, NEW, CHANGE)
        .unwrap();
    assert_no_record_work(&vault);
    assert_eq!(changed.receipt.generation, 3);
    let after = snapshot(&path);
    assert_unchanged_content(&before, &after);
    assert_ne!(before.descriptor, after.descriptor);
    assert_ne!(before.head, after.head);
    assert_eq!(&before.descriptor[..42], &after.descriptor[..42]);
    assert_ne!(&before.descriptor[42..58], &after.descriptor[42..58]);
    assert_changed_session(&mut vault, &old_session, &changed);
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    assert!(reopened.unlock(OLD).is_err());
    let fresh = reopened.unlock(NEW).unwrap();
    assert_payloads(&mut reopened, &fresh);
}

#[test]
fn native_kdf_upgrade_is_explicit_admitted_and_never_downgrades() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("kdf-upgrade.sqlite");
    let (mut vault, old_session) = seeded(&path);
    let observer = StoreObserver::new(&path);
    let initial_version = observer.version();
    let before = snapshot(&path);
    let changed = vault
        .upgrade_kdf(&old_session, OLD, target(), UPGRADE)
        .unwrap();
    assert_no_record_work(&vault);
    let committed_version = observer.version();
    assert_ne!(committed_version, initial_version);
    let after = snapshot(&path);
    assert_unchanged_content(&before, &after);
    assert_eq!(&before.descriptor[26..42], &after.descriptor[26..42]);
    assert_eq!(
        u32::from_be_bytes(after.descriptor[18..22].try_into().unwrap()),
        target().passes()
    );
    assert_changed_session(&mut vault, &old_session, &changed);
    let replay = vault
        .upgrade_kdf(&changed.session, OLD, target(), UPGRADE)
        .unwrap();
    assert_no_record_work(&vault);
    assert_eq!(replay.receipt, changed.receipt);
    assert_eq!(snapshot(&path), after);
    assert_eq!(observer.version(), committed_version);
    for weaker_or_equal in [KdfProfile::baseline(), target()] {
        assert!(vault
            .upgrade_kdf(&changed.session, OLD, weaker_or_equal, [0x45; 16])
            .is_err());
        assert_eq!(snapshot(&path), after);
    }
    // Password change retains the stronger current costs, rather than silently
    // restoring the old baseline while replacing the credential.
    let password = vault
        .change_password(&changed.session, OLD, NEW, CHANGE)
        .unwrap();
    let changed_password = snapshot(&path);
    assert_eq!(
        &after.descriptor[14..26],
        &changed_password.descriptor[14..26]
    );
    assert_unchanged_content(&before, &changed_password);
    assert_payloads(&mut vault, &password.session);
    vault.lock();
    drop(vault);
    assert!(Vault::diagnostic_open(&path, limits()).is_err());
    let mut reopened = Vault::diagnostic_open_with_kdf_policy(&path, limits(), policy()).unwrap();
    assert!(reopened.unlock(OLD).is_err());
    let fresh = reopened.unlock(NEW).unwrap();
    assert_payloads(&mut reopened, &fresh);
}

#[test]
fn native_credential_rejection_preserves_accepted_state() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("credential-rejection.sqlite");
    // The default host policy admits only the original profile.
    let mut vault = Vault::diagnostic_create(&path, OLD, limits()).unwrap();
    let token = vault.unlock(OLD).unwrap();
    vault
        .save(&token, FIRST, None, META, PAYLOAD, [1; 16])
        .unwrap();
    let before = snapshot(&path);
    assert!(vault.upgrade_kdf(&token, OLD, target(), UPGRADE).is_err());
    assert_no_record_work(&vault);
    assert_eq!(vault.last_metrics().head_bytes_read, 0);
    assert_eq!(snapshot(&path), before);
    assert!(vault
        .change_password(&token, b"wrong password", NEW, CHANGE)
        .is_err());
    assert_eq!(snapshot(&path), before);
    assert_eq!(
        vault.read(&token, FIRST).unwrap().payload.as_slice(),
        PAYLOAD
    );
    let huge = KdfProfile::argon2id(u32::MAX - 3, u32::MAX).unwrap();
    assert!(vault.upgrade_kdf(&token, OLD, huge, [0x46; 16]).is_err());
    assert_no_record_work(&vault);
    assert_eq!(vault.last_metrics().head_bytes_read, 0);
    assert_eq!(snapshot(&path), before);
    assert!(KdfProfile::argon2id(KdfProfile::baseline().memory_kib(), 2).is_err());
    assert_eq!(
        vault.read(&token, FIRST).unwrap().payload.as_slice(),
        PAYLOAD
    );
    let denied = scratch.path().join("unadmitted-creation.sqlite");
    assert!(Vault::diagnostic_create_with_kdf_policy(
        &denied,
        OLD,
        limits(),
        KdfPolicy::new(vec![target()]).unwrap()
    )
    .is_err());
    assert!(!denied.exists());
}

#[test]
fn native_password_change_rollback_unknown_reconcile_and_retry() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("password-outcomes.sqlite");
    let (mut vault, old_session) = seeded(&path);
    let observer = StoreObserver::new(&path);
    let initial_version = observer.version();
    let before = snapshot(&path);
    assert!(matches!(
        vault.change_password_with_fault(&old_session, OLD, NEW, CHANGE, CommitFault::BeforeCommit),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(snapshot(&path), before);
    assert_eq!(observer.version(), initial_version);
    assert_payloads(&mut vault, &old_session);
    assert!(matches!(
        vault.change_password_with_fault(&old_session, OLD, NEW, CHANGE, CommitFault::AfterCommit),
        Err(Error::OutcomeUnknown { request_id }) if request_id == CHANGE
    ));
    let durable = snapshot(&path);
    assert_unchanged_content(&before, &durable);
    assert_ne!(observer.version(), initial_version);
    assert!(matches!(
        vault.read(&old_session, FIRST),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        vault.change_password(&old_session, OLD, NEW, [0x34; 16]),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        vault.reconcile_latest(&old_session, [0xff; 16]),
        Err(Error::Conflict)
    ));
    // A failed audit cannot remove the unknown-outcome barrier.
    let (hash, body) = &durable.nodes[0];
    let mut corrupt = body.clone();
    corrupt[0] ^= 1;
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE index_nodes SET bytes=?1 WHERE hash=?2",
            params![corrupt, hash],
        )
        .unwrap();
    assert!(vault.reconcile_latest(&old_session, CHANGE).is_err());
    assert!(matches!(
        vault.read(&old_session, FIRST),
        Err(Error::OutcomeUnknown { .. })
    ));
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE index_nodes SET bytes=?1 WHERE hash=?2",
            params![body, hash],
        )
        .unwrap();
    let receipt = vault.reconcile_latest(&old_session, CHANGE).unwrap();
    let fresh = vault.current_session().unwrap();
    assert!(matches!(
        vault.read(&old_session, FIRST),
        Err(Error::StaleSession)
    ));
    assert_payloads(&mut vault, &fresh);
    let before_retry_version = observer.version();
    let retry = vault.change_password(&fresh, OLD, NEW, CHANGE).unwrap();
    assert_no_record_work(&vault);
    assert_eq!(retry.receipt, receipt);
    assert_eq!(snapshot(&path), durable);
    assert_eq!(observer.version(), before_retry_version);
    assert!(matches!(
        vault.change_password(&fresh, OLD, b"different new password", CHANGE),
        Err(Error::OperationIdReuse)
    ));
    assert_eq!(snapshot(&path), durable);
    assert_eq!(vault.reconcile_latest(&fresh, CHANGE).unwrap(), receipt);
    assert_payloads(&mut vault, &fresh);
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    assert!(reopened.unlock(OLD).is_err());
    let fresh = reopened.unlock(NEW).unwrap();
    assert_payloads(&mut reopened, &fresh);
}

#[test]
fn native_kdf_upgrade_rollback_and_unknown_reconciliation() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("kdf-outcomes.sqlite");
    let (mut vault, old_session) = seeded(&path);
    let before = snapshot(&path);
    assert!(matches!(
        vault.upgrade_kdf_with_fault(
            &old_session,
            OLD,
            target(),
            UPGRADE,
            CommitFault::BeforeCommit
        ),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(snapshot(&path), before);
    assert_payloads(&mut vault, &old_session);
    assert!(matches!(
        vault.upgrade_kdf_with_fault(&old_session, OLD, target(), UPGRADE, CommitFault::AfterCommit),
        Err(Error::OutcomeUnknown { request_id }) if request_id == UPGRADE
    ));
    assert!(matches!(
        vault.read(&old_session, FIRST),
        Err(Error::OutcomeUnknown { .. })
    ));
    let receipt = vault.reconcile_latest(&old_session, UPGRADE).unwrap();
    let fresh = vault.current_session().unwrap();
    assert_eq!(receipt.generation, 3);
    assert_payloads(&mut vault, &fresh);
    assert!(matches!(
        vault.read(&old_session, FIRST),
        Err(Error::StaleSession)
    ));
    let durable = snapshot(&path);
    assert_unchanged_content(&before, &durable);
    vault.lock();
    drop(vault);
    let mut reopened = Vault::diagnostic_open_with_kdf_policy(&path, limits(), policy()).unwrap();
    let fresh = reopened.unlock(OLD).unwrap();
    assert_payloads(&mut reopened, &fresh);
}

#[test]
fn native_credential_rewrap_keeps_old_snapshots_decryptable() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("current.sqlite");
    let backup = scratch.path().join("old-snapshot.sqlite");
    let (mut vault, old_session) = seeded(&path);
    std::fs::copy(&path, &backup).unwrap();
    vault
        .change_password(&old_session, OLD, NEW, CHANGE)
        .unwrap();
    vault.lock();
    let mut old = Vault::diagnostic_open(&backup, limits()).unwrap();
    let old_session = old.unlock(OLD).unwrap();
    assert_payloads(&mut old, &old_session);
    let mut current = Vault::diagnostic_open(&path, limits()).unwrap();
    assert!(current.unlock(OLD).is_err());
    let fresh = current.unlock(NEW).unwrap();
    assert_payloads(&mut current, &fresh);
}

#[test]
fn native_credential_change_rejects_a_stale_writer() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("stale-credential-writer.sqlite");
    let (mut first, first_session) = seeded(&path);
    let mut stale = Vault::diagnostic_open_with_kdf_policy(&path, limits(), policy()).unwrap();
    let stale_session = stale.unlock(OLD).unwrap();
    first
        .change_password(&first_session, OLD, NEW, CHANGE)
        .unwrap();
    let accepted = snapshot(&path);
    assert!(stale.read(&stale_session, FIRST).is_err());
    assert!(stale
        .change_password(&stale_session, OLD, b"stale writer password", [0x55; 16])
        .is_err());
    assert_eq!(snapshot(&path), accepted);
    let current = first.current_session().unwrap();
    assert_payloads(&mut first, &current);
    stale.lock();
    drop(stale);
    let mut reopened = Vault::diagnostic_open(&path, limits()).unwrap();
    let current = reopened.unlock(NEW).unwrap();
    assert_payloads(&mut reopened, &current);
}

#[test]
fn exact_beta3_workspace_survives_password_change_and_kdf_upgrade() {
    use datafog_core::{
        workspace::{
            Conversation, ConversationInput, Head, OperationContext, ReviewInput, SendStatus,
            Workspace, WorkspaceFinding, MAX_BUNDLE_BYTES,
        },
        TextRange,
    };
    use zeroize::Zeroizing;

    fn binding(namespace: [u8; 16], parent: Head, saved: Head) -> Vec<u8> {
        let mut bytes = b"datafog-core:workspace:0.5.0-beta.3\0".to_vec();
        bytes.extend_from_slice(&namespace);
        for head in [parent, saved] {
            bytes.extend_from_slice(&head.revision.to_le_bytes());
            bytes.extend_from_slice(&head.commit_id);
        }
        bytes
    }
    let vector = |id: &str| -> Vec<u8> {
        let row = include_str!("../../../conformance/password-vectors.tsv")
            .lines()
            .find(|line| line.split('\t').nth(1) == Some(id))
            .unwrap();
        let encoded = row.split('\t').nth(3).unwrap();
        (0..encoded.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16).unwrap())
            .collect()
    };
    let old_password = vector("unicode_nul");
    let new_password = vector("decomposed_nul");
    fogvault::password_utf8_bytes(&old_password).unwrap();
    fogvault::password_utf8_bytes(&new_password).unwrap();
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("beta3-credential-lifecycle.sqlite");
    let namespace = [0x61; 16];
    let conversation_id = [0x62; 16];
    let surface = "synthetic-credential-test-no-network";
    let site_id = "synthetic-credential-conversation";
    let mut workspace = Workspace::create(namespace, [0x63; 16]).unwrap();
    let initial = workspace.head().unwrap();
    let initial_binding = binding(namespace, initial, initial);
    let host_limits = Limits {
        // Exact published beta.3 consumer bound; no fabricated Core bundle.
        max_payload_bytes: MAX_BUNDLE_BYTES,
        max_metadata_bytes: initial_binding.len(),
        max_records: 1,
    };
    let mut vault =
        Vault::diagnostic_create_with_kdf_policy(&path, &old_password, host_limits, policy())
            .unwrap();
    let nul = old_password.iter().position(|byte| *byte == 0).unwrap();
    assert!(vault.unlock(&old_password[..nul]).is_err());
    assert!(vault.unlock("  e\u{301}\0🦀\r\n".as_bytes()).is_err());
    let token = vault.unlock(&old_password).unwrap();
    let initial_bundle = Zeroizing::new(workspace.export_bundle().unwrap());
    vault
        .save(
            &token,
            FIRST,
            None,
            &initial_binding,
            &initial_bundle,
            [0x70; 16],
        )
        .unwrap();

    let email = "credential-owner@example.test";
    let text = format!("Please contact {email} about this synthetic vault.");
    let start = text.find(email).unwrap();
    let findings = [WorkspaceFinding::new(
        "EMAIL",
        email,
        TextRange {
            start,
            end: start + email.len(),
        },
    )];
    let mut send = workspace
        .prepare_conversation_send(
            &[ConversationInput {
                input: ReviewInput {
                    text: &text,
                    scanner_findings: &findings,
                    user_selections: &[],
                    corrections: &[],
                },
                conversation: Conversation {
                    id: conversation_id,
                    surface: surface.to_owned(),
                    site_id: None,
                    site_id_byte_budget: site_id.len(),
                },
            }],
            OperationContext {
                id: [0x64; 16],
                occurred_at_ms: 1,
            },
        )
        .unwrap();
    let preview = Zeroizing::new(send.preview().unwrap().text.clone());
    assert!(preview.contains("[[EMAIL_"));
    assert!(!preview.contains(email));
    let send_parent = send.expected_head().unwrap();
    let send_head = send.candidate_head().unwrap();
    let intent = send.send_intents().unwrap()[0];
    assert_eq!(workspace.head().unwrap(), initial);
    let send_binding = binding(namespace, send_parent, send_head);
    // The host explicitly approves this synthetic preview. Persist the complete
    // candidate first; only a successful vault receipt permits Core activation.
    let saved_send = vault
        .save(
            &token,
            FIRST,
            Some(1),
            &send_binding,
            send.export_candidate_bundle().unwrap(),
            [0x71; 16],
        )
        .unwrap();
    assert_eq!(saved_send.request_id, [0x71; 16]);
    assert_eq!(workspace.head().unwrap(), initial);
    workspace
        .activate_saved(&mut send, send_parent, send_head)
        .unwrap();
    assert_eq!(
        workspace.send_intent_status(intent).unwrap(),
        SendStatus::Pending
    );

    // This is a synthetic host observation, never a network send.
    let mut observed = workspace
        .prepare_observed_send(
            intent,
            conversation_id,
            surface,
            site_id,
            OperationContext {
                id: [0x65; 16],
                occurred_at_ms: 2,
            },
        )
        .unwrap();
    let final_parent = observed.expected_head().unwrap();
    let final_head = observed.candidate_head().unwrap();
    let final_binding = binding(namespace, final_parent, final_head);
    let saved_observed = vault
        .save(
            &token,
            FIRST,
            Some(2),
            &final_binding,
            observed.export_candidate_bundle().unwrap(),
            [0x72; 16],
        )
        .unwrap();
    assert_eq!(saved_observed.request_id, [0x72; 16]);
    assert_eq!(workspace.head().unwrap(), send_head);
    workspace
        .activate_saved(&mut observed, final_parent, final_head)
        .unwrap();
    assert_eq!(
        workspace
            .restore_in_conversation(&preview, conversation_id)
            .unwrap(),
        text
    );
    let expected_bundle = Zeroizing::new(workspace.export_bundle().unwrap());
    assert_eq!(workspace.namespace().unwrap(), namespace);
    assert_eq!(workspace.head().unwrap(), final_head);
    // The host closes Core-owned handles before replacing the session authority.
    workspace.close();
    assert!(workspace.export_bundle().is_err());
    let before = snapshot(&path);

    let password = vault
        .change_password(&token, &old_password, &new_password, CHANGE)
        .unwrap();
    assert_no_record_work(&vault);
    let upgraded = vault
        .upgrade_kdf(&password.session, &new_password, target(), UPGRADE)
        .unwrap();
    assert_no_record_work(&vault);
    assert_unchanged_content(&before, &snapshot(&path));
    assert!(matches!(
        vault.read(&token, FIRST),
        Err(Error::StaleSession)
    ));
    assert!(matches!(
        vault.read(&password.session, FIRST),
        Err(Error::StaleSession)
    ));
    vault.lock();
    assert!(vault.read(&upgraded.session, FIRST).is_err());
    drop(vault);

    let mut reopened =
        Vault::diagnostic_open_with_kdf_policy(&path, host_limits, policy()).unwrap();
    assert!(reopened.unlock(&old_password).is_err());
    let token = reopened.unlock(&new_password).unwrap();
    let record = reopened.read(&token, FIRST).unwrap();
    assert_eq!(record.revision, 3);
    // Both revisions AND 16-byte commit IDs are preserved in the authenticated
    // binding; vault generation is independent from the Core Head revision.
    assert_eq!(record.metadata.as_slice(), final_binding);
    assert_eq!(record.payload.as_slice(), expected_bundle.as_slice());
    let mut restored = Workspace::open_bundle(&record.payload).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), final_head);
    assert_eq!(
        restored
            .restore_in_conversation(&preview, conversation_id)
            .unwrap(),
        text
    );
    assert_eq!(
        restored.conversation_for_site(surface, site_id).unwrap(),
        conversation_id
    );
    assert_eq!(
        restored.send_intent_status(intent).unwrap(),
        SendStatus::ObservedSent
    );
    assert_eq!(
        restored
            .conversation(conversation_id)
            .unwrap()
            .pending_intents,
        0
    );
    let round_trip = Zeroizing::new(restored.export_bundle().unwrap());
    assert_eq!(round_trip.as_slice(), expected_bundle.as_slice());
    restored.close();
    reopened.lock();
}
