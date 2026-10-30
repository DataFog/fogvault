//! Disposable consumer proof against the exact published DataFog Core beta.3.
//! The host owns approval, encrypted persistence and coupling Core close to vault lock.
//! Synthetic inputs and copied outputs remain caller-owned; this proves revocation, not erasure.
#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use std::error::Error as StdError;
use std::io;

use datafog_core::{
    workspace::{
        Conversation, ConversationInput, Head, OperationContext, ReviewInput, SendStatus,
        Workspace, WorkspaceFinding, MAX_BUNDLE_BYTES,
    },
    TextRange,
};
use fogvault_disposable_prototype::{
    CommitFault, Error as VaultError, Limits, SecretRecord, Vault,
};
use tempfile::tempdir;
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

const PASSWORD: &[u8] = b"synthetic consumer prototype password; never real credentials";
const METADATA_DOMAIN: &[u8] = b"datafog-core:workspace:0.5.0-beta.3\0";
const HEAD_BYTES: usize = 8 + 16;
const METADATA_BYTES: usize = METADATA_DOMAIN.len() + 16 + HEAD_BYTES * 2;

#[derive(Clone, Copy, PartialEq, Eq)]
struct HostBinding {
    namespace: [u8; 16],
    parent: Head,
    saved: Head,
}

impl HostBinding {
    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(METADATA_BYTES);
        bytes.extend_from_slice(METADATA_DOMAIN);
        bytes.extend_from_slice(&self.namespace);
        for head in [self.parent, self.saved] {
            bytes.extend_from_slice(&head.revision.to_le_bytes());
            bytes.extend_from_slice(&head.commit_id);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> TestResult<Self> {
        if bytes.len() != METADATA_BYTES || !bytes.starts_with(METADATA_DOMAIN) {
            return Err(invalid_binding());
        }
        let mut cursor = METADATA_DOMAIN.len();
        let namespace = bytes[cursor..cursor + 16].try_into()?;
        cursor += 16;
        let mut read_head = || -> TestResult<Head> {
            let revision = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into()?);
            cursor += 8;
            let commit_id = bytes[cursor..cursor + 16].try_into()?;
            cursor += 16;
            Ok(Head {
                revision,
                commit_id,
            })
        };
        let parent = read_head()?;
        let saved = read_head()?;
        Ok(Self {
            namespace,
            parent,
            saved,
        })
    }
}

fn invalid_binding() -> Box<dyn StdError> {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "consumer workspace binding mismatch",
    )
    .into()
}

fn checked_workspace(record: &SecretRecord, expected: HostBinding) -> TestResult<Workspace> {
    let stored = HostBinding::decode(&record.metadata)?;
    if stored != expected {
        return Err(invalid_binding());
    }
    let workspace = Workspace::open_bundle(&record.payload)?;
    if workspace.namespace()? != expected.namespace || workspace.head()? != expected.saved {
        return Err(invalid_binding());
    }
    Ok(workspace)
}

fn random_id() -> [u8; 16] {
    loop {
        let mut id = [0; 16];
        getrandom::fill(&mut id).expect("OS CSPRNG must supply synthetic fixture IDs");
        if id != [0; 16] {
            return id;
        }
    }
}

fn limits() -> Limits {
    Limits {
        // Payload authority: exact beta.3 Workspace::MAX_BUNDLE_BYTES.
        max_payload_bytes: MAX_BUNDLE_BYTES,
        // Metadata and record count derive only from this single-workspace fixture.
        max_metadata_bytes: METADATA_BYTES,
        max_records: 1,
    }
}

fn fixture() -> (String, Vec<WorkspaceFinding>) {
    let value = "alice@example.test";
    let text = format!("🦀 Contact {value} about the synthetic example.");
    let start = text.find(value).expect("fixture contains its finding");
    let finding = WorkspaceFinding::new(
        "EMAIL",
        value,
        TextRange {
            start,
            end: start + value.len(),
        },
    );
    (text, vec![finding])
}

#[test]
fn beta3_workspace_conversation_survives_encrypted_lock_and_reopen() -> TestResult {
    let scratch = tempdir()?;
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite3");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits())?;
    let token = vault.unlock(PASSWORD)?;
    let namespace = random_id();
    let record_id = random_id();
    let mut workspace = Workspace::create(namespace, random_id())?;
    let initial_head = workspace.head()?;
    let initial_binding = HostBinding {
        namespace,
        parent: initial_head,
        saved: initial_head,
    };
    let initial_bundle = Zeroizing::new(workspace.export_bundle()?);
    vault.save(
        &token,
        record_id,
        None,
        &initial_binding.encode(),
        &initial_bundle,
        random_id(),
    )?;
    let initial_record = vault.read(&token, record_id)?;

    let (text, findings) = fixture();
    let logical_id = random_id();
    let site_id = "synthetic-conversation-id";
    let surface = "synthetic-no-network-surface";
    let mut send_plan = workspace.prepare_conversation_send(
        &[ConversationInput {
            input: ReviewInput {
                text: &text,
                scanner_findings: &findings,
                user_selections: &[],
                corrections: &[],
            },
            conversation: Conversation {
                id: logical_id,
                surface: surface.to_owned(),
                site_id: None,
                site_id_byte_budget: site_id.len(),
            },
        }],
        OperationContext {
            id: random_id(),
            occurred_at_ms: 1, // Synthetic fixture time, not an operational clock policy.
        },
    )?;
    let preview = Zeroizing::new(send_plan.preview()?.text.clone());
    assert!(preview.contains("[[EMAIL_"));
    assert!(!preview.contains("alice@example.test"));
    assert_eq!(workspace.head()?, initial_head);
    let send_binding = HostBinding {
        namespace,
        parent: send_plan.expected_head()?,
        saved: send_plan.candidate_head()?,
    };
    let intents = send_plan.send_intents()?;
    assert_eq!(intents.len(), 1);

    // This test explicitly approves its synthetic preview. Core does not provide UI approval.
    vault.save(
        &token,
        record_id,
        Some(initial_record.revision),
        &send_binding.encode(),
        send_plan.export_candidate_bundle()?,
        random_id(),
    )?;
    workspace.activate_saved(&mut send_plan, send_binding.parent, send_binding.saved)?;
    assert_eq!(
        workspace.send_intent_status(intents[0])?,
        SendStatus::Pending
    );
    assert!(workspace
        .restore_in_conversation(&preview, logical_id)
        .is_err());

    // A synthetic trusted-host observation exercises saved beta.3 send state; no message is sent.
    let mut observed = workspace.prepare_observed_send(
        intents[0],
        logical_id,
        surface,
        site_id,
        OperationContext {
            id: random_id(),
            occurred_at_ms: 2,
        },
    )?;
    let final_binding = HostBinding {
        namespace,
        parent: observed.expected_head()?,
        saved: observed.candidate_head()?,
    };
    let current = vault.read(&token, record_id)?;
    vault.save(
        &token,
        record_id,
        Some(current.revision),
        &final_binding.encode(),
        observed.export_candidate_bundle()?,
        random_id(),
    )?;
    workspace.activate_saved(&mut observed, final_binding.parent, final_binding.saved)?;
    assert!(workspace.restore_in_conversation(&preview, logical_id)? == text);

    let mut stale_plan = workspace.prepare(&text, &findings, random_id())?;
    let mut stale_stream =
        workspace.buffered_restore(datafog_core::workspace::RestoreEncoding::Utf8)?;
    stale_stream.feed(preview.as_bytes())?;
    workspace.close();
    vault.lock();
    assert!(stale_plan.export_candidate_bundle().is_err());
    assert!(stale_stream.finalize().is_err());
    assert!(workspace.restore(&preview).is_err());
    assert!(vault.read(&token, record_id).is_err());
    stale_plan.discard();
    stale_stream.close();
    drop(workspace);
    drop(vault);

    let mut reopened = Vault::diagnostic_open(&path, limits())?;
    assert!(reopened.unlock(b"incorrect synthetic password").is_err());
    let reopened_token = reopened.unlock(PASSWORD)?;
    let saved_record = reopened.read(&reopened_token, record_id)?;
    let mut restored_workspace = checked_workspace(&saved_record, final_binding)?;
    assert!(restored_workspace.restore_in_conversation(&preview, logical_id)? == text);
    assert_eq!(
        restored_workspace.conversation(logical_id)?.pending_intents,
        0
    );
    assert_eq!(
        restored_workspace.conversation(logical_id)?.issued_markers,
        1
    );
    assert_eq!(
        restored_workspace.conversation_for_site(surface, site_id)?,
        logical_id
    );
    assert_eq!(
        restored_workspace.send_intent_status(intents[0])?,
        SendStatus::ObservedSent
    );
    let round_trip = Zeroizing::new(restored_workspace.export_bundle()?);
    assert!(round_trip.as_slice() == saved_record.payload.as_slice());

    let mut wrong_commit = final_binding;
    wrong_commit.saved.commit_id = random_id();
    assert_eq!(wrong_commit.saved.revision, final_binding.saved.revision);
    assert!(checked_workspace(&saved_record, wrong_commit).is_err());
    let mut wrong_namespace = final_binding;
    wrong_namespace.namespace = random_id();
    assert!(checked_workspace(&saved_record, wrong_namespace).is_err());
    restored_workspace.close();
    reopened.lock();
    Ok(())
}

#[test]
fn beta3_host_does_not_activate_failed_or_unreconciled_save() -> TestResult {
    let scratch = tempdir()?;
    let path = scratch.path().join("PROTOTYPE-WIPE-ME.sqlite3");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits())?;
    let token = vault.unlock(PASSWORD)?;
    let namespace = random_id();
    let record_id = random_id();
    let mut workspace = Workspace::create(namespace, random_id())?;
    let parent = workspace.head()?;
    let initial_binding = HostBinding {
        namespace,
        parent,
        saved: parent,
    };
    let initial_bundle = Zeroizing::new(workspace.export_bundle()?);
    let initial_receipt = vault.save(
        &token,
        record_id,
        None,
        &initial_binding.encode(),
        &initial_bundle,
        random_id(),
    )?;
    let initial_record = vault.read(&token, record_id)?;
    let (text, findings) = fixture();
    let mut plan = workspace.prepare(&text, &findings, random_id())?;
    let preview = Zeroizing::new(plan.preview()?.text.clone());
    let binding = HostBinding {
        namespace,
        parent: plan.expected_head()?,
        saved: plan.candidate_head()?,
    };
    assert_eq!(binding.parent, parent);

    let failure = vault.save_with_fault(
        &token,
        record_id,
        Some(initial_record.revision),
        &binding.encode(),
        plan.export_candidate_bundle()?,
        random_id(),
        CommitFault::BeforeCommit,
    );
    assert!(matches!(failure, Err(VaultError::InjectedFailure)));
    assert_eq!(workspace.head()?, parent);
    assert!(workspace.restore(&preview).is_err());
    let unchanged = vault.read(&token, record_id)?;
    assert_eq!(unchanged.revision, initial_record.revision);
    assert!(unchanged.payload.as_slice() == initial_bundle.as_slice());

    let lost_acknowledgment_id = random_id();
    let uncertain = vault.save_with_fault(
        &token,
        record_id,
        Some(initial_record.revision),
        &binding.encode(),
        plan.export_candidate_bundle()?,
        lost_acknowledgment_id,
        CommitFault::AfterCommit,
    );
    assert!(matches!(
        uncertain,
        Err(VaultError::OutcomeUnknown { request_id }) if request_id == lost_acknowledgment_id
    ));
    assert_eq!(workspace.head()?, parent);
    assert!(workspace.restore(&preview).is_err());

    let reconciled = vault.reconcile_latest(&token, lost_acknowledgment_id)?;
    assert_eq!(reconciled.request_id, lost_acknowledgment_id);
    assert_eq!(reconciled.generation, initial_receipt.generation + 1);
    let saved = vault.read(&token, record_id)?;
    let mut candidate = checked_workspace(&saved, binding)?;
    assert_eq!(candidate.head()?, binding.saved);
    candidate.close();
    workspace.activate_saved(&mut plan, binding.parent, binding.saved)?;
    assert!(workspace.restore(&preview)? == text);
    assert!(plan.export_candidate_bundle().is_err());
    workspace.close();
    drop(candidate);
    vault.lock();
    Ok(())
}
