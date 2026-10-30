#![cfg(all(feature = "native", not(target_arch = "wasm32")))]
use fogvault::{
    AccessAdmission, AccessChange, AccessPath, AccessProfile, KdfPolicy, KeyProvider,
    ProviderContext, ProviderError, ProviderIdentity, ProviderResult, RecoveryKey,
};
use fogvault_disposable_prototype::{crypto, CommitFault, Error, Limits, Vault};
use rusqlite::Connection;
use tempfile::tempdir;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"synthetic native access password";
const NEW: &[u8] = b"synthetic recovery replacement password";
const ID: [u8; 16] = [0x91; 16];
fn identity(n: u8) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [n; 16],
        key_id: [n + 1; 16],
        device_bound: true,
        nonexportable: true,
    }
}
fn admission() -> AccessAdmission {
    // Exact largest selected fixture:108+2*(64+72+112)+96=700 bytes.
    AccessAdmission {
        allowed_profiles: vec![
            AccessProfile::Portable,
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ],
        providers: vec![identity(1), identity(3), identity(5)],
        max_descriptor_bytes: 700,
        max_device_slots: 2,
        max_provider_blob_bytes: 72,
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 16 * 1024 * 1024,
        max_metadata_bytes: 128,
        max_records: 2,
    }
}
#[derive(Default)]
struct Provider {
    unavailable: bool,
}
impl KeyProvider for Provider {
    // Synthetic operation oracle only; this declaration is not hardware evidence.
    fn capability_kind(
        &self,
        _identity: &fogvault::ProviderIdentity,
    ) -> fogvault::ProviderCapabilityKind {
        fogvault::ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, c: &ProviderContext, s: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        if self.unavailable {
            return Err(ProviderError::Unavailable);
        }
        crypto::seal(&[0x53; 32], &c.authenticated_bytes(), s).map_err(|_| ProviderError::Failure)
    }
    fn unwrap_seed(
        &mut self,
        c: &ProviderContext,
        w: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        if self.unavailable {
            return Err(ProviderError::Unavailable);
        }
        let bytes = crypto::open(&[0x53; 32], &c.authenticated_bytes(), w)
            .map_err(|_| ProviderError::InvalidResponse)?;
        Ok(Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::InvalidResponse)?,
        ))
    }
}
fn content(path: &std::path::Path) -> Vec<Vec<u8>> {
    let db = Connection::open(path).unwrap();
    let mut result = Vec::new();
    for query in [
        "SELECT envelope FROM records ORDER BY id",
        "SELECT bytes FROM index_nodes ORDER BY hash",
    ] {
        let mut statement = db.prepare(query).unwrap();
        result.extend(
            statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|row| row.unwrap()),
        );
    }
    result
}

#[test]
fn native_access_recovery_preserves_exact_beta3_workspace_and_content() {
    use datafog_core::workspace::Workspace;
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("p3-recovery.sqlite");
    let mut provider = Provider::default();
    let (prepared, recovery) = Vault::diagnostic_prepare_access_creation(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(),
        AccessProfile::PasswordAndDevice,
        &[identity(1), identity(3)],
        true,
        &mut provider,
    )
    .unwrap();
    let kit = recovery.unwrap().export();
    assert_eq!(kit.len(), 80); // Owner can retain it BEFORE publication.
    let mut vault = prepared.publish(&path, CommitFault::None).unwrap();
    assert!(Vault::diagnostic_open(&path, limits()).is_err()); // No implicit admission of a new header/profile.
    assert!(vault
        .unlock_access(AccessPath::Password(PASSWORD), &mut provider)
        .is_err());
    let slot = vault.access_info().unwrap().device_slots[0].0;
    assert!(vault
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: None
            },
            &mut provider
        )
        .is_err());
    let token = vault
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD),
            },
            &mut provider,
        )
        .unwrap();
    let namespace = [0x71; 16];
    let mut workspace = Workspace::create(namespace, [0x72; 16]).unwrap();
    let head = workspace.head().unwrap();
    let bundle = Zeroizing::new(workspace.export_bundle().unwrap());
    let mut binding = namespace.to_vec();
    binding.extend_from_slice(&head.revision.to_be_bytes());
    binding.extend_from_slice(&head.commit_id);
    vault
        .save(&token, ID, None, &binding, &bundle, [1; 16])
        .unwrap();
    let before = content(&path);
    workspace.close();
    assert!(workspace.head().is_err()); // Host closes live Core authority before vault lock.
    vault.lock();
    provider.unavailable = true;
    assert!(vault
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD)
            },
            &mut provider
        )
        .is_err());
    let recovery = RecoveryKey::import(&kit).unwrap();
    vault.recover_access(&recovery).unwrap();
    assert!(vault.current_session().is_err());
    assert!(vault.read(&token, ID).is_err());
    provider.unavailable = false;
    let (draft, key) = vault
        .prepare_recovery_maintenance(
            &recovery,
            NEW,
            AccessProfile::PasswordAndDevice,
            &[identity(5)],
            true,
            &mut provider,
            [2; 16],
        )
        .unwrap();
    let _kit_before_attempt = key.unwrap().export();
    assert!(matches!(
        vault.commit_access_change(draft, [2; 16], CommitFault::BeforeCommit),
        Err(Error::InjectedFailure)
    ));
    assert_eq!(content(&path), before);
    assert!(vault.current_session().is_err());
    let (draft, key) = vault
        .prepare_recovery_maintenance(
            &recovery,
            NEW,
            AccessProfile::PasswordAndDevice,
            &[identity(5)],
            true,
            &mut provider,
            [2; 16],
        )
        .unwrap();
    let replacement_kit = key.unwrap().export();
    assert!(matches!(
        vault.commit_access_change(draft, [2; 16], CommitFault::AfterCommit),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(vault.current_session().is_err());
    vault.reconcile_access_latest([2; 16]).unwrap();
    let fresh = vault.current_session().unwrap();
    assert_eq!(content(&path), before);
    let record = vault.read(&fresh, ID).unwrap();
    assert_eq!(record.metadata.as_slice(), binding);
    assert_eq!(record.payload.as_slice(), bundle.as_slice());
    let mut restored = Workspace::open_bundle(record.payload.as_slice()).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), head);
    restored.close();
    workspace.close();
    vault.lock();
    assert!(vault.recover_access(&recovery).is_err());
    drop(vault);
    let mut reopened =
        Vault::diagnostic_open_with_access(&path, limits(), KdfPolicy::baseline(), admission())
            .unwrap();
    let slot = reopened.access_info().unwrap().device_slots[0].0;
    let fresh = reopened
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(NEW),
            },
            &mut provider,
        )
        .unwrap();
    assert_eq!(
        reopened.read(&fresh, ID).unwrap().payload.as_slice(),
        bundle.as_slice()
    );
    reopened.lock();
    reopened
        .recover_access(&RecoveryKey::import(&replacement_kit).unwrap())
        .unwrap();
    assert!(reopened.current_session().is_err());
}

#[test]
fn native_p2_access_promotion_enrollment_and_removal_are_header_only() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("promotion.sqlite");
    let mut provider = Provider::default();
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"metadata", b"payload", [1; 16])
        .unwrap();
    let before = content(&path);
    vault.configure_access_admission(admission()).unwrap();
    let (draft, _) = vault
        .prepare_access_setup_maintenance(
            &token,
            PASSWORD,
            None,
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            false,
            &mut provider,
            admission(),
            [2; 16],
        )
        .unwrap();
    let receipt = vault
        .commit_access_change(draft, [2; 16], CommitFault::None)
        .unwrap();
    assert_eq!(content(&path), before);
    let (draft, _) = vault
        .prepare_access_maintenance(
            &receipt.session,
            AccessPath::Password(PASSWORD),
            AccessChange::EnrollDevice(identity(3)),
            &mut provider,
            [3; 16],
        )
        .unwrap();
    let receipt = vault
        .commit_access_change(draft, [3; 16], CommitFault::None)
        .unwrap();
    assert_eq!(content(&path), before);
    let slots = vault.access_info().unwrap().device_slots;
    let (draft, _) = vault
        .prepare_access_maintenance(
            &receipt.session,
            AccessPath::Password(PASSWORD),
            AccessChange::RemoveDevice(slots[1].0),
            &mut provider,
            [4; 16],
        )
        .unwrap();
    let receipt = vault
        .commit_access_change(draft, [4; 16], CommitFault::None)
        .unwrap();
    assert!(vault
        .prepare_access_maintenance(
            &receipt.session,
            AccessPath::Password(PASSWORD),
            AccessChange::RemoveDevice(slots[0].0),
            &mut provider,
            [5; 16]
        )
        .is_err());
    let draft = vault
        .prepare_access_password_change(
            &receipt.session,
            AccessPath::Password(PASSWORD),
            NEW,
            fogvault::KdfProfile::baseline(),
            &mut provider,
            [6; 16],
        )
        .unwrap();
    let receipt = vault
        .commit_access_change(draft, [6; 16], CommitFault::None)
        .unwrap();
    assert_eq!(content(&path), before);
    assert_eq!(
        vault.read(&receipt.session, ID).unwrap().payload.as_slice(),
        b"payload"
    );
}

#[test]
fn native_prepared_creation_is_exclusive_and_unknown_outcomes_reconcile() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("create.sqlite");
    let aborted =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    assert!(matches!(
        aborted.publish(&path, CommitFault::BeforeCommit),
        Err(Error::InjectedFailure)
    ));
    assert!(!path.exists());
    let prepared =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    let receipt = prepared.receipt();
    assert!(matches!(
        prepared.publish(&path, CommitFault::AfterCommit),
        Err(Error::OutcomeUnknown { .. })
    ));
    let mut reconciled = Vault::diagnostic_reconcile_creation(
        &path,
        &receipt,
        limits(),
        KdfPolicy::baseline(),
        None,
    )
    .unwrap();
    assert!(reconciled.unlock(PASSWORD).is_ok());
    drop(reconciled);
    let mut wrong = receipt.clone();
    wrong.request_id = [0; 16];
    assert!(Vault::diagnostic_reconcile_creation(
        &path,
        &wrong,
        limits(),
        KdfPolicy::baseline(),
        None
    )
    .is_err());
    let other = Vault::diagnostic_prepare_creation(NEW, limits(), KdfPolicy::baseline()).unwrap();
    assert!(matches!(
        other.publish(&path, CommitFault::None),
        Err(Error::Exists)
    ));
    let prepared =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    prepared.revocation_handle().revoke();
    assert!(prepared
        .publish(scratch.path().join("revoked.sqlite"), CommitFault::None)
        .is_err());
}

#[test]
fn native_source_head_prevents_revision_aba_for_queued_intent() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("intent.sqlite");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let first = vault
        .save(&token, ID, None, b"", b"first incarnation", [1; 16])
        .unwrap();
    let removed = vault
        .delete_at(&token, first.head_digest, ID, 1, [2; 16])
        .unwrap();
    let next = vault
        .save_at(
            &token,
            removed.head_digest,
            ID,
            None,
            b"",
            b"new incarnation",
            [3; 16],
        )
        .unwrap();
    assert!(matches!(
        vault.delete_at(&token, first.head_digest, ID, 1, [4; 16]),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        vault.save_at(
            &token,
            first.head_digest,
            ID,
            Some(1),
            b"",
            b"stale intent",
            [5; 16]
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"new incarnation"
    );
    assert!(vault
        .delete_at(&token, next.head_digest, ID, 1, [6; 16])
        .is_ok());
}

#[test]
fn native_credential_commit_rejects_mismatched_request_before_storage_changes() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("request-binding.sqlite");
    let mut provider = Provider::default();
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"metadata", b"payload", [1; 16])
        .unwrap();
    let snapshot = || {
        let c = Connection::open(&path).unwrap();
        let header: (Vec<u8>, Vec<u8>) = c
            .query_row(
                "SELECT descriptor,head FROM vault_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        (header, content(&path))
    };
    let before = snapshot();
    let request = [0x31; 16];
    let other = [0x32; 16];
    let (draft, _) = vault
        .prepare_access_setup_maintenance(
            &token,
            PASSWORD,
            None,
            NEW,
            AccessProfile::Portable,
            &[],
            false,
            &mut provider,
            admission(),
            request,
        )
        .unwrap();
    assert!(matches!(
        vault.commit_access_change(draft, other, CommitFault::AfterCommit),
        Err(Error::Malformed(_))
    ));
    assert_eq!(snapshot(), before);
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"payload"
    );
    let (draft, _) = vault
        .prepare_access_setup_maintenance(
            &token,
            PASSWORD,
            None,
            NEW,
            AccessProfile::Portable,
            &[],
            false,
            &mut provider,
            admission(),
            request,
        )
        .unwrap();
    assert!(
        matches!(vault.commit_access_change(draft,request,CommitFault::AfterCommit),Err(Error::OutcomeUnknown{request_id}) if request_id==request)
    );
    let receipt = vault.reconcile_access_latest(request).unwrap();
    assert_eq!(receipt.request_id, request);
    assert_eq!(content(&path), before.1);
    vault.lock();
    assert!(vault
        .unlock_access(AccessPath::Password(PASSWORD), &mut provider)
        .is_err());
    let token = vault
        .unlock_access(AccessPath::Password(NEW), &mut provider)
        .unwrap();
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"payload"
    );
}
