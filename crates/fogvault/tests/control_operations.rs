//! The maintained ordinary owner builders reject mutations of public plans.
use fogvault::{
    AccessAdmission, AccessProfile, CommitPlan, ControlOperation, ControlState, Engine, Error,
    KdfPolicy, KdfProfile, Limits, NodeHash, NodeStore, PreparedControlOperation, Result,
    StoredRecord, WorkBudget,
};
use std::collections::BTreeMap;

#[derive(Default)]
struct Memory(BTreeMap<NodeHash, Vec<u8>>);
impl NodeStore for Memory {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        self.0.insert(hash, bytes.to_vec());
        Ok(())
    }
}
fn engine() -> Engine {
    let mut engine = Engine::create(
        b"control test passphrase",
        Limits {
            max_payload_bytes: 128,
            max_metadata_bytes: 64,
            max_records: 16,
        },
    )
    .unwrap();
    engine.activate_created().unwrap();
    engine
}
fn save(engine: &mut Engine, memory: &mut Memory) -> CommitPlan {
    engine
        .prepare_save(memory, [3; 16], None, b"meta", b"body", [4; 16], None)
        .unwrap()
}
fn accepted(owner: &PreparedControlOperation) -> ControlState {
    ControlState::register(owner.vault_id(), owner.registration_id(), owner.source())
}

#[test]
fn engine_control_save_rejects_mutated_public_plan_fields() {
    let mut engine = engine();
    let mut memory = Memory::default();
    let mut plan = save(&mut engine, &mut memory);
    let owner = engine.control_save([2; 16], &plan).unwrap();
    assert_eq!(owner.operation(), ControlOperation::Save);
    let prepared = accepted(&owner).prepare_ordinary(&owner).unwrap();
    let submitted = prepared.authorize_ordinary_submission(&owner).unwrap();
    assert_eq!(
        submitted.pending().unwrap().submission(),
        Some(owner.target())
    );

    macro_rules! change {
        ($field:expr, $value:expr) => {{
            let original = std::mem::replace(&mut $field, $value);
            assert!(matches!(
                engine.control_save([2; 16], &plan),
                Err(Error::Conflict)
            ));
            $field = original;
        }};
    }
    change!(plan.id, [9; 16]);
    change!(plan.revision, 9);
    change!(plan.receipt.request_id, [9; 16]);
    change!(plan.receipt.generation, 9);
    change!(plan.receipt.head_digest, [9; 32]);
    change!(plan.prior_head, vec![9; 129]);
    change!(plan.head_bytes, vec![9; 129]);
    change!(plan.envelope, vec![9; 200]);
    change!(plan.obsolete, vec![[9; 32]]);
    change!(plan.replay, true);
    assert_eq!(engine.control_save([2; 16], &plan).unwrap(), owner);
}

#[test]
fn engine_control_delete_and_credentials_bind_exact_pending_operations() {
    let mut engine = engine();
    let mut memory = Memory::default();
    let saved = save(&mut engine, &mut memory);
    engine.confirm_commit(&saved.head_bytes).unwrap();
    let mut deleted = engine
        .prepare_delete(
            &mut memory,
            saved.id,
            saved.revision,
            [5; 16],
            Some(StoredRecord {
                revision: saved.revision,
                envelope: &saved.envelope,
            }),
        )
        .unwrap();
    let owner = engine.control_delete([2; 16], &deleted).unwrap();
    assert_eq!(owner.operation(), ControlOperation::Delete);
    assert!(engine.control_save([2; 16], &saved).is_err());
    deleted.id[0] ^= 1;
    assert!(engine.control_delete([2; 16], &deleted).is_err());
    deleted.id[0] ^= 1;
    deleted.deleted_revision += 1;
    assert!(engine.control_delete([2; 16], &deleted).is_err());
    deleted.deleted_revision -= 1;
    deleted.obsolete.push([9; 32]);
    assert!(engine.control_delete([2; 16], &deleted).is_err());
    deleted.obsolete.pop();
    assert_eq!(engine.control_delete([2; 16], &deleted).unwrap(), owner);
    engine.confirm_commit(&deleted.head_bytes).unwrap();

    let draft = engine
        .draft_password_change(
            b"control test passphrase",
            b"replacement passphrase",
            [6; 16],
        )
        .unwrap();
    let mut credentials = engine.stage_credential_change(&draft).unwrap();
    let owner = engine.control_credentials([2; 16], &credentials).unwrap();
    assert_eq!(owner.operation(), ControlOperation::Credentials);
    assert_ne!(
        owner.source().descriptor_digest,
        owner.target().descriptor_digest
    );
    let last = credentials.descriptor_bytes.len() - 1;
    credentials.descriptor_bytes[last] ^= 1;
    assert!(engine.control_credentials([2; 16], &credentials).is_err());
    credentials.descriptor_bytes[last] ^= 1;
    credentials.prior_descriptor[0] ^= 1;
    assert!(engine.control_credentials([2; 16], &credentials).is_err());
    credentials.prior_descriptor[0] ^= 1;
    credentials.receipt.request_id[0] ^= 1;
    assert!(engine.control_credentials([2; 16], &credentials).is_err());
    credentials.receipt.request_id[0] ^= 1;
    assert_eq!(
        engine.control_credentials([2; 16], &credentials).unwrap(),
        owner
    );
}

#[test]
fn engine_control_rejects_replayed_unknown_and_revoked_work() {
    let mut engine = engine();
    let mut memory = Memory::default();
    let plan = save(&mut engine, &mut memory);
    engine.control_save([2; 16], &plan).unwrap();
    engine.mark_unknown().unwrap();
    assert!(matches!(
        engine.control_save([2; 16], &plan),
        Err(Error::OutcomeUnknown { request_id }) if request_id == [4; 16]
    ));
    engine.lock();
    assert!(matches!(
        engine.control_save([2; 16], &plan),
        Err(Error::Locked)
    ));

    let mut engine = self::engine();
    let mut memory = Memory::default();
    let plan = save(&mut engine, &mut memory);
    engine.confirm_commit(&plan.head_bytes).unwrap();
    let replay = engine
        .prepare_save(
            &mut memory,
            plan.id,
            None,
            b"meta",
            b"body",
            [4; 16],
            Some(StoredRecord {
                revision: plan.revision,
                envelope: &plan.envelope,
            }),
        )
        .unwrap();
    assert!(replay.replay);
    assert!(matches!(
        engine.control_save([2; 16], &replay),
        Err(Error::Conflict)
    ));
}

#[test]
fn engine_reopen_locked_retains_identity_and_revokes_before_failed_parse() {
    let mut engine = engine();
    let token = engine.current_session().unwrap();
    let original = engine.descriptor_bytes().to_vec();
    let mut memory = Memory::default();
    let plan = save(&mut engine, &mut memory);
    engine.mark_unknown().unwrap();
    engine.reopen_locked(&original).unwrap();
    assert!(!engine.is_unlocked());
    assert!(engine.head_bytes().is_empty());
    assert!(matches!(engine.check_session(&token), Err(Error::Locked)));
    assert_eq!(engine.descriptor_bytes(), original);
    assert!(matches!(
        engine.control_save([2; 16], &plan),
        Err(Error::Locked)
    ));

    let foreign = self::engine();
    assert!(matches!(
        engine.reopen_locked(foreign.descriptor_bytes()),
        Err(Error::Integrity)
    ));
    assert_eq!(engine.descriptor_bytes(), original);
    assert!(!engine.is_unlocked());
    assert!(engine.reopen_locked(b"not a descriptor").is_err());
    assert!(!engine.is_unlocked());
}

#[test]
fn engine_reopen_locked_retains_kdf_admission_and_shared_work_budget() {
    let upgraded = KdfProfile::argon2id(
        KdfProfile::baseline().memory_kib(),
        KdfProfile::baseline().passes() + 1,
    )
    .unwrap();
    let budget = WorkBudget::new(KdfProfile::baseline().memory_kib() as usize * 1024, 1).unwrap();
    let policy = KdfPolicy::new(vec![KdfProfile::baseline(), upgraded])
        .unwrap()
        .with_work_budget(budget.clone());
    let mut engine = Engine::create_with_kdf_policy(
        b"control test passphrase",
        Limits {
            max_payload_bytes: 128,
            max_metadata_bytes: 64,
            max_records: 16,
        },
        policy,
    )
    .unwrap();
    engine.activate_created().unwrap();
    let draft = engine
        .draft_kdf_upgrade(b"control test passphrase", upgraded, [8; 16])
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    let source = engine.descriptor_bytes().to_vec();
    let mut unadmitted =
        Engine::open_with_kdf_policy(&source, engine.limits(), KdfPolicy::baseline()).unwrap();
    unadmitted.begin_unlock(b"control test passphrase").unwrap();
    let original_phase = unadmitted.phase();
    assert_eq!(
        unadmitted
            .prepare_reopen_locked(&plan.descriptor_bytes)
            .err()
            .unwrap()
            .code(),
        "ResourceLimit"
    );
    assert_eq!(unadmitted.descriptor_bytes(), source);
    assert_eq!(unadmitted.phase(), original_phase);
    unadmitted.begin_host_work().unwrap().check().unwrap();
    let reservation = budget.reserve(1).unwrap();
    // Parsing succeeds with the admitted upgraded tuple and no KDF invocation,
    // even though the sole configured operation slot is currently occupied.
    let original_phase = engine.phase();
    let replacement = engine
        .prepare_reopen_locked(&plan.descriptor_bytes)
        .unwrap();
    assert_eq!(replacement.descriptor_bytes(), plan.descriptor_bytes);
    assert!(!replacement.is_unlocked());
    assert!(replacement.head_bytes().is_empty());
    assert_eq!(engine.phase(), original_phase);
    assert_eq!(engine.descriptor_bytes(), source);
    engine.reopen_locked(&plan.descriptor_bytes).unwrap();
    assert_eq!(engine.kdf_profile(), upgraded);
    assert_eq!(
        engine
            .begin_unlock(b"control test passphrase")
            .unwrap_err()
            .code(),
        "ResourceLimit"
    );
    drop(reservation);
    engine.begin_unlock(b"control test passphrase").unwrap();
    assert!(!engine.is_unlocked()); // No head audit/session activation yet.
}

#[test]
fn engine_reopen_locked_preserves_explicit_epoch_profile_admission() {
    let descriptor = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/epoch-vectors/descriptor.bin"
    ));
    let limits = Limits {
        max_payload_bytes: 128,
        max_metadata_bytes: 64,
        max_records: 16,
    };
    let admission = AccessAdmission {
        allowed_profiles: vec![AccessProfile::Portable],
        providers: Vec::new(),
        max_descriptor_bytes: descriptor.len(),
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    };
    let mut engine =
        Engine::open_epoch_access(descriptor, limits, KdfPolicy::baseline(), admission).unwrap();
    engine.reopen_locked(descriptor).unwrap();
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.access_info().unwrap().root_epoch, 7);
    assert!(!engine.is_unlocked());
    assert!(engine.head_bytes().is_empty());
}

#[test]
fn engine_reopen_locked_uses_exact_pending_admission_but_does_not_invent_restart_policy() {
    struct NoDevice;
    impl fogvault::KeyProvider for NoDevice {
        fn capability_kind(
            &self,
            _: &fogvault::ProviderIdentity,
        ) -> fogvault::ProviderCapabilityKind {
            panic!("portable profile must not use a device provider")
        }
        fn wrap_seed(
            &mut self,
            _: &fogvault::ProviderContext,
            _: &[u8; 32],
        ) -> fogvault::ProviderResult<Vec<u8>> {
            panic!("portable profile must not use a device provider")
        }
        fn unwrap_seed(
            &mut self,
            _: &fogvault::ProviderContext,
            _: &[u8],
        ) -> fogvault::ProviderResult<zeroize::Zeroizing<[u8; 32]>> {
            panic!("portable profile must not use a device provider")
        }
    }
    let mut engine = Engine::diagnostic_create(
        b"control test passphrase",
        Limits {
            max_payload_bytes: 128,
            max_metadata_bytes: 64,
            max_records: 16,
        },
    )
    .unwrap();
    engine.activate_created().unwrap();
    let source = engine.descriptor_bytes().to_vec();
    let source_admission = AccessAdmission {
        allowed_profiles: vec![AccessProfile::Portable],
        providers: Vec::new(),
        // Current portable descriptor: fixed108 + password-root72.
        max_descriptor_bytes: 180,
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    };
    engine
        .configure_access_admission(source_admission.clone())
        .unwrap();
    assert_eq!(
        engine.descriptor_byte_limit(),
        source_admission.max_descriptor_bytes
    );
    let admission = AccessAdmission {
        // A recovery route adds its exact96-byte wrapper to portable180.
        max_descriptor_bytes: source_admission.max_descriptor_bytes + 96,
        ..source_admission.clone()
    };
    let (draft, _) = engine
        .draft_access_setup(
            b"control test passphrase",
            None,
            b"replacement passphrase",
            AccessProfile::Portable,
            &[],
            true,
            &mut NoDevice,
            admission.clone(),
            [9; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine.mark_unknown().unwrap();
    assert_eq!(plan.descriptor_bytes.len(), admission.max_descriptor_bytes);
    // Retention already admits the exact pending target width; it does not
    // install the target's profile/provider policy or need a new width getter.
    assert_eq!(engine.descriptor_byte_limit(), plan.descriptor_bytes.len());
    engine.reopen_locked(&plan.descriptor_bytes).unwrap();
    assert_eq!(
        engine.access_info().unwrap().profile,
        AccessProfile::Portable
    );
    assert!(!engine.is_unlocked());

    let mut restarted =
        Engine::diagnostic_open_with_kdf_policy(&source, engine.limits(), KdfPolicy::baseline())
            .unwrap();
    assert!(matches!(
        restarted.reopen_locked(&plan.descriptor_bytes),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(restarted.descriptor_bytes(), source);
    restarted
        .configure_access_admission(source_admission)
        .unwrap();
    assert_eq!(
        restarted
            .reopen_locked(&plan.descriptor_bytes)
            .unwrap_err()
            .code(),
        "ResourceLimit"
    );
    restarted.configure_access_admission(admission).unwrap();
    restarted.reopen_locked(&plan.descriptor_bytes).unwrap();
    assert_eq!(restarted.descriptor_bytes(), plan.descriptor_bytes);
    assert!(!restarted.is_unlocked());
}
