//! Real P3 wrapper/Engine proofs. Provider properties are an in-memory oracle,
//! not hardware/device qualification.
use fogvault::{
    AccessAdmission, AccessChange, AccessPath, AccessProfile, AuditRequest, Engine, Error,
    KdfPolicy, KdfProfile, KeyProvider, Limits, ProviderContext, ProviderError, ProviderIdentity,
    ProviderResult, RecoveryKey, RevocationHandle,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
#[derive(Default)]
struct Nodes(BTreeMap<[u8; 32], Vec<u8>>);
impl fogvault::NodeStore for Nodes {
    fn get(&mut self, hash: &[u8; 32]) -> fogvault::Result<Option<Vec<u8>>> {
        Ok(self.0.get(hash).cloned())
    }
    fn put(&mut self, hash: [u8; 32], bytes: &[u8]) -> fogvault::Result<()> {
        self.0.insert(hash, bytes.to_vec());
        Ok(())
    }
}

const PASSWORD: &[u8] = b"synthetic access password";
const NEW: &[u8] = b"synthetic replacement password";
fn identity(n: u8) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [n; 16],
        key_id: [n + 1; 16],
        device_bound: true,
        nonexportable: true,
    }
}
fn admission() -> AccessAdmission {
    // Exact worst-case encoding for two 16-byte opaque provider handles plus
    // strict profile and recovery wrappers:108+2*(64+16+112)+96=588.
    AccessAdmission {
        allowed_profiles: vec![
            AccessProfile::Portable,
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ],
        providers: vec![identity(1), identity(3)],
        max_descriptor_bytes: 588,
        max_device_slots: 2,
        max_provider_blob_bytes: 16,
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 0,
        max_records: 2,
    }
}
#[derive(Default)]
struct Provider {
    seeds: BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>,
    error: Option<ProviderError>,
    revoke: Option<RevocationHandle>,
    unavailable_slot: Option<[u8; 16]>,
    unwrap_calls: Vec<[u8; 16]>,
    kind: Option<fogvault::ProviderCapabilityKind>,
}
impl KeyProvider for Provider {
    // Synthetic operation oracle only; this declaration is not hardware evidence.
    fn capability_kind(
        &self,
        _identity: &fogvault::ProviderIdentity,
    ) -> fogvault::ProviderCapabilityKind {
        self.kind
            .unwrap_or(fogvault::ProviderCapabilityKind::NonExportableOperation)
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let blob = context.slot_id.to_vec();
        self.seeds
            .insert(context.authenticated_bytes(), Zeroizing::new(*seed));
        Ok(blob)
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        self.unwrap_calls.push(context.slot_id);
        if self.unavailable_slot == Some(context.slot_id) {
            return Err(ProviderError::Unavailable);
        }
        if let Some(handle) = self.revoke.take() {
            handle.revoke();
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        if wrapped != context.slot_id {
            return Err(ProviderError::InvalidResponse);
        }
        self.seeds
            .get(&context.authenticated_bytes())
            .map(|seed| Zeroizing::new(**seed))
            .ok_or(ProviderError::IdentityChanged)
    }
}
fn audit(engine: &mut Engine, head: &[u8]) {
    engine.begin_audit(head).unwrap();
    assert!(matches!(engine.audit_next().unwrap(), AuditRequest::Done));
    engine.finish_audit(0, 0).unwrap();
    engine.activate_audit().unwrap();
}
fn create(
    profile: AccessProfile,
    recovery: bool,
    provider: &mut Provider,
) -> (Engine, Option<RecoveryKey>) {
    let devices = if profile == AccessProfile::Portable {
        vec![]
    } else {
        vec![identity(1)]
    };
    let (mut engine, key) = Engine::diagnostic_create_with_access(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(),
        profile,
        &devices,
        recovery,
        provider,
    )
    .unwrap();
    engine.activate_created().unwrap();
    (engine, key)
}
#[test]
fn access_profiles_require_exact_paths_and_recovery_is_restricted() {
    for profile in [
        AccessProfile::Portable,
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let mut provider = Provider::default();
        let (mut engine, key) = create(profile, true, &mut provider);
        let head = engine.head_bytes().to_vec();
        let descriptor = engine.descriptor_bytes().to_vec();
        assert!(Engine::diagnostic_open(&descriptor, limits()).is_err());
        let slot = engine
            .access_info()
            .unwrap()
            .device_slots
            .first()
            .map(|slot| slot.0);
        engine.lock();
        if profile == AccessProfile::PasswordAndDevice {
            assert!(engine
                .begin_unlock_access(AccessPath::Password(PASSWORD), &mut provider)
                .is_err());
            assert!(engine
                .begin_unlock_access(
                    AccessPath::Device {
                        slot_id: slot.unwrap(),
                        password: None
                    },
                    &mut provider
                )
                .is_err());
        } else {
            engine
                .begin_unlock_access(AccessPath::Password(PASSWORD), &mut provider)
                .unwrap();
            audit(&mut engine, &head);
        }
        if let Some(slot) = slot {
            engine
                .begin_unlock_access(
                    AccessPath::Device {
                        slot_id: slot,
                        password: if profile == AccessProfile::PasswordAndDevice {
                            Some(PASSWORD)
                        } else {
                            None
                        },
                    },
                    &mut provider,
                )
                .unwrap();
            assert!(engine.current_session().is_err());
            audit(&mut engine, &head);
            assert!(engine.is_unlocked());
        }
        engine.begin_recovery(key.as_ref().unwrap()).unwrap();
        assert!(engine.is_recovery_candidate());
        audit(&mut engine, &head);
        assert!(!engine.is_unlocked());
        assert!(engine.current_session().is_err());
        let (draft, _) = engine
            .draft_recovery_maintenance(
                key.as_ref().unwrap(),
                NEW,
                AccessProfile::Portable,
                &[],
                true,
                &mut provider,
                [9; 16],
            )
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        assert!(engine.current_session().is_err());
        let receipt = engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert!(engine.check_session(&receipt.session).is_ok());
        engine.lock();
        assert!(engine.begin_recovery(key.as_ref().unwrap()).is_err());
        let mut reopened = Engine::diagnostic_open_with_access(
            &plan.descriptor_bytes,
            limits(),
            KdfPolicy::baseline(),
            admission(),
        )
        .unwrap();
        reopened
            .begin_unlock_access(AccessPath::Password(NEW), &mut provider)
            .unwrap();
        audit(&mut reopened, &plan.head_bytes);
    }
}
#[test]
fn access_enrollment_removal_and_recovery_policy_use_paired_commits() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    let before = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    let (draft, key) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnableRecovery,
            &mut provider,
            [1; 16],
        )
        .unwrap();
    assert!(key.is_some());
    let _plan = engine.stage_credential_change(&draft).unwrap();
    assert_eq!(engine.descriptor_bytes(), before);
    assert_eq!(engine.head_bytes(), head);
    engine.abort_prepared().unwrap();
    assert_eq!(engine.descriptor_bytes(), before);
    let (draft, key) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnableRecovery,
            &mut provider,
            [1; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let (retry, no_new_secret) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnableRecovery,
            &mut provider,
            [1; 16],
        )
        .unwrap();
    assert!(no_new_secret.is_none());
    assert!(engine.stage_credential_change(&retry).unwrap().replay);
    let (draft, _) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnrollDevice(identity(3)),
            &mut provider,
            [2; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    let (draft, _) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::RemoveDevice(slot),
            &mut provider,
            [3; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let last = engine.access_info().unwrap().device_slots[0].0;
    assert!(engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::RemoveDevice(last),
            &mut provider,
            [4; 16]
        )
        .is_err());
    let encoded = key.unwrap().export();
    let restored = RecoveryKey::import(&encoded).unwrap();
    let accepted = engine.head_bytes().to_vec();
    engine.begin_recovery(&restored).unwrap();
    audit(&mut engine, &accepted);
}
#[test]
fn access_provider_errors_revocation_and_unadmitted_profiles_never_publish() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::PasswordAndDevice, false, &mut provider);
    let descriptor = engine.descriptor_bytes().to_vec();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    for error in [
        ProviderError::Denied,
        ProviderError::Cancelled,
        ProviderError::Unavailable,
        ProviderError::IdentityChanged,
    ] {
        provider.error = Some(error);
        assert!(
            matches!(engine.begin_unlock_access(AccessPath::Device{slot_id:slot,password:Some(PASSWORD)},&mut provider),Err(Error::Provider(value)) if value==error)
        );
        assert!(engine.current_session().is_err());
    }
    provider.error = None;
    provider.revoke = Some(engine.revocation_handle());
    assert!(engine
        .begin_unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD)
            },
            &mut provider
        )
        .is_err());
    assert!(!engine.is_unlocked());
    let mut rejected = admission();
    rejected.allowed_profiles = vec![AccessProfile::Portable];
    assert!(Engine::diagnostic_open_with_access(
        &descriptor,
        limits(),
        KdfPolicy::baseline(),
        rejected
    )
    .is_err());
    let mut short = admission();
    short.max_descriptor_bytes = descriptor.len() - 1;
    assert!(Engine::diagnostic_open_with_access(
        &descriptor,
        limits(),
        KdfPolicy::baseline(),
        short
    )
    .is_err());
    let mut tampered = descriptor.clone();
    tampered[46] = 0;
    assert!(Engine::diagnostic_open_with_access(
        &tampered,
        limits(),
        KdfPolicy::baseline(),
        admission()
    )
    .is_err());
    if usize::BITS > 32 {
        for field in [0, 1] {
            let mut config = admission();
            if field == 0 {
                config.max_device_slots = usize::MAX;
            } else {
                config.max_provider_blob_bytes = usize::MAX;
            }
            let mut unused = Provider::default();
            assert!(matches!(
                Engine::diagnostic_create_with_access(
                    PASSWORD,
                    limits(),
                    KdfPolicy::baseline(),
                    config,
                    AccessProfile::PasswordAndDevice,
                    &[identity(1)],
                    true,
                    &mut unused
                ),
                Err(Error::ResourceLimit)
            ));
            assert!(unused.seeds.is_empty());
        }
    }
}
#[test]
fn access_enrollment_retry_binds_provider_capabilities() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    let request = [73; 16];
    let target = identity(3);
    let (draft, _) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnrollDevice(target),
            &mut provider,
            request,
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    let slots = engine.access_info().unwrap().device_slots;
    for field in [0, 1] {
        let mut changed = target;
        if field == 0 {
            changed.device_bound = false;
        } else {
            changed.nonexportable = false;
        }
        assert!(matches!(
            engine.draft_access_maintenance(
                AccessPath::Password(PASSWORD),
                AccessChange::EnrollDevice(changed),
                &mut provider,
                request,
            ),
            Err(Error::OperationIdReuse)
        ));
        assert_eq!(engine.descriptor_bytes(), descriptor);
        assert_eq!(engine.head_bytes(), head);
        assert_eq!(engine.access_info().unwrap().device_slots, slots);
    }
    let (retry, key) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::EnrollDevice(target),
            &mut provider,
            request,
        )
        .unwrap();
    assert!(key.is_none());
    let replay = engine.stage_credential_change(&retry).unwrap();
    assert!(replay.replay);
    assert_eq!(replay.descriptor_bytes, descriptor);
    assert_eq!(replay.head_bytes, head);
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
    assert_eq!(engine.access_info().unwrap().device_slots, slots);
}

#[test]
fn access_device_password_change_retry_binds_replacement_password() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    let slot = engine.access_info().unwrap().device_slots[0].0;
    let request = [71; 16];
    let draft = engine
        .draft_access_password_change(
            AccessPath::Device {
                slot_id: slot,
                password: None,
            },
            NEW,
            KdfProfile::baseline(),
            &mut provider,
            request,
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    provider.unwrap_calls.clear();
    assert!(matches!(
        engine.draft_access_password_change(
            AccessPath::Device {
                slot_id: slot,
                password: None
            },
            b"different requested replacement",
            KdfProfile::baseline(),
            &mut provider,
            request,
        ),
        Err(Error::OperationIdReuse)
    ));
    let retry = engine
        .draft_access_password_change(
            AccessPath::Device {
                slot_id: slot,
                password: None,
            },
            NEW,
            KdfProfile::baseline(),
            &mut provider,
            request,
        )
        .unwrap();
    let replay = engine.stage_credential_change(&retry).unwrap();
    assert!(replay.replay);
    assert_eq!(replay.descriptor_bytes, descriptor);
    assert_eq!(replay.head_bytes, head);
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
    // Convenience devices may unlock without a password, so retry equivalence
    // must use the actual password wrapper instead of a provider callback.
    assert!(provider.unwrap_calls.is_empty());
}

#[test]
fn access_profile_change_retry_binds_replacement_password() {
    for profile in [
        AccessProfile::Portable,
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let mut provider = Provider::default();
        let (mut engine, _) = Engine::diagnostic_create_with_access(
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
            admission(),
            if profile == AccessProfile::PasswordAndDevice {
                profile
            } else {
                AccessProfile::PasswordOrDevice
            },
            &[identity(1), identity(3)],
            false,
            &mut provider,
        )
        .unwrap();
        engine.activate_created().unwrap();
        let slots = engine.access_info().unwrap().device_slots;
        let (first, second) = (slots[0].0, slots[1].0);
        let request = [72; 16];
        let (draft, _) = engine
            .draft_access_maintenance(
                if profile == AccessProfile::PasswordAndDevice {
                    AccessPath::Device {
                        slot_id: first,
                        password: Some(PASSWORD),
                    }
                } else {
                    AccessPath::Password(PASSWORD)
                },
                AccessChange::SetProfile {
                    profile,
                    password: NEW,
                },
                &mut provider,
                request,
            )
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        let descriptor = engine.descriptor_bytes().to_vec();
        let head = engine.head_bytes().to_vec();
        // Initial transition proved the complete target graph. A subsequent
        // retry only reauthenticates its selected path, not another device.
        provider.unavailable_slot = Some(second);
        let auth = || {
            if profile == AccessProfile::Portable {
                AccessPath::Password(NEW)
            } else {
                AccessPath::Device {
                    slot_id: first,
                    password: Some(NEW),
                }
            }
        };
        provider.unwrap_calls.clear();
        assert!(matches!(
            engine.draft_access_maintenance(
                auth(),
                AccessChange::SetProfile {
                    profile,
                    password: b"different requested replacement"
                },
                &mut provider,
                request,
            ),
            Err(Error::OperationIdReuse)
        ));
        let (retry, key) = engine
            .draft_access_maintenance(
                auth(),
                AccessChange::SetProfile {
                    profile,
                    password: NEW,
                },
                &mut provider,
                request,
            )
            .unwrap();
        assert!(key.is_none());
        let replay = engine.stage_credential_change(&retry).unwrap();
        assert!(replay.replay);
        assert_eq!(replay.descriptor_bytes, descriptor);
        assert_eq!(replay.head_bytes, head);
        assert_eq!(engine.descriptor_bytes(), descriptor);
        assert_eq!(engine.head_bytes(), head);
        if profile == AccessProfile::PasswordAndDevice {
            assert_eq!(provider.unwrap_calls, [first]);
            provider.unavailable_slot = Some(first);
            assert!(matches!(
                engine.draft_access_maintenance(
                    auth(),
                    AccessChange::SetProfile {
                        profile,
                        password: NEW
                    },
                    &mut provider,
                    request
                ),
                Err(Error::Provider(ProviderError::Unavailable))
            ));
        } else {
            assert!(provider.unwrap_calls.is_empty());
        }
        assert_eq!(engine.descriptor_bytes(), descriptor);
        assert_eq!(engine.head_bytes(), head);
    }
}

#[test]
fn access_strict_password_changes_keep_other_devices_offline() {
    let mut provider = Provider::default();
    let (mut engine, _) = Engine::diagnostic_create_with_access(
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
    engine.activate_created().unwrap();
    let slots = engine.access_info().unwrap().device_slots;
    let (first, second) = (slots[0].0, slots[1].0);
    assert_eq!(engine.descriptor_bytes().len(), 588);
    provider.unavailable_slot = Some(second);
    let draft = engine
        .draft_access_password_change(
            AccessPath::Device {
                slot_id: first,
                password: Some(PASSWORD),
            },
            NEW,
            KdfProfile::baseline(),
            &mut provider,
            [7; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let retry = engine
        .draft_access_password_change(
            AccessPath::Device {
                slot_id: first,
                password: Some(PASSWORD),
            },
            NEW,
            KdfProfile::baseline(),
            &mut provider,
            [7; 16],
        )
        .unwrap();
    assert!(engine.stage_credential_change(&retry).unwrap().replay);
    assert!(matches!(
        engine.draft_access_password_change(
            AccessPath::Device {
                slot_id: first,
                password: Some(PASSWORD)
            },
            b"different",
            KdfProfile::baseline(),
            &mut provider,
            [7; 16]
        ),
        Err(Error::OperationIdReuse)
    ));
    provider.unavailable_slot = None;
    engine.lock();
    assert!(engine
        .begin_unlock_access(
            AccessPath::Device {
                slot_id: second,
                password: Some(PASSWORD)
            },
            &mut provider
        )
        .is_err());
    engine
        .begin_unlock_access(
            AccessPath::Device {
                slot_id: second,
                password: Some(NEW),
            },
            &mut provider,
        )
        .unwrap();
    audit(&mut engine, &plan.head_bytes);
}

#[test]
fn access_p2_promotion_preserves_content_context_and_authenticates_whole_policy() {
    let mut provider = Provider::default();
    let mut engine = Engine::diagnostic_create(PASSWORD, limits()).unwrap();
    engine.activate_created().unwrap();
    let mut nodes = Nodes::default();
    let record = [42; 16];
    let saved = engine
        .prepare_save(
            &mut nodes,
            record,
            None,
            &[],
            b"preserved P2 consumer bytes",
            [12; 16],
            None,
        )
        .unwrap();
    let envelope = saved.envelope.clone();
    engine.confirm_commit(&saved.head_bytes).unwrap();
    let old = engine.descriptor_bytes().to_vec();
    engine.configure_access_admission(admission()).unwrap();
    let (draft, _) = engine
        .draft_access_setup_maintenance(
            PASSWORD,
            None,
            NEW,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            admission(),
            [10; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    assert_eq!(plan.prior_descriptor, old);
    assert_ne!(plan.descriptor_bytes, old);
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let proof = engine.lookup(&mut nodes, &record).unwrap();
    assert_eq!(
        engine
            .read_verified(proof.entry().unwrap(), 1, &envelope)
            .unwrap()
            .payload
            .as_slice(),
        b"preserved P2 consumer bytes"
    );
    let (retry, _) = engine
        .draft_access_setup_maintenance(
            PASSWORD,
            None,
            NEW,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            admission(),
            [10; 16],
        )
        .unwrap();
    assert!(engine.stage_credential_change(&retry).unwrap().replay);
    let mut tampered = plan.descriptor_bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let mut opened = Engine::diagnostic_open_with_access(
        &tampered,
        limits(),
        KdfPolicy::baseline(),
        admission(),
    )
    .unwrap();
    opened
        .begin_unlock_access(AccessPath::Password(NEW), &mut provider)
        .unwrap();
    assert!(opened.begin_audit(&plan.head_bytes).is_err());
    assert!(opened.current_session().is_err());
}

#[test]
fn access_uncertain_recovery_requires_audited_reconciliation() {
    let mut provider = Provider::default();
    let (mut engine, key) = create(AccessProfile::Portable, true, &mut provider);
    let head = engine.head_bytes().to_vec();
    let key = key.unwrap();
    engine.begin_recovery(&key).unwrap();
    audit(&mut engine, &head);
    let (draft, _) = engine
        .draft_recovery_maintenance(
            &key,
            NEW,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            [11; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine.mark_unknown().unwrap();
    assert!(matches!(
        engine.confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes),
        Err(Error::OutcomeUnknown { .. })
    ));
    assert!(engine.current_session().is_err());
    engine
        .begin_reconcile_snapshot(&plan.descriptor_bytes, &plan.head_bytes, [11; 16])
        .unwrap();
    assert!(matches!(engine.audit_next().unwrap(), AuditRequest::Done));
    engine.finish_audit(0, 0).unwrap();
    engine.activate_audit().unwrap();
    assert!(engine.is_unlocked());
    assert!(!engine.is_recovery_candidate());
    let (retry, no_key) = engine
        .draft_recovery_maintenance(
            &key,
            NEW,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            [11; 16],
        )
        .unwrap();
    assert!(no_key.is_none());
    assert!(engine.stage_credential_change(&retry).unwrap().replay);
}

#[test]
fn access_profile_transition_proves_every_retained_device_before_publication() {
    let mut provider = Provider::default();
    let (mut engine, _) = Engine::diagnostic_create_with_access(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(),
        AccessProfile::PasswordOrDevice,
        &[identity(1), identity(3)],
        false,
        &mut provider,
    )
    .unwrap();
    engine.activate_created().unwrap();
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    let slots = engine.access_info().unwrap().device_slots;
    // A live alternative must not silently excuse retaining a dead target slot.
    provider.unavailable_slot = Some(slots[1].0);
    provider.unwrap_calls.clear();
    assert!(matches!(
        engine.draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::SetProfile {
                profile: AccessProfile::PasswordOrDevice,
                password: NEW
            },
            &mut provider,
            [81; 16],
        ),
        Err(Error::Provider(ProviderError::Unavailable))
    ));
    assert!(provider.unwrap_calls.contains(&slots[1].0));
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
    assert_eq!(engine.pending_request(), None);
    provider.unavailable_slot = None;
    provider.unwrap_calls.clear();
    let (draft, _) = engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::SetProfile {
                profile: AccessProfile::PasswordOrDevice,
                password: NEW,
            },
            &mut provider,
            [81; 16],
        )
        .unwrap();
    assert_eq!(
        provider.unwrap_calls,
        slots.iter().map(|slot| slot.0).collect::<Vec<_>>()
    );
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    for (slot, _) in slots {
        engine
            .begin_unlock_access(
                AccessPath::Device {
                    slot_id: slot,
                    password: Some(NEW),
                },
                &mut provider,
            )
            .unwrap();
        audit(&mut engine, &plan.head_bytes);
    }
}

#[test]
fn access_profile_transition_rejects_late_or_invalid_target_device_proof() {
    let mut provider = Provider::default();
    let (engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    // A syntactically valid, wrong seed cannot prove the intended target root.
    for seed in provider.seeds.values_mut() {
        **seed = [0; 32];
    }
    assert!(engine
        .draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::SetProfile {
                profile: AccessProfile::PasswordOrDevice,
                password: NEW
            },
            &mut provider,
            [82; 16],
        )
        .is_err());
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
    let mut provider = Provider::default();
    let (engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    provider.revoke = Some(engine.revocation_handle());
    assert!(matches!(
        engine.draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::SetProfile {
                profile: AccessProfile::PasswordOrDevice,
                password: NEW
            },
            &mut provider,
            [83; 16],
        ),
        Err(Error::Provider(ProviderError::Cancelled))
    ));
    assert!(!engine.is_unlocked());
    assert_eq!(engine.pending_request(), None);
}

#[test]
fn access_setup_admission_is_installed_only_with_confirmed_or_reconciled_target() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::Portable, false, &mut provider);
    let mut narrow = admission();
    narrow.allowed_profiles = vec![AccessProfile::Portable];
    narrow.providers.clear();
    narrow.max_device_slots = 0;
    narrow.max_descriptor_bytes = 256;
    engine.configure_access_admission(narrow).unwrap();
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    let (abandoned, _) = engine
        .draft_access_setup_maintenance(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            NEW,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            false,
            &mut provider,
            admission(),
            [84; 16],
        )
        .unwrap();
    assert_eq!(engine.descriptor_byte_limit(), 256);
    assert_eq!(engine.descriptor_bytes(), descriptor);
    drop(abandoned);
    assert_eq!(engine.descriptor_byte_limit(), 256);
    let (draft, _) = engine
        .draft_access_setup_maintenance(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            NEW,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            false,
            &mut provider,
            admission(),
            [85; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    assert_eq!(
        engine.descriptor_byte_limit(),
        plan.descriptor_bytes.len().max(256)
    );
    engine.abort_prepared().unwrap();
    assert_eq!(engine.descriptor_byte_limit(), 256);
    assert_eq!(engine.head_bytes(), head);
    // A known committed target installs the proposed policy only on confirmation.
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(
        engine.descriptor_byte_limit(),
        admission().max_descriptor_bytes
    );
    // Repeat with a narrower accepted policy and an unknown outcome: target
    // audit completion, not the draft or source observation, grants admission.
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::Portable, false, &mut provider);
    let mut narrow = admission();
    narrow.max_descriptor_bytes = 256;
    engine.configure_access_admission(narrow).unwrap();
    let (draft, _) = engine
        .draft_access_setup_maintenance(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            NEW,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            false,
            &mut provider,
            admission(),
            [86; 16],
        )
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine.mark_unknown().unwrap();
    engine
        .begin_reconcile_snapshot(&plan.descriptor_bytes, &plan.head_bytes, [86; 16])
        .unwrap();
    assert!(matches!(engine.audit_next().unwrap(), AuditRequest::Done));
    engine.finish_audit(0, 0).unwrap();
    assert_eq!(
        engine.descriptor_byte_limit(),
        plan.descriptor_bytes.len().max(256)
    );
    engine.activate_audit().unwrap();
    assert_eq!(
        engine.descriptor_byte_limit(),
        admission().max_descriptor_bytes
    );
}

#[test]
fn access_reconcile_source_keeps_policy_and_repair_outcomes_unknown() {
    for recovery in [false, true] {
        let mut provider = Provider::default();
        let (mut engine, key) = create(AccessProfile::Portable, true, &mut provider);
        let descriptor = engine.descriptor_bytes().to_vec();
        let head = engine.head_bytes().to_vec();
        if recovery {
            engine.begin_recovery(key.as_ref().unwrap()).unwrap();
            audit(&mut engine, &head);
        }
        let (draft, _) = if recovery {
            engine.draft_recovery_maintenance(
                key.as_ref().unwrap(),
                NEW,
                AccessProfile::Portable,
                &[],
                true,
                &mut provider,
                [87; 16],
            )
        } else {
            engine.draft_access_maintenance(
                AccessPath::Password(PASSWORD),
                AccessChange::ReplaceRecovery,
                &mut provider,
                [87; 16],
            )
        }
        .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine.mark_unknown().unwrap();
        assert!(
            matches!(engine.begin_reconcile_snapshot(&descriptor,&head,[87;16]),
            Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16])
        );
        assert!(engine.is_uncertain());
        assert_eq!(engine.pending_request(), Some([87; 16]));
        assert_eq!(engine.descriptor_bytes(), descriptor);
        assert_eq!(engine.head_bytes(), head);
        assert!(
            matches!(engine.abort_prepared(),Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16])
        );
        assert!(
            matches!(engine.begin_audit(&head),Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16])
        );
        assert!(
            matches!(engine.stage_credential_change(&draft),Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16])
        );
        assert!(
            matches!(engine.draft_recovery_maintenance(key.as_ref().unwrap(),NEW,
            AccessProfile::Portable,&[],true,&mut provider,[89;16]),
            Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16])
        );
        let source_auth = if recovery {
            fogvault::ProtectiveSource::Recovery(key.as_ref().unwrap())
        } else {
            fogvault::ProtectiveSource::Access(AccessPath::Password(PASSWORD))
        };
        assert!(matches!(engine.draft_protective_transition(source_auth,NEW,
            AccessProfile::Portable,&[],true,&mut provider,admission(),[90;16]),
            Err(Error::OutcomeUnknown { request_id }) if request_id == [87;16]));
        engine
            .begin_reconcile_snapshot(&plan.descriptor_bytes, &plan.head_bytes, [87; 16])
            .unwrap();
        assert!(matches!(engine.audit_next().unwrap(), AuditRequest::Done));
        engine.finish_audit(0, 0).unwrap();
        engine.activate_audit().unwrap();
        assert!(!engine.is_uncertain());
        assert!(engine.is_unlocked());
    }
}

#[test]
fn access_provider_classification_is_explicit_and_non_operation_kinds_are_rejected() {
    for kind in [
        fogvault::ProviderCapabilityKind::RawSecret,
        fogvault::ProviderCapabilityKind::DerivedSecret,
        fogvault::ProviderCapabilityKind::ConvenienceCache,
    ] {
        let mut provider = Provider {
            kind: Some(kind),
            ..Provider::default()
        };
        assert!(matches!(
            Engine::diagnostic_create_with_access(
                PASSWORD,
                limits(),
                KdfPolicy::baseline(),
                admission(),
                AccessProfile::PasswordAndDevice,
                &[identity(1)],
                false,
                &mut provider
            ),
            Err(Error::UnsupportedCapability)
        ));
        assert!(provider.seeds.is_empty());
    }
}

#[test]
fn access_header_only_strengthening_requires_protective_transition() {
    let mut provider = Provider::default();
    let (mut engine, _) = create(AccessProfile::PasswordOrDevice, false, &mut provider);
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    assert!(matches!(
        engine.draft_access_maintenance(
            AccessPath::Password(PASSWORD),
            AccessChange::SetProfile {
                profile: AccessProfile::PasswordAndDevice,
                password: NEW
            },
            &mut provider,
            [88; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert!(matches!(
        engine.draft_access_setup_maintenance(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            NEW,
            AccessProfile::PasswordAndDevice,
            &[identity(1)],
            false,
            &mut provider,
            admission(),
            [88; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
    assert_eq!(engine.pending_request(), None);
}
