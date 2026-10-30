//! Explicit maintenance preserves keys; loss replacement selects the protective planner.
//! Providers are synthetic and establish no hardware property.
use fogvault::{
    AccessAdmission, AccessChange, AccessPath, AccessProfile, AuditRequest, Engine, Error,
    KdfPolicy, KeyEffect, KeyProvider, Limits, NodeHash, NodeStore, ProtectiveSource,
    ProviderCapabilityKind, ProviderContext, ProviderError, ProviderIdentity, ProviderResult,
    Result,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"synthetic key-effect password";
fn identity(n: u8) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [n; 16],
        key_id: [n + 1; 16],
        device_bound: true,
        nonexportable: true,
    }
}
fn admission() -> AccessAdmission {
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
        max_payload_bytes: 64,
        max_metadata_bytes: 0,
        max_records: 1,
    }
}
#[derive(Default)]
struct Provider {
    seeds: BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>,
    calls: usize,
}
impl KeyProvider for Provider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, c: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        self.calls += 1;
        self.seeds
            .insert(c.authenticated_bytes(), Zeroizing::new(*seed));
        Ok(c.slot_id.to_vec())
    }
    fn unwrap_seed(
        &mut self,
        c: &ProviderContext,
        blob: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        self.calls += 1;
        if blob != c.slot_id {
            return Err(ProviderError::InvalidResponse);
        }
        self.seeds
            .get(&c.authenticated_bytes())
            .map(|seed| Zeroizing::new(**seed))
            .ok_or(ProviderError::Unavailable)
    }
}
#[derive(Default)]
struct Memory {
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    row: Option<(u64, Vec<u8>)>,
}
impl NodeStore for Memory {
    fn get(&mut self, h: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(h).cloned())
    }
    fn put(&mut self, h: NodeHash, b: &[u8]) -> Result<()> {
        self.nodes.insert(h, b.to_vec());
        Ok(())
    }
}
fn audit(engine: &mut Engine, head: &[u8], memory: &Memory) {
    engine.begin_audit(head).unwrap();
    loop {
        match engine.audit_next().unwrap() {
            AuditRequest::Node(h) => engine.supply_node(&memory.nodes[&h]).unwrap(),
            AuditRequest::Record { .. } => {
                let (r, b) = memory.row.as_ref().unwrap();
                engine.supply_record(*r, b.len() as u64, Some(b)).unwrap();
            }
            AuditRequest::Done => break,
        }
    }
    engine
        .finish_audit(u64::from(memory.row.is_some()), memory.nodes.len() as u64)
        .unwrap();
    engine.activate_audit().unwrap();
}
fn saved(
    profile: AccessProfile,
    provider: &mut Provider,
) -> (Engine, Memory, fogvault::RecoveryKey) {
    let devices = if profile == AccessProfile::Portable {
        vec![]
    } else {
        vec![identity(1), identity(3)]
    };
    let (mut engine, key) = Engine::create_with_access(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(),
        profile,
        &devices,
        true,
        provider,
    )
    .unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory::default();
    let plan = engine
        .prepare_save(
            &mut memory,
            [9; 16],
            None,
            b"",
            b"unchanged bytes",
            [10; 16],
            None,
        )
        .unwrap();
    memory.row = Some((plan.revision, plan.envelope));
    engine.confirm_commit(&plan.head_bytes).unwrap();
    (engine, memory, key.unwrap())
}
#[test]
fn access_removal_requires_explicit_maintenance_and_reports_preserved_keys() {
    for profile in [
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let mut provider = Provider::default();
        let (mut engine, memory, _) = saved(profile, &mut provider);
        let info = engine.access_info().unwrap();
        let slot = info.device_slots[0].0;
        let auth = || {
            if profile == AccessProfile::PasswordAndDevice {
                AccessPath::Device {
                    slot_id: slot,
                    password: Some(PASSWORD),
                }
            } else {
                AccessPath::Password(PASSWORD)
            }
        };
        let before_calls = provider.calls;
        let before_head = engine.head_bytes().to_vec();
        assert!(matches!(
            engine.draft_access_change(
                auth(),
                AccessChange::RemoveDevice(slot),
                &mut provider,
                [11; 16]
            ),
            Err(Error::UnsupportedCapability)
        ));
        assert!(matches!(
            engine.draft_access_change(
                auth(),
                AccessChange::ReplaceRecovery,
                &mut provider,
                [12; 16]
            ),
            Err(Error::UnsupportedCapability)
        ));
        assert!(matches!(
            engine.draft_access_change(
                auth(),
                AccessChange::DisableRecovery,
                &mut provider,
                [13; 16]
            ),
            Err(Error::UnsupportedCapability)
        ));
        assert!(matches!(
            engine.draft_access_setup(
                PASSWORD,
                Some(auth()),
                PASSWORD,
                profile,
                &[identity(3)],
                true,
                &mut provider,
                admission(),
                [14; 16]
            ),
            Err(Error::UnsupportedCapability)
        ));
        assert_eq!(provider.calls, before_calls);
        assert_eq!(engine.head_bytes(), before_head);
        let before = memory.row.clone();
        let (draft, _) = engine
            .draft_access_maintenance(
                auth(),
                AccessChange::RemoveDevice(slot),
                &mut provider,
                [15; 16],
            )
            .unwrap();
        assert_eq!(draft.key_effect(), KeyEffect::Preserved);
        let plan = engine.stage_credential_change(&draft).unwrap();
        assert_eq!(plan.key_effect(), KeyEffect::Preserved);
        let receipt = engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert_eq!(receipt.key_effect(), KeyEffect::Preserved);
        assert_eq!(engine.access_info().unwrap().root_epoch, info.root_epoch);
        assert_eq!(memory.row, before);
        let mut memory = memory;
        let proof = engine.lookup(&mut memory, &[9; 16]).unwrap();
        let (r, b) = memory.row.as_ref().unwrap();
        assert_eq!(
            engine
                .read_verified(proof.entry().unwrap(), *r, b)
                .unwrap()
                .payload
                .as_slice(),
            b"unchanged bytes"
        );
    }
}
#[test]
fn recovery_repair_requires_explicit_maintenance_or_protective_replacement() {
    let mut provider = Provider::default();
    let (mut engine, memory, key) = saved(AccessProfile::Portable, &mut provider);
    let head = engine.head_bytes().to_vec();
    engine.begin_recovery(&key).unwrap();
    audit(&mut engine, &head, &memory);
    assert!(matches!(
        engine.draft_recovery_repair(
            &key,
            PASSWORD,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            [20; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    let (draft, _) = engine
        .draft_recovery_maintenance(
            &key,
            PASSWORD,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            [21; 16],
        )
        .unwrap();
    assert_eq!(draft.key_effect(), KeyEffect::Preserved);
    let plan = engine.stage_credential_change(&draft).unwrap();
    assert_eq!(
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap()
            .key_effect,
        KeyEffect::Preserved
    );
    engine.begin_recovery(&key).unwrap_err();
}
#[test]
fn device_replacement_excludes_lost_key_before_provider_work() {
    let mut provider = Provider::default();
    let (engine, _, _) = saved(AccessProfile::PasswordOrDevice, &mut provider);
    let slot = engine
        .access_info()
        .unwrap()
        .device_slots
        .into_iter()
        .find(|(_, provider)| *provider == identity(1))
        .unwrap()
        .0;
    let before = provider.calls;
    assert!(matches!(
        engine.draft_device_replacement(
            ProtectiveSource::Password(PASSWORD),
            &[slot],
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            true,
            &mut provider,
            admission(),
            [30; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert!(matches!(
        engine.draft_device_replacement(
            ProtectiveSource::Password(PASSWORD),
            &[slot, slot],
            PASSWORD,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            admission(),
            [31; 16]
        ),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        engine.draft_device_replacement(
            ProtectiveSource::Password(PASSWORD),
            &[[99; 16]],
            PASSWORD,
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
            admission(),
            [32; 16]
        ),
        Err(Error::NotFound)
    ));
    assert_eq!(provider.calls, before);
    let (transition, _) = engine
        .draft_device_replacement(
            ProtectiveSource::Password(PASSWORD),
            &[slot],
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(3)],
            true,
            &mut provider,
            admission(),
            [33; 16],
        )
        .unwrap();
    assert_eq!(transition.key_effect(), KeyEffect::FreshRootAndContentKeys);
}

#[test]
fn generic_setup_replay_preserves_effect_without_authorizing_new_route_removal() {
    let mut provider = Provider::default();
    let mut engine = Engine::create(PASSWORD, limits()).unwrap();
    engine.activate_created().unwrap();
    let request = [0x41; 16];
    let (draft, kit) = engine
        .draft_access_setup(
            PASSWORD,
            None,
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            true,
            &mut provider,
            admission(),
            request,
        )
        .unwrap();
    assert!(kit.is_some());
    assert_eq!(draft.key_effect(), KeyEffect::Preserved);
    let plan = engine.stage_credential_change(&draft).unwrap();
    let receipt = engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(receipt.key_effect(), KeyEffect::Preserved);
    let descriptor = engine.descriptor_bytes().to_vec();
    let head = engine.head_bytes().to_vec();
    let before_calls = provider.calls;
    let (draft, replayed_kit) = engine
        .draft_access_setup(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(1)],
            true,
            &mut provider,
            admission(),
            request,
        )
        .unwrap();
    assert!(replayed_kit.is_none());
    assert_eq!(draft.key_effect(), KeyEffect::Preserved);
    let replay = engine.stage_credential_change(&draft).unwrap();
    assert!(replay.replay);
    assert_eq!(replay.descriptor_bytes, descriptor);
    assert_eq!(replay.head_bytes, head);
    assert_eq!(provider.calls, before_calls); // only password authentication, no new device wrappers
    assert!(matches!(
        engine.draft_access_setup(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            PASSWORD,
            AccessProfile::PasswordOrDevice,
            &[identity(3)],
            true,
            &mut provider,
            admission(),
            request
        ),
        Err(Error::OperationIdReuse)
    ));
    assert!(matches!(
        engine.draft_access_setup(
            PASSWORD,
            Some(AccessPath::Password(PASSWORD)),
            PASSWORD,
            AccessProfile::Portable,
            &[],
            false,
            &mut provider,
            admission(),
            [0x42; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert_eq!(engine.head_bytes(), head);
}
