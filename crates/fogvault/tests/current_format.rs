//! Maintained creation has one content grammar across all normal profiles.
//! Synthetic providers prove call/context behavior, not hardware properties.
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, AuditRequest, Engine, Error, KdfPolicy, KdfProfile,
    KeyProvider, Limits, NodeHash, NodeStore, ProviderCapabilityKind, ProviderContext,
    ProviderError, ProviderIdentity, ProviderResult, RecordId, Result,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"SYNTHETIC-current-format-password";
const ID: RecordId = [0x51; 16];
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 64,
        max_metadata_bytes: 7,
        max_records: 2,
    }
}
fn identity() -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [0x52; 16],
        key_id: [0x53; 16],
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
        providers: vec![identity()],
        max_descriptor_bytes: 1024,
        max_device_slots: 1,
        max_provider_blob_bytes: 256,
    }
}
#[derive(Default)]
struct Provider {
    seeds: BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>,
    wraps: usize,
    unwraps: usize,
}
impl KeyProvider for Provider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation // Synthetic declaration only.
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        self.wraps += 1;
        let handle = context.authenticated_bytes();
        self.seeds.insert(handle.clone(), Zeroizing::new(*seed));
        Ok(handle)
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        handle: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        self.unwraps += 1;
        if handle != context.authenticated_bytes() {
            return Err(ProviderError::IdentityChanged);
        }
        self.seeds
            .get(handle)
            .map(|seed| Zeroizing::new(**seed))
            .ok_or(ProviderError::Unavailable)
    }
}
#[derive(Default)]
struct Memory {
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    rows: BTreeMap<RecordId, (u64, Vec<u8>)>,
}
impl NodeStore for Memory {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<()> {
        if self.nodes.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, bytes.to_vec());
        Ok(())
    }
}
fn audit(engine: &mut Engine, head: &[u8], memory: &Memory) {
    engine.begin_audit(head).unwrap();
    loop {
        match engine.audit_next().unwrap() {
            AuditRequest::Node(hash) => engine.supply_node(&memory.nodes[&hash]).unwrap(),
            AuditRequest::Record { id, .. } => {
                let (revision, envelope) = &memory.rows[&id];
                engine
                    .supply_record(*revision, envelope.len() as u64, Some(envelope))
                    .unwrap();
            }
            AuditRequest::Done => break,
        }
    }
    engine
        .finish_audit(memory.rows.len() as u64, memory.nodes.len() as u64)
        .unwrap();
    engine.activate_audit().unwrap();
}

#[test]
fn maintained_creators_share_epoch_zero_content_three_across_profiles() {
    for profile in [
        AccessProfile::Portable,
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let mut provider = Provider::default();
        let devices = if profile == AccessProfile::Portable {
            vec![]
        } else {
            vec![identity()]
        };
        let (mut engine, recovery) = Engine::create_with_access(
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
            admission(),
            profile,
            &devices,
            false,
            &mut provider,
        )
        .unwrap();
        assert!(recovery.is_none());
        assert_eq!(engine.content_format(), 3);
        assert_eq!(&engine.descriptor_bytes()[..8], b"FGVP0003");
        assert_eq!(&engine.descriptor_bytes()[8..10], &3u16.to_be_bytes());
        assert_eq!(&engine.descriptor_bytes()[12..14], &3u16.to_be_bytes());
        let info = engine.access_info().unwrap();
        assert_eq!(info.root_epoch, 0);
        assert_eq!(info.profile, profile);
        assert_eq!(engine.envelope_byte_limit().unwrap(), 64 + 7 + 176);
        if profile == AccessProfile::Portable {
            assert_eq!((provider.wraps, provider.unwraps), (0, 0));
        } else {
            assert_eq!((provider.wraps, provider.unwraps), (1, 1));
        }
        let descriptor = engine.descriptor_bytes().to_vec();
        engine.activate_created().unwrap();
        let mut memory = Memory::default();
        let plan = engine
            .prepare_save(
                &mut memory,
                ID,
                None,
                &[0x54; 7],
                &[0x55; 64],
                [0x56; 16],
                None,
            )
            .unwrap();
        assert_eq!(plan.envelope.len(), 64 + 7 + 176);
        assert_eq!(&plan.envelope[..8], b"FGVR0003");
        assert_eq!(&plan.envelope[32..40], &0u64.to_be_bytes());
        memory.rows.insert(ID, (plan.revision, plan.envelope));
        engine.confirm_commit(&plan.head_bytes).unwrap();
        let head = engine.head_bytes().to_vec();
        engine.lock();
        let mut reopened =
            Engine::open_with_access(&descriptor, limits(), KdfPolicy::baseline(), admission())
                .unwrap();
        if profile == AccessProfile::Portable {
            reopened.begin_unlock(PASSWORD).unwrap();
        } else {
            let slot = info.device_slots[0].0;
            reopened
                .begin_unlock_access(
                    AccessPath::Device {
                        slot_id: slot,
                        password: (profile == AccessProfile::PasswordAndDevice).then_some(PASSWORD),
                    },
                    &mut provider,
                )
                .unwrap();
            assert!(Engine::open(&descriptor, limits()).is_err());
        }
        audit(&mut reopened, &head, &memory);
        let lookup = reopened.lookup(&mut memory, &ID).unwrap();
        let (revision, envelope) = &memory.rows[&ID];
        let record = reopened
            .read_verified(lookup.entry().unwrap(), *revision, envelope)
            .unwrap();
        assert_eq!(record.metadata.as_slice(), &[0x54; 7]);
        assert_eq!(record.payload.as_slice(), &[0x55; 64]);
    }
}

#[test]
fn maintained_default_creation_and_reader_refuse_legacy_content() {
    let current = Engine::create(PASSWORD, limits()).unwrap();
    assert_eq!(current.content_format(), 3);
    assert_eq!(current.access_info().unwrap().root_epoch, 0);
    assert_eq!(current.descriptor_bytes().len(), 180);
    assert!(Engine::open(current.descriptor_bytes(), limits()).is_ok());
    let legacy = Engine::diagnostic_create(PASSWORD, limits()).unwrap();
    assert_eq!(legacy.content_format(), 2);
    assert!(Engine::open(legacy.descriptor_bytes(), limits()).is_err());
    assert!(Engine::diagnostic_open(legacy.descriptor_bytes(), limits()).is_ok());
    let (legacy_access, _) = Engine::diagnostic_create_with_access(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(),
        AccessProfile::Portable,
        &[],
        false,
        &mut Provider::default(),
    )
    .unwrap();
    assert_eq!(legacy_access.content_format(), 2);
    assert!(Engine::open(legacy_access.descriptor_bytes(), limits()).is_err());
    assert!(Engine::open_with_access(
        legacy_access.descriptor_bytes(),
        limits(),
        KdfPolicy::baseline(),
        admission()
    )
    .is_err());
    assert!(Engine::diagnostic_open_with_access(
        legacy_access.descriptor_bytes(),
        limits(),
        KdfPolicy::baseline(),
        admission()
    )
    .is_ok());
    assert!(Engine::diagnostic_open_with_access(
        current.descriptor_bytes(),
        limits(),
        KdfPolicy::baseline(),
        admission()
    )
    .is_err());
}

#[test]
fn current_epoch_and_size_admission_precede_provider_or_password_work() {
    // The fixed 176-byte current framing overflows while the old 168-byte
    // arithmetic still fits. This is an encoded-width boundary, not a quota.
    let oversized = Limits {
        max_payload_bytes: usize::MAX - 170,
        max_metadata_bytes: 0,
        max_records: 1,
    };
    assert!(oversized.diagnostic_legacy_envelope_bytes().is_ok());
    let incompatible_policy =
        KdfPolicy::new(vec![KdfProfile::argon2id(65536, 4).unwrap()]).unwrap();
    let mut provider = Provider::default();
    assert!(matches!(
        Engine::create_with_access(
            PASSWORD,
            oversized,
            incompatible_policy,
            admission(),
            AccessProfile::PasswordAndDevice,
            &[identity()],
            false,
            &mut provider
        ),
        Err(Error::ResourceLimit)
    ));
    assert_eq!((provider.wraps, provider.unwraps), (0, 0));
    let engine = Engine::create(PASSWORD, limits()).unwrap();
    let mut changed = engine.descriptor_bytes().to_vec();
    changed[30..38].copy_from_slice(&1u64.to_be_bytes());
    let mut reopened = Engine::open(&changed, limits()).unwrap();
    assert!(matches!(
        reopened.begin_unlock(PASSWORD),
        Err(Error::Crypto(_))
    ));
    assert!(!reopened.is_unlocked());
}

#[test]
fn maintained_rebinding_cannot_enter_a_legacy_writable_profile() {
    let mut engine = Engine::create(PASSWORD, limits()).unwrap();
    let descriptor = engine.descriptor_bytes().to_vec();
    let token = engine.activate_created().unwrap();
    // This has the same vault identity and valid credential grammar. Legacy
    // diagnostic admission accepts its content-two tag; maintained rebinding
    // must reject it even though identity checks alone would pass.
    let mut legacy = descriptor.clone();
    legacy[12..14].copy_from_slice(&2u16.to_be_bytes());
    let diagnostic =
        Engine::diagnostic_open_with_access(&legacy, limits(), KdfPolicy::baseline(), admission())
            .unwrap();
    assert_eq!(diagnostic.vault_id(), engine.vault_id());
    assert!(matches!(
        engine.prepare_reopen_locked(&legacy),
        Err(Error::UnsupportedCapability)
    ));
    engine.check_session(&token).unwrap();
    assert_eq!(engine.descriptor_bytes(), descriptor);
    assert!(matches!(
        engine.reopen_locked(&legacy),
        Err(Error::UnsupportedCapability)
    ));
    assert!(!engine.is_unlocked());
    assert!(engine.check_session(&token).is_err());
    assert!(diagnostic.prepare_reopen_locked(&descriptor).is_ok());
}
