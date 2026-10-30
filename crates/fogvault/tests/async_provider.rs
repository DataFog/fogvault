//! Cooperative providers use the exact synchronous slot construction. This
//! synthetic oracle exercises job ownership, not hardware/provider qualification.
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, AuditRequest, Engine, Error, KdfPolicy,
    KeyProvider, Limits, NodeHash, NodeStore, ProviderCapabilityKind, ProviderContext,
    ProviderError, ProviderIdentity, ProviderReply, ProviderRequest, ProviderResult, RecordId,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
const PASSWORD: &[u8] = b"SYNTHETIC-cooperative-password";
fn identity(n: u8) -> ProviderIdentity {
    ProviderIdentity {
        provider_id: [1; 16],
        key_id: [n; 16],
        device_bound: true,
        nonexportable: true,
    }
}
fn bound() -> usize {
    ProviderContext {
        vault_id: [0; 16],
        root_epoch: 0,
        slot_id: [0; 16],
        slot_revision: 1,
        identity: identity(2),
    }
    .authenticated_bytes()
    .len()
}
fn admission(profile: AccessProfile) -> AccessAdmission {
    let max_descriptor_bytes = 108 + 72 + 2 * (64 + bound() + 112) + 96;
    AccessAdmission {
        allowed_profiles: vec![profile],
        providers: vec![identity(2), identity(3)],
        max_device_slots: 2,
        max_provider_blob_bytes: bound(),
        max_descriptor_bytes,
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 128,
        max_metadata_bytes: 16,
        max_records: 4,
    }
}
#[derive(Default)]
struct Provider(BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>);
impl KeyProvider for Provider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, c: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        let key = c.authenticated_bytes();
        self.0.insert(key.clone(), Zeroizing::new(*seed));
        Ok(key)
    }
    fn unwrap_seed(
        &mut self,
        c: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        if wrapped != c.authenticated_bytes() {
            return Err(ProviderError::IdentityChanged);
        }
        self.0
            .get(wrapped)
            .map(|seed| Zeroizing::new(**seed))
            .ok_or(ProviderError::Unavailable)
    }
}
fn reply(
    provider: &mut Provider,
    job: ProviderRequest,
) -> ([u8; 16], ProviderContext, ProviderReply) {
    let id = job.id();
    let context = job.context();
    let response = match job {
        ProviderRequest::WrapSeed { seed, .. } => {
            ProviderReply::Wrapped(provider.wrap_seed(&context, &seed).unwrap())
        }
        ProviderRequest::UnwrapSeed { wrapped, .. } => {
            ProviderReply::Unwrapped(provider.unwrap_seed(&context, &wrapped).unwrap())
        }
    };
    (id, context, response)
}
fn begin(profile: AccessProfile) -> fogvault::AsyncCreation {
    Engine::begin_create_access_async(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(profile),
        profile,
        &[identity(2), identity(3)],
        true,
        &[
            (identity(2), ProviderCapabilityKind::NonExportableOperation),
            (identity(3), ProviderCapabilityKind::NonExportableOperation),
        ],
    )
    .unwrap()
}
#[derive(Default)]
struct Memory {
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    records: BTreeMap<RecordId, (u64, Vec<u8>)>,
}
impl NodeStore for Memory {
    fn get(&mut self, h: &NodeHash) -> fogvault::Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(h).cloned())
    }
    fn put(&mut self, h: NodeHash, b: &[u8]) -> fogvault::Result<()> {
        self.nodes.insert(h, b.to_vec());
        Ok(())
    }
}
fn audit(engine: &mut Engine, head: &[u8], memory: &Memory) {
    engine.begin_audit(head).unwrap();
    loop {
        match engine.audit_next().unwrap() {
            AuditRequest::Node(hash) => engine.supply_node(&memory.nodes[&hash]).unwrap(),
            AuditRequest::Record { id, .. } => {
                let (revision, bytes) = &memory.records[&id];
                engine
                    .supply_record(*revision, bytes.len() as u64, Some(bytes))
                    .unwrap();
            }
            AuditRequest::Done => break,
        }
    }
    engine
        .finish_audit(memory.records.len() as u64, memory.nodes.len() as u64)
        .unwrap();
    engine.activate_audit().unwrap();
}
fn created(profile: AccessProfile) -> (Engine, Provider) {
    let mut creator = begin(profile);
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, value) = reply(&mut provider, job);
        creator.complete(id, &context, value).unwrap();
    }
    let (mut engine, _) = creator.finish().unwrap();
    engine.activate_created().unwrap();
    (engine, provider)
}
#[test]
fn asynchronous_creation_and_device_unlock_share_sync_formats_for_or_and_profiles() {
    for profile in [
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let (mut engine, mut provider) = created(profile);
        let id = [4; 16];
        let mut memory = Memory::default();
        let plan = engine
            .prepare_save(&mut memory, id, None, b"label", b"value", [5; 16], None)
            .unwrap();
        for h in &plan.obsolete {
            memory.nodes.remove(h);
        }
        memory.records.insert(id, (plan.revision, plan.envelope));
        engine.confirm_commit(&plan.head_bytes).unwrap();
        let head = engine.head_bytes().to_vec();
        let descriptor = engine.descriptor_bytes().to_vec();
        let slot = engine.access_info().unwrap().device_slots[0].0;
        engine.lock();
        let mut operation = engine
            .begin_unlock_device_async(
                slot,
                if profile == AccessProfile::PasswordAndDevice {
                    Some(PASSWORD)
                } else {
                    None
                },
                ProviderCapabilityKind::NonExportableOperation,
            )
            .unwrap();
        let (id, context, value) = reply(&mut provider, operation.request().unwrap().unwrap());
        operation.complete(id, &context, value).unwrap();
        engine.finish_unlock_device_async(operation).unwrap();
        assert!(engine.current_session().is_err());
        audit(&mut engine, &head, &memory);
        let proof = engine.lookup(&mut memory, &id_from_record()).unwrap();
        let (row_revision, row) = &memory.records[&id_from_record()];
        assert_eq!(
            engine
                .read_verified(proof.entry().unwrap(), *row_revision, row)
                .unwrap()
                .payload
                .as_slice(),
            b"value"
        );
        let mut reopened = Engine::open_with_access(
            &descriptor,
            limits(),
            KdfPolicy::baseline(),
            admission(profile),
        )
        .unwrap();
        reopened
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
        audit(&mut reopened, &head, &memory);
    }
}
fn id_from_record() -> RecordId {
    [4; 16]
}
#[test]
fn asynchronous_provider_jobs_reject_foreign_identity_and_wrong_phase_without_regenerating_seed() {
    let mut op = begin(AccessProfile::PasswordOrDevice);
    let mut provider = Provider::default();
    let first = op.request().unwrap().unwrap();
    let id = first.id();
    let context = first.context();
    let seed = match first {
        ProviderRequest::WrapSeed { seed, .. } => seed,
        _ => unreachable!(),
    };
    let mut wrong = id;
    wrong[0] ^= 1;
    assert!(matches!(
        op.complete(wrong, &context, ProviderReply::Wrapped(vec![])),
        Err(Error::Conflict)
    ));
    let mut foreign = context;
    foreign.identity.key_id[0] ^= 1;
    assert!(matches!(
        op.complete(id, &foreign, ProviderReply::Wrapped(vec![])),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        op.complete(
            id,
            &context,
            ProviderReply::Unwrapped(Zeroizing::new([0; 32]))
        ),
        Err(Error::Conflict)
    ));
    match op.request().unwrap().unwrap() {
        ProviderRequest::WrapSeed {
            seed: again,
            id: again_id,
            ..
        } => {
            assert_eq!(*again, *seed);
            assert_eq!(again_id, id);
        }
        _ => unreachable!(),
    }
    let wrapped = provider.wrap_seed(&context, &seed).unwrap();
    op.complete(id, &context, ProviderReply::Wrapped(wrapped))
        .unwrap();
    assert!(matches!(
        op.complete(id, &context, ProviderReply::Wrapped(vec![])),
        Err(Error::Conflict)
    ));
    let next = op.request().unwrap().unwrap();
    assert_ne!(next.id(), id);
    let (id, context, value) = reply(&mut provider, next);
    op.complete(id, &context, value).unwrap();
}
#[test]
fn asynchronous_creation_clears_failed_provider_results_and_refuses_unadmitted_capabilities() {
    let profile = AccessProfile::PasswordOrDevice;
    assert!(matches!(
        Engine::begin_create_access_async(
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
            admission(profile),
            profile,
            &[identity(2)],
            false,
            &[(identity(2), ProviderCapabilityKind::RawSecret)]
        ),
        Err(Error::UnsupportedCapability)
    ));
    let mut op = begin(profile);
    let job = op.request().unwrap().unwrap();
    let id = job.id();
    let context = job.context();
    assert!(matches!(
        op.complete(id, &context, ProviderReply::Wrapped(vec![0; bound() + 1])),
        Err(Error::ResourceLimit)
    ));
    assert!(op.request().is_err());
    assert!(op.finish().is_err());
    let mut op = begin(profile);
    let mut provider = Provider::default();
    let (id, context, response) = reply(&mut provider, op.request().unwrap().unwrap());
    op.complete(id, &context, response).unwrap();
    let job = op.request().unwrap().unwrap();
    let mut wrong = provider
        .unwrap_seed(
            &job.context(),
            match &job {
                ProviderRequest::UnwrapSeed { wrapped, .. } => wrapped,
                _ => unreachable!(),
            },
        )
        .unwrap();
    wrong[0] ^= 1;
    assert!(matches!(
        op.complete(job.id(), &job.context(), ProviderReply::Unwrapped(wrong)),
        Err(Error::Integrity)
    ));
    assert!(op.request().is_err());
}
#[test]
fn asynchronous_provider_callbacks_cannot_outlive_lock_or_change_host_admission() {
    let mut op = begin(AccessProfile::PasswordOrDevice);
    let job = op.request().unwrap().unwrap();
    op.revocation_handle().revoke();
    assert!(op
        .complete(job.id(), &job.context(), ProviderReply::Wrapped(vec![]))
        .is_err());
    assert!(op.finish().is_err());
    let (mut engine, mut provider) = created(AccessProfile::PasswordOrDevice);
    let slot = engine.access_info().unwrap().device_slots[0].0;
    engine.lock();
    let mut op = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    let (id, context, response) = reply(&mut provider, op.request().unwrap().unwrap());
    op.complete(id, &context, response).unwrap();
    engine.lock();
    assert!(engine.finish_unlock_device_async(op).is_err());
    assert!(engine.current_session().is_err());
    let (mut engine, mut provider) = created(AccessProfile::PasswordOrDevice);
    let slot = engine.access_info().unwrap().device_slots[0].0;
    engine.lock();
    let mut op = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    let (id, context, response) = reply(&mut provider, op.request().unwrap().unwrap());
    op.complete(id, &context, response).unwrap();
    let mut changed = admission(AccessProfile::PasswordOrDevice);
    changed.max_descriptor_bytes += 1;
    engine.configure_access_admission(changed).unwrap();
    assert!(matches!(
        engine.finish_unlock_device_async(op),
        Err(Error::Conflict)
    ));
    assert!(engine.current_session().is_err());
}
#[test]
fn asynchronous_unlock_response_cannot_transfer_candidate_keys_to_another_engine() {
    let (mut engine, mut provider) = created(AccessProfile::PasswordOrDevice);
    let descriptor = engine.descriptor_bytes().to_vec();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    engine.lock();
    let mut op = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    let (id, context, response) = reply(&mut provider, op.request().unwrap().unwrap());
    op.complete(id, &context, response).unwrap();
    let mut other = Engine::open_with_access(
        &descriptor,
        limits(),
        KdfPolicy::baseline(),
        admission(AccessProfile::PasswordOrDevice),
    )
    .unwrap();
    assert!(other.finish_unlock_device_async(op).is_err());
    assert!(other.current_session().is_err());
    assert!(engine.current_session().is_err());
}

#[test]
fn asynchronous_old_cancellation_cannot_revoke_a_new_unlock_generation() {
    let (mut engine, mut provider) = created(AccessProfile::PasswordOrDevice);
    let head = engine.head_bytes().to_vec();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    engine.lock();
    let mut old = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    let old_revoker = old.revocation_handle();
    let mut current = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    old.cancel();
    old_revoker.revoke();
    let (id, context, response) = reply(&mut provider, current.request().unwrap().unwrap());
    current.complete(id, &context, response).unwrap();
    engine.finish_unlock_device_async(current).unwrap();
    audit(&mut engine, &head, &Memory::default());
    assert!(engine.current_session().is_ok());
    // A creator's late cancellation handle is scoped too, after ownership has
    // transferred to the Engine and a later unlock created a new generation.
    let mut creator = begin(AccessProfile::PasswordOrDevice);
    let revoker = creator.revocation_handle();
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        creator.complete(id, &context, response).unwrap();
    }
    let (mut engine, _) = creator.finish().unwrap();
    engine.activate_created().unwrap();
    let head = engine.head_bytes().to_vec();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    engine.lock();
    let mut current = engine
        .begin_unlock_device_async(slot, None, ProviderCapabilityKind::NonExportableOperation)
        .unwrap();
    revoker.revoke();
    let (id, context, response) = reply(&mut provider, current.request().unwrap().unwrap());
    current.complete(id, &context, response).unwrap();
    engine.finish_unlock_device_async(current).unwrap();
    audit(&mut engine, &head, &Memory::default());
    assert!(engine.current_session().is_ok());
}

impl fogvault::TransitionStore for Memory {
    fn staged_record(
        &mut self,
        id: &RecordId,
        maximum: usize,
    ) -> fogvault::Result<Option<(u64, Vec<u8>)>> {
        if self
            .records
            .get(id)
            .is_some_and(|(_, bytes)| bytes.len() > maximum)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(self.records.get(id).cloned())
    }
}
fn drive_setup(op: &mut fogvault::AsyncAccessSetup, engine: &Engine, provider: &mut Provider) {
    while let Some(job) = op.request(engine).unwrap() {
        let (id, context, response) = reply(provider, job);
        op.complete(engine, id, &context, response).unwrap();
    }
}
fn save(engine: &mut Engine, memory: &mut Memory, id: RecordId, request: [u8; 16]) {
    let p = engine
        .prepare_save(
            memory,
            id,
            None,
            b"metadata",
            b"preserved body",
            request,
            None,
        )
        .unwrap();
    for h in &p.obsolete {
        memory.nodes.remove(h);
    }
    memory.records.insert(id, (p.revision, p.envelope));
    engine.confirm_commit(&p.head_bytes).unwrap();
}
#[test]
fn asynchronous_first_device_setup_preserves_records_and_latest_retry_intent() {
    let mut engine = Engine::create(PASSWORD, limits()).unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    let old = memory.records.clone();
    let mut provider = Provider::default();
    let profile = AccessProfile::PasswordOrDevice;
    let caps = [(identity(2), ProviderCapabilityKind::NonExportableOperation)];
    let mut op = engine
        .begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            b"SYNTHETIC-new",
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [6; 16],
        )
        .unwrap();
    drive_setup(&mut op, &engine, &mut provider);
    let (draft, _) = op.finish(&engine).unwrap();
    assert_eq!(draft.key_effect(), fogvault::KeyEffect::Preserved);
    let plan = engine.stage_credential_change(&draft).unwrap();
    let receipt = engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(memory.records, old);
    let proof = engine.lookup(&mut memory, &[4; 16]).unwrap();
    let (rev, bytes) = &memory.records[&[4; 16]];
    assert_eq!(
        engine
            .read_verified(proof.entry().unwrap(), *rev, bytes)
            .unwrap()
            .payload
            .as_slice(),
        b"preserved body"
    );
    assert!(engine.check_session(&receipt.session).is_ok());
    let retry = engine
        .begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            b"SYNTHETIC-new",
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [6; 16],
        )
        .unwrap();
    assert!(retry.request(&engine).unwrap().is_none());
    let (draft, key) = retry.finish(&engine).unwrap();
    assert!(key.is_none());
    let replay = engine.stage_credential_change(&draft).unwrap();
    assert!(replay.replay);
    assert_eq!(replay.receipt, receipt.receipt);
    assert!(matches!(
        engine.begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            b"SYNTHETIC-wrong",
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [6; 16]
        ),
        Err(Error::OperationIdReuse)
    ));
    assert!(matches!(
        engine.begin_access_setup_async(
            AccessPath::Password(b"SYNTHETIC-new"),
            ProviderCapabilityKind::RawSecret,
            b"SYNTHETIC-new",
            profile,
            &[identity(3)],
            false,
            admission(profile),
            &[(identity(3), ProviderCapabilityKind::NonExportableOperation)],
            [7; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
}
#[test]
fn asynchronous_existing_strict_device_maintenance_authenticates_before_rebuilding_slots() {
    let profile = AccessProfile::PasswordAndDevice;
    let (mut engine, mut provider) = created(profile);
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    let old = memory.records.clone();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    let caps = [(identity(3), ProviderCapabilityKind::NonExportableOperation)];
    let mut op = engine
        .begin_access_setup_maintenance_async(
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD),
            },
            ProviderCapabilityKind::NonExportableOperation,
            b"SYNTHETIC-new-strict",
            profile,
            &[identity(3)],
            true,
            admission(profile),
            &caps,
            [8; 16],
        )
        .unwrap();
    assert!(matches!(
        op.request(&engine).unwrap(),
        Some(ProviderRequest::UnwrapSeed { .. })
    ));
    drive_setup(&mut op, &engine, &mut provider);
    let (draft, key) = op.finish(&engine).unwrap();
    assert!(key.is_some());
    let plan = engine.stage_credential_change(&draft).unwrap();
    let receipt = engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(receipt.key_effect, fogvault::KeyEffect::Preserved);
    assert_eq!(memory.records, old);
    assert_eq!(engine.access_info().unwrap().device_slots[0].1, identity(3));
}
#[test]
fn asynchronous_access_callbacks_reject_changed_source_and_cancellation_preserves_live_vault() {
    let mut engine = Engine::create(PASSWORD, limits()).unwrap();
    let token = engine.activate_created().unwrap();
    let profile = AccessProfile::PasswordOrDevice;
    let caps = [(identity(2), ProviderCapabilityKind::NonExportableOperation)];
    let mut stale = engine
        .begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            PASSWORD,
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [7; 16],
        )
        .unwrap();
    let job = stale.request(&engine).unwrap().unwrap();
    let mut provider = Provider::default();
    let (id, context, response) = reply(&mut provider, job);
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    assert!(matches!(
        stale.complete(&engine, id, &context, response),
        Err(Error::Conflict)
    ));
    assert!(stale.finish(&engine).is_err());
    assert!(engine.check_session(&token).is_ok());
    let mut old = engine
        .begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            PASSWORD,
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [8; 16],
        )
        .unwrap();
    let cancel = old.cancellation_handle();
    let mut current = engine
        .begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            PASSWORD,
            profile,
            &[identity(2)],
            false,
            admission(profile),
            &caps,
            [9; 16],
        )
        .unwrap();
    old.cancel();
    cancel.cancel();
    assert!(engine.check_session(&token).is_ok());
    drive_setup(&mut current, &engine, &mut provider);
    assert!(current.finish(&engine).is_ok());
}
#[test]
fn asynchronous_protective_target_construction_uses_fresh_keys_and_same_bulk_planner() {
    let mut engine = Engine::create(PASSWORD, limits()).unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    let old = memory.records[&[4; 16]].1.clone();
    let profile = AccessProfile::PasswordAndDevice;
    let caps = [(identity(2), ProviderCapabilityKind::NonExportableOperation)];
    let mut provider = Provider::default();
    let mut op = engine
        .begin_protective_access_async(
            fogvault::ProtectiveSource::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            b"SYNTHETIC-protected",
            profile,
            &[identity(2)],
            true,
            admission(profile),
            &caps,
            [8; 16],
        )
        .unwrap();
    while let Some(job) = op.request(&engine).unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        op.complete(&engine, id, &context, response).unwrap();
    }
    let (mut transition, key) = op.finish(&engine).unwrap();
    assert!(key.is_some());
    assert_eq!(
        transition.key_effect(),
        fogvault::KeyEffect::FreshRootAndContentKeys
    );
    let control = transition.unanchored_control(&engine).unwrap();
    let proof = engine.protective_lookup(&mut memory, &[4; 16]).unwrap();
    let mut target = Memory::default();
    let encrypted = transition
        .transform_unanchored_record(
            &engine,
            proof.entry().unwrap(),
            1,
            &old,
            &mut target,
            &control,
        )
        .unwrap();
    assert_ne!(encrypted, old);
    target.records.insert([4; 16], (1, encrypted));
    let plan = transition
        .finish_unanchored(&engine, &mut target, &control)
        .unwrap();
    let control = control.authorize_submission(&transition, &plan).unwrap();
    engine
        .authorize_unanchored_protective_submission(&transition, &plan, &control)
        .unwrap();
    let control = control.confirm_target(&transition, &plan).unwrap();
    engine
        .confirm_unanchored_protective_transition(
            transition,
            &control,
            &plan.descriptor_bytes,
            &plan.head_bytes,
        )
        .unwrap();
    let proof = engine.lookup(&mut target, &[4; 16]).unwrap();
    let (rev, row) = &target.records[&[4; 16]];
    assert_eq!(
        engine
            .read_verified(proof.entry().unwrap(), *rev, row)
            .unwrap()
            .payload
            .as_slice(),
        b"preserved body"
    );
}

#[test]
fn asynchronous_named_device_replacement_refuses_lost_identity_before_provider_jobs() {
    let profile = AccessProfile::PasswordOrDevice;
    let (engine, _) = created(profile);
    let slot = engine
        .access_info()
        .unwrap()
        .device_slots
        .iter()
        .find(|(_, id)| *id == identity(2))
        .unwrap()
        .0;
    assert!(matches!(
        engine.begin_device_replacement_async(
            fogvault::ProtectiveSource::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            &[slot],
            PASSWORD,
            profile,
            &[identity(2)],
            true,
            admission(profile),
            &[(identity(2), ProviderCapabilityKind::NonExportableOperation)],
            [9; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    assert!(matches!(
        engine.begin_access_setup_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            PASSWORD,
            profile,
            &[identity(3)],
            true,
            admission(profile),
            &[(identity(3), ProviderCapabilityKind::NonExportableOperation)],
            [9; 16]
        ),
        Err(Error::UnsupportedCapability)
    ));
    let allowed = engine.begin_device_replacement_async(
        fogvault::ProtectiveSource::Password(PASSWORD),
        ProviderCapabilityKind::RawSecret,
        &[slot],
        PASSWORD,
        profile,
        &[identity(3)],
        true,
        admission(profile),
        &[(identity(3), ProviderCapabilityKind::NonExportableOperation)],
        [9; 16],
    );
    assert!(allowed.is_ok());
}
#[test]
fn asynchronous_recovery_replacement_returns_a_fresh_kit_and_keeps_source_read_restricted() {
    let profile = AccessProfile::PasswordOrDevice;
    let mut creator = begin(profile);
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        creator.complete(id, &context, response).unwrap();
    }
    let (mut engine, old_kit) = creator.finish().unwrap();
    let old_kit = old_kit.unwrap();
    engine.activate_created().unwrap();
    let mut source = Memory::default();
    save(&mut engine, &mut source, [4; 16], [5; 16]);
    let head = engine.head_bytes().to_vec();
    engine.lock();
    engine.begin_recovery(&old_kit).unwrap();
    audit(&mut engine, &head, &source);
    assert!(engine.current_session().is_err());
    let mut op = engine
        .begin_recovery_replacement_async(
            &old_kit,
            b"SYNTHETIC-recovered",
            profile,
            &[identity(3)],
            true,
            admission(profile),
            &[(identity(3), ProviderCapabilityKind::NonExportableOperation)],
            [9; 16],
        )
        .unwrap();
    while let Some(job) = op.request(&engine).unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        op.complete(&engine, id, &context, response).unwrap();
    }
    let (mut transition, new_kit) = op.finish(&engine).unwrap();
    let new_kit = new_kit.unwrap();
    assert_ne!(old_kit.export().as_slice(), new_kit.export().as_slice());
    assert!(engine.current_session().is_err());
    let control = transition.unanchored_control(&engine).unwrap();
    let proof = engine.protective_lookup(&mut source, &[4; 16]).unwrap();
    let (revision, row) = &source.records[&[4; 16]];
    let mut target = Memory::default();
    let encrypted = transition
        .transform_unanchored_record(
            &engine,
            proof.entry().unwrap(),
            *revision,
            row,
            &mut target,
            &control,
        )
        .unwrap();
    target.records.insert([4; 16], (*revision, encrypted));
    let plan = transition
        .finish_unanchored(&engine, &mut target, &control)
        .unwrap();
    let control = control.authorize_submission(&transition, &plan).unwrap();
    engine
        .authorize_unanchored_protective_submission(&transition, &plan, &control)
        .unwrap();
    let control = control.confirm_target(&transition, &plan).unwrap();
    engine
        .confirm_unanchored_protective_transition(
            transition,
            &control,
            &plan.descriptor_bytes,
            &plan.head_bytes,
        )
        .unwrap();
    let mut reopened = Engine::open_with_access(
        &plan.descriptor_bytes,
        limits(),
        KdfPolicy::baseline(),
        admission(profile),
    )
    .unwrap();
    assert!(reopened.begin_recovery(&old_kit).is_err());
    reopened.begin_recovery(&new_kit).unwrap();
    audit(&mut reopened, &plan.head_bytes, &target);
    assert!(reopened.current_session().is_err());
}

#[test]
fn asynchronous_and_password_change_and_kdf_upgrade_preserve_slots_recovery_and_records() {
    let base = fogvault::KdfProfile::baseline();
    let target = fogvault::KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
    let policy = KdfPolicy::new(vec![base, target]).unwrap();
    let profile = AccessProfile::PasswordAndDevice;
    let mut creator = Engine::begin_create_access_async(
        PASSWORD,
        limits(),
        policy.clone(),
        admission(profile),
        profile,
        &[identity(2), identity(3)],
        true,
        &[
            (identity(2), ProviderCapabilityKind::NonExportableOperation),
            (identity(3), ProviderCapabilityKind::NonExportableOperation),
        ],
    )
    .unwrap();
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        creator.complete(id, &context, response).unwrap();
    }
    let (mut engine, kit) = creator.finish().unwrap();
    let kit = kit.unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    let ciphertext = memory.records.clone();
    let slots = engine.access_info().unwrap().device_slots;
    let slot = slots[0].0;
    let provider_entries = provider.0.len();
    let mut password = engine
        .begin_access_password_change_async(
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD),
            },
            ProviderCapabilityKind::NonExportableOperation,
            b"SYNTHETIC-new-AND",
            base,
            [7; 16],
        )
        .unwrap();
    assert!(matches!(
        password.request(&engine).unwrap(),
        Some(ProviderRequest::UnwrapSeed { .. })
    ));
    drive_setup(&mut password, &engine, &mut provider);
    let (draft, new_kit) = password.finish(&engine).unwrap();
    assert!(new_kit.is_none());
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(engine.access_info().unwrap().device_slots, slots);
    assert_eq!(provider.0.len(), provider_entries);
    assert_eq!(memory.records, ciphertext);
    let mut upgrade = engine
        .begin_kdf_upgrade_access_async(
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-new-AND"),
            },
            ProviderCapabilityKind::NonExportableOperation,
            target,
            [8; 16],
        )
        .unwrap();
    drive_setup(&mut upgrade, &engine, &mut provider);
    let (draft, _) = upgrade.finish(&engine).unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    let receipt = engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    assert_eq!(receipt.key_effect, fogvault::KeyEffect::Preserved);
    assert_eq!(engine.kdf_profile(), target);
    assert_eq!(engine.access_info().unwrap().device_slots, slots);
    assert_eq!(provider.0.len(), provider_entries);
    assert_eq!(memory.records, ciphertext);
    let mut reopened =
        Engine::open_with_access(&plan.descriptor_bytes, limits(), policy, admission(profile))
            .unwrap();
    reopened.begin_recovery(&kit).unwrap();
    audit(&mut reopened, &plan.head_bytes, &memory);
    assert!(reopened.current_session().is_err());
}
#[test]
fn asynchronous_kdf_upgrade_does_not_treat_a_convenience_device_as_password_equality() {
    let base = fogvault::KdfProfile::baseline();
    let target = fogvault::KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
    let policy = KdfPolicy::new(vec![base, target]).unwrap();
    let profile = AccessProfile::PasswordOrDevice;
    let mut creator = Engine::begin_create_access_async(
        PASSWORD,
        limits(),
        policy,
        admission(profile),
        profile,
        &[identity(2)],
        false,
        &[(identity(2), ProviderCapabilityKind::NonExportableOperation)],
    )
    .unwrap();
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        creator.complete(id, &context, response).unwrap();
    }
    let (mut engine, _) = creator.finish().unwrap();
    engine.activate_created().unwrap();
    let slot = engine.access_info().unwrap().device_slots[0].0;
    assert!(matches!(
        engine.begin_kdf_upgrade_access_async(
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-wrong")
            },
            ProviderCapabilityKind::NonExportableOperation,
            target,
            [8; 16]
        ),
        Err(Error::Crypto(fogvault::CryptoError::AuthenticationFailed))
    ));
    assert_eq!(engine.kdf_profile(), base);
}

#[test]
fn asynchronous_enrollment_preserves_offline_existing_slots_and_owner_recovery() {
    let profile = AccessProfile::PasswordOrDevice;
    let mut creator = Engine::begin_create_access_async(
        PASSWORD,
        limits(),
        KdfPolicy::baseline(),
        admission(profile),
        profile,
        &[identity(2)],
        true,
        &[(identity(2), ProviderCapabilityKind::NonExportableOperation)],
    )
    .unwrap();
    let mut provider = Provider::default();
    while let Some(job) = creator.request().unwrap() {
        let (id, context, response) = reply(&mut provider, job);
        creator.complete(id, &context, response).unwrap();
    }
    let (mut engine, kit) = creator.finish().unwrap();
    let kit = kit.unwrap();
    engine.activate_created().unwrap();
    let mut memory = Memory::default();
    save(&mut engine, &mut memory, [4; 16], [5; 16]);
    let original = memory.records.clone();
    let old_slot = engine.access_info().unwrap().device_slots[0];
    provider.0.clear(); // original device is unavailable; password authentication remains valid.
    let mut op = engine
        .begin_enroll_device_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            identity(3),
            admission(profile),
            ProviderCapabilityKind::NonExportableOperation,
            [9; 16],
        )
        .unwrap();
    let mut jobs = 0;
    while let Some(job) = op.request(&engine).unwrap() {
        assert_eq!(job.context().identity, identity(3));
        jobs += 1;
        let (id, context, response) = reply(&mut provider, job);
        op.complete(&engine, id, &context, response).unwrap();
    }
    assert_eq!(jobs, 2);
    let (draft, key) = op.finish(&engine).unwrap();
    assert!(key.is_none());
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let slots = engine.access_info().unwrap().device_slots;
    assert_eq!(slots.len(), 2);
    assert!(slots.contains(&old_slot));
    assert_eq!(memory.records, original);
    let retry = engine
        .begin_enroll_device_async(
            AccessPath::Password(PASSWORD),
            ProviderCapabilityKind::RawSecret,
            identity(3),
            admission(profile),
            ProviderCapabilityKind::NonExportableOperation,
            [9; 16],
        )
        .unwrap();
    assert!(retry.request(&engine).unwrap().is_none());
    let (draft, _) = retry.finish(&engine).unwrap();
    assert!(engine.stage_credential_change(&draft).unwrap().replay);
    let mut reopened = Engine::open_with_access(
        &plan.descriptor_bytes,
        limits(),
        KdfPolicy::baseline(),
        admission(profile),
    )
    .unwrap();
    reopened.begin_recovery(&kit).unwrap();
    audit(&mut reopened, &plan.head_bytes, &memory);
    assert!(reopened.current_session().is_err());
}
