//! Exact published beta.3 remains an opaque consumer through protective rotation.
//! In-memory atomic adapter and synthetic provider; durable host proof is separate.
use datafog_core::workspace::{Workspace, MAX_BUNDLE_BYTES};
use fogvault::{
    control::{ControlOperation, ControlState},
    AccessAdmission, AccessPath, AccessProfile, AuditRequest, Engine, Error, KdfPolicy,
    KeyProvider, Limits, NodeHash, NodeStore, ProtectiveSource, ProviderCapabilityKind,
    ProviderContext, ProviderError, ProviderIdentity, ProviderResult, RecordId, Result,
    TransitionStore,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

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
        if self.nodes.get(&hash).is_some_and(|prior| prior != bytes) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, bytes.to_vec());
        Ok(())
    }
}
impl TransitionStore for Memory {
    fn staged_record(&mut self, id: &RecordId, maximum: usize) -> Result<Option<(u64, Vec<u8>)>> {
        if self
            .rows
            .get(id)
            .is_some_and(|(_, bytes)| bytes.len() > maximum)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(self.rows.get(id).cloned())
    }
}
#[derive(Default)]
struct SyntheticProvider {
    seeds: BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>,
}
impl KeyProvider for SyntheticProvider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation // declaration only: synthetic oracle
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        let handle = context.authenticated_bytes();
        self.seeds.insert(handle.clone(), Zeroizing::new(*seed));
        Ok(handle)
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        if context.authenticated_bytes() != wrapped {
            return Err(ProviderError::IdentityChanged);
        }
        self.seeds
            .get(wrapped)
            .map(|seed| Zeroizing::new(**seed))
            .ok_or(ProviderError::Unavailable)
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
fn exact_beta3_bundle_and_complete_head_survive_protective_transition_and_reopen() {
    let password = b"SYNTHETIC-beta3-protective-password";
    let namespace = [0x23; 16];
    let mut workspace = Workspace::create(namespace, [0x24; 16]).unwrap();
    let core_head = workspace.head().unwrap();
    let bundle = Zeroizing::new(workspace.export_bundle().unwrap());
    let mut metadata = namespace.to_vec();
    metadata.extend_from_slice(&core_head.revision.to_be_bytes());
    metadata.extend_from_slice(&core_head.commit_id);
    let limits = Limits {
        max_payload_bytes: MAX_BUNDLE_BYTES,
        max_metadata_bytes: metadata.len(),
        max_records: 1,
    };
    let mut engine = Engine::create(password, limits).unwrap();
    engine.activate_created().unwrap();
    let id = [0x25; 16];
    let mut source = Memory::default();
    let save = engine
        .prepare_save(&mut source, id, None, &metadata, &bundle, [0x26; 16], None)
        .unwrap();
    source.rows.insert(id, (save.revision, save.envelope));
    engine.confirm_commit(&save.head_bytes).unwrap();
    let identity = ProviderIdentity {
        provider_id: [1; 16],
        key_id: [2; 16],
        device_bound: true,
        nonexportable: true,
    };
    let provider_context_bytes = ProviderContext {
        vault_id: engine.vault_id(),
        root_epoch: 1,
        slot_id: [0; 16],
        slot_revision: 1,
        identity,
    }
    .authenticated_bytes()
    .len();
    let admission = AccessAdmission {
        allowed_profiles: vec![AccessProfile::PasswordAndDevice],
        providers: vec![identity],
        max_device_slots: 1,
        // Exact ProviderContext width from this synthetic provider, not a host capacity.
        max_provider_blob_bytes: provider_context_bytes,
        max_descriptor_bytes: 108 + 64 + provider_context_bytes + 112 + 96,
    };
    let mut provider = SyntheticProvider::default();
    let request = [0x27; 16];
    let (mut transition, recovery) = engine
        .draft_protective_transition(
            ProtectiveSource::Password(password),
            password,
            AccessProfile::PasswordAndDevice,
            &[identity],
            true,
            &mut provider,
            admission.clone(),
            request,
        )
        .unwrap();
    assert!(recovery.is_some());
    let control =
        ControlState::register(engine.vault_id(), [0x28; 16], transition.source_snapshot());
    let control = control
        .prepare(
            ControlOperation::ProtectiveTransition,
            request,
            transition.target_descriptor_digest(),
            transition.owner_commitment(),
        )
        .unwrap();
    let proof = engine.protective_lookup(&mut source, &id).unwrap();
    let old = source.rows.get(&id).unwrap();
    let mut target = Memory::default();
    let envelope = transition
        .transform_record(
            &engine,
            proof.entry().unwrap(),
            old.0,
            &old.1,
            &mut target,
            &control,
        )
        .unwrap();
    assert_ne!(envelope, old.1);
    target.rows.insert(id, (old.0, envelope));
    let plan = transition.finish(&engine, &mut target, &control).unwrap();
    let submitted = control
        .authorize_submission(plan.target_snapshot())
        .unwrap();
    engine
        .authorize_protective_submission(&transition, &plan, &submitted)
        .unwrap();
    assert!(matches!(
        engine.lookup(&mut source, &id),
        Err(Error::OutcomeUnknown { .. })
    ));
    // This fixture's complete atomic adapter publishes exactly the validated target.
    let completed = submitted.confirm_target(plan.target_snapshot()).unwrap();
    engine
        .confirm_protective_transition(
            transition,
            &completed,
            &plan.descriptor_bytes,
            &plan.head_bytes,
        )
        .unwrap();
    let token = engine.current_session().unwrap();
    let proof = engine.lookup(&mut target, &id).unwrap();
    let (revision, envelope) = &target.rows[&id];
    let record = engine
        .read_verified(proof.entry().unwrap(), *revision, envelope)
        .unwrap();
    assert_eq!(record.payload.as_slice(), bundle.as_slice());
    assert_eq!(record.metadata.as_slice(), metadata);
    let mut restored = Workspace::open_bundle(&record.payload).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), core_head); // revision AND commit ID
    engine.lock();
    workspace.close();
    restored.close();
    assert!(matches!(engine.check_session(&token), Err(Error::Locked)));
    let mut reopened = Engine::open_epoch_access(
        &plan.descriptor_bytes,
        limits,
        KdfPolicy::baseline(),
        admission,
    )
    .unwrap();
    assert!(reopened
        .begin_unlock_access(AccessPath::Password(password), &mut provider)
        .is_err());
    let slot = reopened.access_info().unwrap().device_slots[0].0;
    reopened
        .begin_unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(password),
            },
            &mut provider,
        )
        .unwrap();
    audit(&mut reopened, &plan.head_bytes, &target);
    let proof = reopened.lookup(&mut target, &id).unwrap();
    let (revision, envelope) = &target.rows[&id];
    let record = reopened
        .read_verified(proof.entry().unwrap(), *revision, envelope)
        .unwrap();
    assert_eq!(record.payload.as_slice(), bundle.as_slice());
    let mut restored = Workspace::open_bundle(&record.payload).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), core_head);
    restored.close();
    reopened.lock();
}
