//! Candidate full-content transition. Storage and durable control-state writes
//! remain host operations; this planner never exports unwrapped keys.
use super::*;
use crate::{
    AccessAdmission, AccessPath, AccessProfile, KeyProvider, ProviderCapabilityKind,
    ProviderContext, ProviderIdentity, ProviderResult, RecoveryKey,
};

use crate::control::{ControlOperation, ControlState, SnapshotIdentity};

const OWNER_DOMAIN: &[u8] = b"fogvault/prototype/protective-owner/v1";
const STAGING_DOMAIN: &[u8] = b"protective-staging/v1";
const CHECKPOINT_MAGIC: &[u8; 8] = b"FGVPRT01";
/// 8-byte version, 32-byte owner commitment, 58-byte progress, nonce24/tag16.
const CHECKPOINT_BYTES: usize = 138;

pub enum ProtectiveSource<'a> {
    Password(&'a [u8]),
    Access(AccessPath<'a>),
    Recovery(&'a RecoveryKey),
}

/// One bounded encrypted row at a time. A host must admit the stored length
/// before allocating and return data from its coherent isolated staging state.
pub trait TransitionStore: NodeStore {
    fn staged_record(
        &mut self,
        id: &RecordId,
        maximum_envelope_bytes: usize,
    ) -> Result<Option<(u64, Vec<u8>)>>;
}

/// Opaque secret-owning operation; deliberately not Clone/Debug/serializable.
pub struct ProtectiveTransition {
    source_descriptor: Descriptor,
    source_head: IndexHead,
    source_head_bytes: Vec<u8>,
    source_session: SessionToken,
    work: WorkGuard,
    target_descriptor: Descriptor,
    target_keys: Keys,
    staging_key: Zeroizing<[u8; 32]>,
    target_session: SessionToken,
    admission: AccessAdmission,
    request: [u8; 16],
    commitment: [u8; 32],
    processed: u64,
    last_id: Option<RecordId>,
    target_root: Option<crate::NodeHash>,
    limits: Limits,
}

/// Encrypted objects are already isolated in the adapter's staging namespace.
/// Publish its complete graph with these paired headers under one source CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectivePlan {
    pub prior_descriptor: Vec<u8>,
    pub prior_head: Vec<u8>,
    pub descriptor_bytes: Vec<u8>,
    pub head_bytes: Vec<u8>,
    pub receipt: CommitReceipt,
    /// Reachable target graph only. Staging can contain obsolete/orphan objects.
    pub index_root: Option<crate::NodeHash>,
    pub record_count: u64,
}
impl ProtectivePlan {
    pub fn key_effect(&self) -> crate::KeyEffect {
        crate::KeyEffect::FreshRootAndContentKeys
    }
    pub fn target_snapshot(&self) -> SnapshotIdentity {
        SnapshotIdentity {
            descriptor_digest: crypto::digest(&self.descriptor_bytes),
            head_digest: self.receipt.head_digest,
            generation: self.receipt.generation,
        }
    }
}

struct Guarded<'a> {
    provider: &'a mut dyn KeyProvider,
    work: &'a WorkGuard,
}
impl KeyProvider for Guarded<'_> {
    fn capability_kind(&self, identity: &ProviderIdentity) -> ProviderCapabilityKind {
        self.provider.capability_kind(identity)
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        self.work
            .check()
            .map_err(|_| crate::ProviderError::Cancelled)?;
        let value = self.provider.wrap_seed(context, seed);
        self.work
            .check()
            .map_err(|_| crate::ProviderError::Cancelled)?;
        value
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        bytes: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        self.work
            .check()
            .map_err(|_| crate::ProviderError::Cancelled)?;
        let value = self.provider.unwrap_seed(context, bytes);
        self.work
            .check()
            .map_err(|_| crate::ProviderError::Cancelled)?;
        value
    }
}

impl Engine {
    /// Explicitly admit the epoch-aware record profile. Ordinary P3 opening
    /// continues to reject it rather than silently interpreting changed bytes.
    pub fn open_epoch_access(
        descriptor: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Self> {
        crate::validate_policy(limits)?;
        let descriptor = Descriptor::parse_epoch_access(descriptor, &admission, &kdf_policy)?;
        descriptor.envelope_limit(limits)?;
        Ok(Self {
            descriptor,
            head: Self::empty_head()?,
            head_bytes: Vec::new(),
            limits,
            kdf_policy,
            keys: None,
            session: None,
            initializing: false,
            pending: None,
            audit: None,
            authority: PublicationAuthority::new(false),
            access_admission: Some(admission),
            recovery_candidate: false,
        })
    }

    fn protective_source_session(&self) -> Result<SessionToken> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        if self.audit.is_some() || self.pending.is_some() || self.initializing {
            return Err(Error::Conflict);
        }
        if self.recovery_candidate {
            self.session.ok_or(Error::Locked)
        } else {
            self.current_session()
        }
    }

    /// Lookup for the private full-content operation. A restricted recovery
    /// candidate gets authenticated encrypted-object proofs, never read authority.
    pub fn protective_lookup<S: NodeStore + ?Sized>(
        &self,
        store: &mut S,
        id: &RecordId,
    ) -> Result<VerifiedLookup> {
        let session = self.protective_source_session()?;
        let found = index::lookup(store, self.head.root, id)?;
        let head_digest = crypto::digest(&self.head_bytes);
        Ok(VerifiedLookup {
            id: *id,
            session,
            head_digest,
            entry: found.entry.map(|entry| VerifiedRecord {
                id: *id,
                entry,
                session,
                head_digest,
            }),
            stats: found.stats,
        })
    }
    /// Loss/exposure response: exclude every named old device key and use the
    /// fresh-root/full-content planner. Historical copies remain readable under
    /// their old factors; the selected new graph uses fresh key material.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_device_replacement(
        &self,
        source: ProtectiveSource<'_>,
        removed_slots: &[[u8; 16]],
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(ProtectiveTransition, Option<RecoveryKey>)> {
        self.protective_source_session()?;
        if removed_slots.is_empty() {
            return Err(Error::Malformed("missing replaced device"));
        }
        let current = self.access_info()?;
        for (index, slot) in removed_slots.iter().enumerate() {
            if removed_slots[..index].contains(slot) {
                return Err(Error::Malformed("duplicate replaced device"));
            }
            let old = current
                .device_slots
                .iter()
                .find(|(id, _)| id == slot)
                .ok_or(Error::NotFound)?
                .1;
            if devices
                .iter()
                .any(|target| target.provider_id == old.provider_id && target.key_id == old.key_id)
            {
                return Err(Error::UnsupportedCapability);
            }
        }
        self.draft_protective_transition(
            source,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )
    }
    /// A recovery-secret replacement always generates fresh root/content keys
    /// and (when requested) a new random recovery secret through the planner.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_recovery_replacement(
        &self,
        key: &RecoveryKey,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(ProtectiveTransition, Option<RecoveryKey>)> {
        self.draft_protective_transition(
            ProtectiveSource::Recovery(key),
            new_password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn draft_protective_transition(
        &self,
        source: ProtectiveSource<'_>,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(ProtectiveTransition, Option<RecoveryKey>)> {
        let session = self.protective_source_session()?;
        if self.head.request_id == request {
            return Err(Error::OperationIdReuse);
        }
        self.head
            .generation
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        admission.profile(profile)?;
        if devices.len() > admission.max_device_slots
            || (profile == AccessProfile::Portable) != devices.is_empty()
        {
            return Err(Error::UnsupportedCapability);
        }
        for identity in devices {
            admission.provider(*identity)?;
        }
        let epoch = self
            .descriptor
            .root_epoch()
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let policy_epoch = if self.descriptor.credential_format_id() == 3 {
            self.access_info()?
                .policy_epoch
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?
        } else {
            1
        };
        let work = self.authority.work()?;
        let mut guarded = Guarded {
            provider,
            work: &work,
        };
        let root = match source {
            ProtectiveSource::Password(password) if !self.recovery_candidate => self
                .descriptor
                .unlock_with_policy(password, &self.kdf_policy)?,
            ProtectiveSource::Access(path) if !self.recovery_candidate => {
                self.descriptor.access()?.unlock(
                    &path,
                    &mut guarded,
                    self.access_admission
                        .as_ref()
                        .ok_or(Error::UnsupportedCapability)?,
                    &self.kdf_policy,
                )?
            }
            ProtectiveSource::Recovery(key) if self.recovery_candidate => {
                self.descriptor.access()?.recover(key)?
            }
            _ => return Err(Error::UnsupportedCapability),
        };
        let authenticated = Self::derive(&root, &self.descriptor)?;
        if !crypto::tags_match(&authenticated.wrapping, &self.raw_keys()?.wrapping) {
            return Err(Error::Integrity);
        }
        let new_root = Zeroizing::new(crypto::random::<32>()?);
        if crypto::tags_match(&root, &new_root) {
            return Err(Error::Integrity);
        }
        let (target, key) = format::AccessDescriptor::new(
            self.vault_id(),
            epoch,
            policy_epoch,
            &new_root,
            new_password,
            self.kdf_profile(),
            profile,
            devices,
            recovery,
            &mut guarded,
            &admission,
            &self.kdf_policy,
        )?;
        let target_descriptor = target.epoch_content()?.descriptor();
        target_descriptor.envelope_limit(self.limits)?;
        let target_keys = Self::derive(&new_root, &target_descriptor)?;
        let staging_key = crypto::derive(&new_root, &self.vault_id(), STAGING_DOMAIN)?;
        let commitment = ProtectiveTransition::binding(
            &self.descriptor,
            &self.head_bytes,
            &target_descriptor,
            request,
        );
        let target_session = SessionToken {
            vault_id: self.vault_id(),
            nonce: crypto::random()?,
        };
        work.check()?;
        Ok((
            ProtectiveTransition {
                source_descriptor: self.descriptor.clone(),
                source_head: self.head.clone(),
                source_head_bytes: self.head_bytes.clone(),
                source_session: session,
                work,
                target_descriptor,
                target_keys,
                staging_key,
                target_session,
                admission,
                request,
                commitment,
                processed: 0,
                last_id: None,
                target_root: None,
                limits: self.limits,
            },
            key,
        ))
    }

    /// Caller must have persisted this exact submission authorization to the
    /// independently trusted control store BEFORE submitting the database write.
    /// Once this barrier is set, only dedicated target reconciliation is allowed.
    pub fn authorize_protective_submission(
        &mut self,
        transition: &ProtectiveTransition,
        plan: &ProtectivePlan,
        control: &ControlState,
    ) -> Result<()> {
        transition.check_source(self)?;
        transition.check_control(control)?;
        if control.pending().and_then(|pending| pending.submission())
            != Some(plan.target_snapshot())
            || transition.plan()? != *plan
        {
            return Err(Error::Conflict);
        }
        let head = transition.target_head();
        self.pending = Some(Pending {
            head,
            bytes: plan.head_bytes.clone(),
            unknown: true,
            descriptor: Some(transition.target_descriptor.clone()),
            replacement_session: Some(transition.target_session),
            access_admission: Some(transition.admission.clone()),
            protective: true,
            ordinary_binding: None,
        });
        Ok(())
    }

    /// The host must confirm and persist the exact target in trusted control
    /// state first. Confirmation does no entropy/KDF/provider work.
    pub fn confirm_protective_transition(
        &mut self,
        transition: ProtectiveTransition,
        control: &ControlState,
        descriptor: &[u8],
        head: &[u8],
    ) -> Result<CredentialReceipt> {
        transition.work.check()?;
        let plan = transition.plan()?;
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if !pending.protective
            || !pending.unknown
            || pending.head.request_id != transition.request
            // Bind the opaque callback to the exact admitted draft, not merely
            // its request ID. A second owner-created draft can share that ID
            // while holding different keys, policy and target head.
            || pending.head != transition.target_head()
            || pending.bytes != plan.head_bytes
            || pending.descriptor.as_ref().map(Descriptor::bytes)
                != Some(plan.descriptor_bytes.as_slice())
            || pending.replacement_session != Some(transition.target_session)
            || pending.access_admission.as_ref() != Some(&transition.admission)
            || control.vault_id() != self.vault_id()
            || control.pending().is_some()
            || control.accepted() != plan.target_snapshot()
            || descriptor != plan.descriptor_bytes
            || head != plan.head_bytes
            || self.descriptor.hash() != transition.source_descriptor.hash()
            || self.head_bytes != transition.source_head_bytes
            || self.session != Some(transition.source_session)
        {
            return Err(Error::Conflict);
        }
        self.keys = Some(transition.target_keys);
        self.descriptor = transition.target_descriptor;
        self.head = pending.head.clone();
        self.head_bytes = plan.head_bytes;
        self.session = Some(transition.target_session);
        self.access_admission = Some(transition.admission);
        self.pending = None;
        self.audit = None;
        self.recovery_candidate = false;
        Ok(CredentialReceipt {
            receipt: plan.receipt,
            session: transition.target_session,
            key_effect: crate::KeyEffect::FreshRootAndContentKeys,
        })
    }
}

impl ProtectiveTransition {
    pub fn key_effect(&self) -> crate::KeyEffect {
        crate::KeyEffect::FreshRootAndContentKeys
    }
    fn binding(
        source: &Descriptor,
        head: &[u8],
        target: &Descriptor,
        request: [u8; 16],
    ) -> [u8; 32] {
        let mut bytes = format::frame(OWNER_DOMAIN);
        bytes.extend_from_slice(&source.hash());
        bytes.extend_from_slice(&crypto::digest(head));
        bytes.extend_from_slice(&target.hash());
        bytes.extend_from_slice(&request);
        bytes.push(1); // full content re-encryption; no wrapping-only reinterpretation
        crypto::digest(&bytes)
    }
    pub fn owner_commitment(&self) -> [u8; 32] {
        self.commitment
    }
    pub fn target_descriptor_bytes(&self) -> &[u8] {
        self.target_descriptor.bytes()
    }
    pub fn target_descriptor_digest(&self) -> [u8; 32] {
        self.target_descriptor.hash()
    }
    pub fn source_snapshot(&self) -> SnapshotIdentity {
        SnapshotIdentity {
            descriptor_digest: self.source_descriptor.hash(),
            head_digest: crypto::digest(&self.source_head_bytes),
            generation: self.source_head.generation,
        }
    }
    pub fn processed_records(&self) -> u64 {
        self.processed
    }
    fn check_source(&self, source: &Engine) -> Result<()> {
        self.work.check()?;
        if source.protective_source_session()? != self.source_session
            || source.descriptor.hash() != self.source_descriptor.hash()
            || source.head_bytes != self.source_head_bytes
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn check_control(&self, control: &ControlState) -> Result<()> {
        let pending = control.pending().ok_or(Error::Conflict)?;
        if control.vault_id() != self.source_descriptor.vault_id
            || control.accepted() != self.source_snapshot()
            || pending.operation != ControlOperation::ProtectiveTransition
            || pending.request_id != self.request
            || pending.target_descriptor_digest != self.target_descriptor.hash()
            || pending.owner_commitment != self.commitment
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Source proof is bound to the accepted snapshot and session. Strict ID
    /// order plus complete source count prevents omission/duplicate substitution.
    pub fn transform_record<S: NodeStore + ?Sized>(
        &mut self,
        source: &Engine,
        proof: &VerifiedRecord,
        stored_revision: u64,
        envelope: &[u8],
        target_nodes: &mut S,
        control: &ControlState,
    ) -> Result<Vec<u8>> {
        self.check_source(source)?;
        self.check_control(control)?;
        if control
            .pending()
            .and_then(|pending| pending.submission())
            .is_some()
            || self.processed >= self.source_head.count
            || self.last_id.is_some_and(|previous| previous >= proof.id)
        {
            return Err(Error::Conflict);
        }
        if proof.session != self.source_session
            || proof.head_digest != crypto::digest(&self.source_head_bytes)
            || proof.entry.revision != stored_revision
            || envelope.len() < self.source_descriptor.envelope_minimum()
            || envelope.len() > self.source_descriptor.envelope_limit(self.limits)?
            || crypto::digest(envelope) != proof.entry.digest
        {
            return Err(Error::Integrity);
        }
        let decoded = format::decrypt_record(
            &self.source_descriptor,
            &source.raw_keys()?.wrapping,
            &proof.id,
            stored_revision,
            envelope,
            self.limits,
        )?;
        let next = format::encrypt_record(
            &self.target_descriptor,
            &self.target_keys.wrapping,
            &proof.id,
            stored_revision,
            &decoded.metadata,
            &decoded.payload,
            self.limits,
        )?;
        self.work.check()?;
        let change = index::upsert(
            target_nodes,
            self.target_root,
            proof.id,
            Entry {
                revision: stored_revision,
                digest: crypto::digest(&next),
            },
        )?;
        if change.previous.is_some() {
            return Err(Error::Integrity);
        }
        self.work.check()?;
        self.target_root = Some(change.root);
        self.last_id = Some(proof.id);
        self.processed = self.processed.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(next)
    }
    fn audit_target<S: TransitionStore + ?Sized>(&self, store: &mut S) -> Result<()> {
        let maximum = self
            .processed
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .unwrap_or(0);
        let mut cursor = index::AuditCursor::new(self.target_root, maximum);
        let mut checked = 0u64;
        let mut last = None;
        while let Some(hash) = cursor.next_hash()? {
            self.work.check()?;
            let bytes = store.get(&hash)?.ok_or(Error::Integrity)?;
            if let Some((id, entry)) = cursor.supply(&bytes)? {
                let (revision, envelope) = store
                    .staged_record(&id, self.target_descriptor.envelope_limit(self.limits)?)?
                    .ok_or(Error::Integrity)?;
                if revision != entry.revision || crypto::digest(&envelope) != entry.digest {
                    return Err(Error::Integrity);
                }
                format::decrypt_record(
                    &self.target_descriptor,
                    &self.target_keys.wrapping,
                    &id,
                    revision,
                    &envelope,
                    self.limits,
                )?;
                checked = checked.checked_add(1).ok_or(Error::ResourceLimit)?;
                last = Some(id);
            }
        }
        let stats = cursor.finish()?;
        if checked != self.processed || stats.nodes_read != maximum || last != self.last_id {
            return Err(Error::Integrity);
        }
        self.work.check()
    }
    fn target_head(&self) -> IndexHead {
        let mut identity = format::frame(b"fogvault/prototype/protective-full/v1");
        identity.extend_from_slice(&self.commitment);
        IndexHead {
            generation: self.source_head.generation + 1,
            request_id: self.request,
            operation_digest: crypto::mac(&self.target_keys.operation, &identity),
            count: self.source_head.count,
            root: self.target_root,
        }
    }
    fn plan(&self) -> Result<ProtectivePlan> {
        if self.processed != self.source_head.count {
            return Err(Error::Conflict);
        }
        let head = self.target_head();
        let bytes = head.encode(&self.target_descriptor, &self.target_keys.head);
        Ok(ProtectivePlan {
            prior_descriptor: self.source_descriptor.bytes().to_vec(),
            prior_head: self.source_head_bytes.clone(),
            descriptor_bytes: self.target_descriptor.bytes().to_vec(),
            receipt: Engine::receipt(&head, &bytes),
            head_bytes: bytes,
            index_root: self.target_root,
            record_count: self.source_head.count,
        })
    }
    pub fn finish<S: TransitionStore + ?Sized>(
        &self,
        source: &Engine,
        store: &mut S,
        control: &ControlState,
    ) -> Result<ProtectivePlan> {
        self.check_source(source)?;
        self.check_control(control)?;
        self.audit_target(store)?;
        let plan = self.plan()?;
        if control
            .pending()
            .and_then(|pending| pending.submission())
            .is_some_and(|target| target != plan.target_snapshot())
        {
            return Err(Error::Conflict);
        }
        self.work.check()?;
        Ok(plan)
    }
    pub fn checkpoint(&self, source: &Engine, control: &ControlState) -> Result<Vec<u8>> {
        self.check_source(source)?;
        self.check_control(control)?;
        if control
            .pending()
            .and_then(|pending| pending.submission())
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let mut progress = Zeroizing::new(Vec::with_capacity(58));
        progress.extend_from_slice(&self.processed.to_be_bytes());
        progress.push(u8::from(self.last_id.is_some()));
        progress.extend_from_slice(&self.last_id.unwrap_or([0; 16]));
        progress.push(u8::from(self.target_root.is_some()));
        progress.extend_from_slice(&self.target_root.unwrap_or([0; 32]));
        let mut bytes = CHECKPOINT_MAGIC.to_vec();
        bytes.extend_from_slice(&self.commitment);
        let sealed = crypto::seal(&self.staging_key, &bytes, &progress)?;
        bytes.extend_from_slice(&sealed);
        self.work.check()?;
        Ok(bytes)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn resume<S: TransitionStore + ?Sized>(
        source: &Engine,
        target_descriptor: &[u8],
        checkpoint: &[u8],
        path: AccessPath<'_>,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        control: &ControlState,
        stage: &mut S,
    ) -> Result<Self> {
        let session = source.protective_source_session()?;
        if checkpoint.len() != CHECKPOINT_BYTES || &checkpoint[..8] != CHECKPOINT_MAGIC {
            return Err(Error::Malformed("protective checkpoint"));
        }
        let target_descriptor =
            Descriptor::parse_epoch_access(target_descriptor, &admission, &source.kdf_policy)?;
        if target_descriptor.vault_id != source.vault_id()
            || source.descriptor.root_epoch().checked_add(1) != Some(target_descriptor.root_epoch())
        {
            return Err(Error::Integrity);
        }
        let pending = control.pending().ok_or(Error::Conflict)?;
        let request = pending.request_id;
        let commitment = Self::binding(
            &source.descriptor,
            &source.head_bytes,
            &target_descriptor,
            request,
        );
        if checkpoint[8..40] != commitment
            || control.vault_id() != source.vault_id()
            || control.accepted()
                != (SnapshotIdentity {
                    descriptor_digest: source.descriptor.hash(),
                    head_digest: crypto::digest(&source.head_bytes),
                    generation: source.head.generation,
                })
            || pending.operation != ControlOperation::ProtectiveTransition
            || pending.target_descriptor_digest != target_descriptor.hash()
            || pending.owner_commitment != commitment
        {
            return Err(Error::Conflict);
        }
        source
            .head
            .generation
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let work = source.authority.work()?;
        let mut guarded = Guarded {
            provider,
            work: &work,
        };
        let root = target_descriptor.access()?.unlock(
            &path,
            &mut guarded,
            &admission,
            &source.kdf_policy,
        )?;
        let target_keys = Engine::derive(&root, &target_descriptor)?;
        if crypto::tags_match(&target_keys.wrapping, &source.raw_keys()?.wrapping) {
            return Err(Error::Integrity);
        }
        let staging_key = crypto::derive(&root, &source.vault_id(), STAGING_DOMAIN)?;
        let progress = crypto::open(&staging_key, &checkpoint[..40], &checkpoint[40..])?;
        if progress.len() != 58 {
            return Err(Error::Integrity);
        }
        let processed = u64::from_be_bytes(progress[..8].try_into().map_err(|_| Error::Integrity)?);
        let last_flag = progress[8];
        let last: RecordId = progress[9..25].try_into().map_err(|_| Error::Integrity)?;
        let root_flag = progress[25];
        let root: crate::NodeHash = progress[26..58].try_into().map_err(|_| Error::Integrity)?;
        let (last_id, target_root) = match (processed, last_flag, root_flag) {
            (0, 0, 0) if last == [0; 16] && root == [0; 32] => (None, None),
            (count, 1, 1) if count > 0 && count <= source.head.count => (Some(last), Some(root)),
            _ => return Err(Error::Integrity),
        };
        let value = Self {
            source_descriptor: source.descriptor.clone(),
            source_head: source.head.clone(),
            source_head_bytes: source.head_bytes.clone(),
            source_session: session,
            work,
            target_descriptor,
            target_keys,
            staging_key,
            target_session: SessionToken {
                vault_id: source.vault_id(),
                nonce: crypto::random()?,
            },
            admission,
            request,
            commitment,
            processed,
            last_id,
            target_root,
            limits: source.limits,
        };
        value.audit_target(stage)?;
        match control.pending().and_then(|pending| pending.submission()) {
            Some(expected) if expected != value.plan()?.target_snapshot() => {
                return Err(Error::Conflict)
            }
            _ => {}
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    const PASSWORD: &[u8] = b"SYNTHETIC-PROTECTIVE-PASSWORD";
    const REQUEST: [u8; 16] = [0x69; 16];
    #[derive(Clone, Default)]
    struct Memory {
        nodes: BTreeMap<crate::NodeHash, Vec<u8>>,
        rows: BTreeMap<RecordId, (u64, Vec<u8>)>,
    }
    impl NodeStore for Memory {
        fn get(&mut self, hash: &crate::NodeHash) -> Result<Option<Vec<u8>>> {
            Ok(self.nodes.get(hash).cloned())
        }
        fn put(&mut self, hash: crate::NodeHash, bytes: &[u8]) -> Result<()> {
            if self.nodes.get(&hash).is_some_and(|old| old != bytes) {
                return Err(Error::Integrity);
            }
            self.nodes.insert(hash, bytes.to_vec());
            Ok(())
        }
    }
    impl TransitionStore for Memory {
        fn staged_record(
            &mut self,
            id: &RecordId,
            maximum: usize,
        ) -> Result<Option<(u64, Vec<u8>)>> {
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
    struct Provider;
    impl KeyProvider for Provider {
        fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
            ProviderCapabilityKind::NonExportableOperation
        }
        fn wrap_seed(&mut self, c: &ProviderContext, s: &[u8; 32]) -> ProviderResult<Vec<u8>> {
            crypto::seal(&[0x41; 32], &c.authenticated_bytes(), s)
                .map_err(|_| crate::ProviderError::Failure)
        }
        fn unwrap_seed(
            &mut self,
            c: &ProviderContext,
            b: &[u8],
        ) -> ProviderResult<Zeroizing<[u8; 32]>> {
            let value = crypto::open(&[0x41; 32], &c.authenticated_bytes(), b)
                .map_err(|_| crate::ProviderError::InvalidResponse)?;
            Ok(Zeroizing::new(
                value
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::ProviderError::InvalidResponse)?,
            ))
        }
    }
    fn aad(descriptor: &Descriptor, id: &RecordId, revision: u64, purpose: &[u8]) -> Vec<u8> {
        let mut bytes = format::frame(purpose);
        bytes.extend_from_slice(&descriptor.context_hash());
        bytes.extend_from_slice(&descriptor.vault_id);
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&revision.to_be_bytes());
        if descriptor.format_id() == 3 && purpose == b"fogvault/prototype/record-wrap/v1" {
            bytes.extend_from_slice(&descriptor.root_epoch().to_be_bytes());
        }
        bytes
    }
    fn identity() -> ProviderIdentity {
        ProviderIdentity {
            provider_id: [1; 16],
            key_id: [2; 16],
            device_bound: true,
            nonexportable: true,
        }
    }
    fn admission() -> AccessAdmission {
        // One synthetic 72-byte provider blob; OR+recovery=484, strict=452.
        AccessAdmission {
            allowed_profiles: vec![
                AccessProfile::Portable,
                AccessProfile::PasswordOrDevice,
                AccessProfile::PasswordAndDevice,
            ],
            providers: vec![identity()],
            max_descriptor_bytes: 484,
            max_device_slots: 1,
            max_provider_blob_bytes: 72,
        }
    }
    fn limits() -> Limits {
        Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 16,
            max_records: 2,
        }
    }
    fn source() -> (Engine, Memory, RecoveryKey) {
        let (mut engine, key) = Engine::diagnostic_create_with_access(
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
            admission(),
            AccessProfile::PasswordOrDevice,
            &[identity()],
            true,
            &mut Provider,
        )
        .unwrap();
        engine.activate_created().unwrap();
        let mut memory = Memory::default();
        for n in 1..=2 {
            let plan = engine
                .prepare_save(&mut memory, [n; 16], None, b"label", &[n; 8], [n; 16], None)
                .unwrap();
            memory.rows.insert([n; 16], (plan.revision, plan.envelope));
            engine.confirm_commit(&plan.head_bytes).unwrap();
        }
        (engine, memory, key.unwrap())
    }
    fn prepare(engine: &Engine) -> (ProtectiveTransition, RecoveryKey, ControlState) {
        let (transition, key) = engine
            .draft_protective_transition(
                ProtectiveSource::Access(AccessPath::Password(PASSWORD)),
                PASSWORD,
                AccessProfile::PasswordAndDevice,
                &[identity()],
                true,
                &mut Provider,
                admission(),
                REQUEST,
            )
            .unwrap();
        let control =
            ControlState::register(engine.vault_id(), [0x52; 16], transition.source_snapshot())
                .prepare(
                    ControlOperation::ProtectiveTransition,
                    REQUEST,
                    transition.target_descriptor_digest(),
                    transition.owner_commitment(),
                )
                .unwrap();
        (transition, key.unwrap(), control)
    }
    fn transform(
        transition: &mut ProtectiveTransition,
        engine: &Engine,
        source: &mut Memory,
        stage: &mut Memory,
        control: &ControlState,
        n: u8,
    ) {
        let proof = engine.lookup(source, &[n; 16]).unwrap();
        let (revision, body) = source.rows.get(&[n; 16]).unwrap();
        let encrypted = transition
            .transform_record(
                engine,
                proof.entry().unwrap(),
                *revision,
                body,
                stage,
                control,
            )
            .unwrap();
        stage.rows.insert([n; 16], (*revision, encrypted));
    }
    fn audit_target(engine: &mut Engine, head: &[u8], memory: &Memory) {
        engine.begin_audit(head).unwrap();
        loop {
            match engine.audit_next().unwrap() {
                AuditRequest::Node(hash) => engine
                    .supply_node(memory.nodes.get(&hash).unwrap())
                    .unwrap(),
                AuditRequest::Record { id, .. } => {
                    let (revision, body) = memory.rows.get(&id).unwrap();
                    engine
                        .supply_record(*revision, body.len() as u64, Some(body))
                        .unwrap();
                }
                AuditRequest::Done => break,
            }
        }
        engine
            .finish_audit(memory.rows.len() as u64, (memory.rows.len() * 2 - 1) as u64)
            .unwrap();
    }

    #[test]
    fn lost_device_replacement_changes_root_and_content_keys_but_preserves_historical_access() {
        for profile in [
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ] {
            let old_device = identity();
            let new_device = ProviderIdentity {
                provider_id: [3; 16],
                key_id: [4; 16],
                ..old_device
            };
            let mut allowed = admission();
            allowed.providers.push(new_device);
            let (mut engine, recovery) = Engine::create_with_access(
                PASSWORD,
                limits(),
                KdfPolicy::baseline(),
                allowed.clone(),
                profile,
                &[old_device],
                true,
                &mut Provider,
            )
            .unwrap();
            engine.activate_created().unwrap();
            let mut source = Memory::default();
            let saved = engine
                .prepare_save(
                    &mut source,
                    [1; 16],
                    None,
                    b"label",
                    b"current data",
                    [0x31; 16],
                    None,
                )
                .unwrap();
            source
                .rows
                .insert([1; 16], (saved.revision, saved.envelope));
            engine.confirm_commit(&saved.head_bytes).unwrap();
            let historical_descriptor = engine.descriptor.clone();
            let historical_body = source.rows[&[1; 16]].1.clone();
            let recovery = recovery.unwrap();
            let old_root = historical_descriptor
                .access()
                .unwrap()
                .recover(&recovery)
                .unwrap();
            let old_wrapping =
                crypto::derive(&old_root, &engine.vault_id(), b"record-key-wrapping").unwrap();
            let old_content_key = crypto::open(
                &old_wrapping,
                &aad(
                    &historical_descriptor,
                    &[1; 16],
                    1,
                    b"fogvault/prototype/record-wrap/v1",
                ),
                &historical_body[40..112],
            )
            .unwrap();
            let lost_slot = engine.access_info().unwrap().device_slots[0].0;
            let historical_head = engine.head_bytes().to_vec();
            engine.begin_recovery(&recovery).unwrap();
            audit_target(&mut engine, &historical_head, &source);
            engine.activate_audit().unwrap();
            let request = [0x32; 16];
            let (mut transition, new_recovery) = engine
                .draft_device_replacement(
                    ProtectiveSource::Recovery(&recovery),
                    &[lost_slot],
                    PASSWORD,
                    profile,
                    &[new_device],
                    true,
                    &mut Provider,
                    allowed.clone(),
                    request,
                )
                .unwrap();
            assert_eq!(
                transition.key_effect(),
                crate::KeyEffect::FreshRootAndContentKeys
            );
            let target_descriptor = transition.target_descriptor.clone();
            assert_eq!(
                target_descriptor.root_epoch(),
                historical_descriptor.root_epoch() + 1
            );
            assert!(target_descriptor
                .access()
                .unwrap()
                .recover(&recovery)
                .is_err());
            assert!(target_descriptor
                .access()
                .unwrap()
                .recover(new_recovery.as_ref().unwrap())
                .is_ok());
            let control =
                ControlState::register(engine.vault_id(), [0x33; 16], transition.source_snapshot())
                    .prepare(
                        ControlOperation::ProtectiveTransition,
                        request,
                        transition.target_descriptor_digest(),
                        transition.owner_commitment(),
                    )
                    .unwrap();
            let proof = engine.protective_lookup(&mut source, &[1; 16]).unwrap();
            let mut target = Memory::default();
            let body = transition
                .transform_record(
                    &engine,
                    proof.entry().unwrap(),
                    1,
                    &historical_body,
                    &mut target,
                    &control,
                )
                .unwrap();
            // Compare actual cryptographic authority, not just old index proofs.
            assert!(format::decrypt_record(
                &target_descriptor,
                &old_wrapping,
                &[1; 16],
                1,
                &body,
                limits()
            )
            .is_err());
            let old_content_key: &[u8; 32] = old_content_key.as_slice().try_into().unwrap();
            assert!(crypto::open(
                old_content_key,
                &aad(
                    &target_descriptor,
                    &[1; 16],
                    1,
                    b"fogvault/prototype/record-body/v1"
                ),
                &body[120..]
            )
            .is_err());
            assert_eq!(
                format::decrypt_record(
                    &historical_descriptor,
                    &old_wrapping,
                    &[1; 16],
                    1,
                    &historical_body,
                    limits()
                )
                .unwrap()
                .payload
                .as_slice(),
                b"current data"
            );
            target.rows.insert([1; 16], (1, body));
            let plan = transition.finish(&engine, &mut target, &control).unwrap();
            assert_eq!(plan.key_effect(), crate::KeyEffect::FreshRootAndContentKeys);
            let submitted = control
                .authorize_submission(plan.target_snapshot())
                .unwrap();
            engine
                .authorize_protective_submission(&transition, &plan, &submitted)
                .unwrap();
            let completed = submitted.confirm_target(plan.target_snapshot()).unwrap();
            let receipt = engine
                .confirm_protective_transition(
                    transition,
                    &completed,
                    &plan.descriptor_bytes,
                    &plan.head_bytes,
                )
                .unwrap();
            assert_eq!(
                receipt.key_effect,
                crate::KeyEffect::FreshRootAndContentKeys
            );
            let proof = engine.lookup(&mut target, &[1; 16]).unwrap();
            assert_eq!(
                engine
                    .read_verified(proof.entry().unwrap(), 1, &target.rows[&[1; 16]].1)
                    .unwrap()
                    .payload
                    .as_slice(),
                b"current data"
            );
        }
    }

    #[test]
    fn named_recovery_replacement_requires_fresh_keys_and_a_new_recovery_secret() {
        let (mut engine, mut source, old_recovery) = source();
        let head = engine.head_bytes().to_vec();
        engine.begin_recovery(&old_recovery).unwrap();
        audit_target(&mut engine, &head, &source);
        engine.activate_audit().unwrap();
        let (mut transition, new_recovery) = engine
            .draft_recovery_replacement(
                &old_recovery,
                PASSWORD,
                AccessProfile::Portable,
                &[],
                true,
                &mut Provider,
                admission(),
                [0x35; 16],
            )
            .unwrap();
        assert_eq!(
            transition.key_effect(),
            crate::KeyEffect::FreshRootAndContentKeys
        );
        assert!(transition
            .target_descriptor
            .access()
            .unwrap()
            .recover(&old_recovery)
            .is_err());
        assert!(transition
            .target_descriptor
            .access()
            .unwrap()
            .recover(new_recovery.as_ref().unwrap())
            .is_ok());
        let control =
            ControlState::register(engine.vault_id(), [0x36; 16], transition.source_snapshot())
                .prepare(
                    ControlOperation::ProtectiveTransition,
                    [0x35; 16],
                    transition.target_descriptor_digest(),
                    transition.owner_commitment(),
                )
                .unwrap();
        let mut target = Memory::default();
        for n in 1..=2 {
            let proof = engine.protective_lookup(&mut source, &[n; 16]).unwrap();
            let (revision, body) = &source.rows[&[n; 16]];
            let encrypted = transition
                .transform_record(
                    &engine,
                    proof.entry().unwrap(),
                    *revision,
                    body,
                    &mut target,
                    &control,
                )
                .unwrap();
            target.rows.insert([n; 16], (*revision, encrypted));
        }
        let plan = transition.finish(&engine, &mut target, &control).unwrap();
        assert_eq!(plan.key_effect(), crate::KeyEffect::FreshRootAndContentKeys);
        assert!(engine.current_session().is_err());
    }

    #[test]
    fn protective_full_transition_rejects_retained_root_content_keys_and_old_routes() {
        let (mut engine, mut source, old_recovery) = source();
        let old_descriptor = engine.descriptor.clone();
        let old_root = old_descriptor
            .access()
            .unwrap()
            .unlock_password(PASSWORD, &KdfPolicy::baseline())
            .unwrap();
        let old_wrapping =
            crypto::derive(&old_root, &engine.vault_id(), b"record-key-wrapping").unwrap();
        let old_body = &source.rows[&[1; 16]].1;
        let old_key = crypto::open(
            &old_wrapping,
            &aad(
                &old_descriptor,
                &[1; 16],
                1,
                b"fogvault/prototype/record-wrap/v1",
            ),
            &old_body[32..104],
        )
        .unwrap();
        let old_slot = engine.access_info().unwrap().device_slots[0].0;
        let (mut transition, new_recovery, control) = prepare(&engine);
        let target_descriptor = transition.target_descriptor.clone();
        assert_eq!(target_descriptor.format_id(), 3);
        assert_eq!(target_descriptor.root_epoch(), 1);
        assert!(target_descriptor
            .access()
            .unwrap()
            .recover(&old_recovery)
            .is_err());
        assert!(target_descriptor
            .access()
            .unwrap()
            .recover(&new_recovery)
            .is_ok());
        assert!(target_descriptor
            .access()
            .unwrap()
            .unlock(
                &AccessPath::Device {
                    slot_id: old_slot,
                    password: Some(PASSWORD)
                },
                &mut Provider,
                &admission(),
                &KdfPolicy::baseline()
            )
            .is_err());
        let slot = target_descriptor.access().unwrap().info().device_slots[0].0;
        let mut stage = Memory::default();
        transform(
            &mut transition,
            &engine,
            &mut source,
            &mut stage,
            &control,
            1,
        );
        assert!(transition.finish(&engine, &mut stage, &control).is_err());
        let checkpoint = transition.checkpoint(&engine, &control).unwrap();
        assert_eq!(checkpoint.len(), CHECKPOINT_BYTES);
        drop(transition);
        assert!(ProtectiveTransition::resume(
            &engine,
            target_descriptor.bytes(),
            &checkpoint,
            AccessPath::Password(PASSWORD),
            &mut Provider,
            admission(),
            &control,
            &mut stage
        )
        .is_err());
        assert!(ProtectiveTransition::resume(
            &engine,
            target_descriptor.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"wrong")
            },
            &mut Provider,
            admission(),
            &control,
            &mut stage
        )
        .is_err());
        let mut transition = ProtectiveTransition::resume(
            &engine,
            target_descriptor.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD),
            },
            &mut Provider,
            admission(),
            &control,
            &mut stage,
        )
        .unwrap();
        transform(
            &mut transition,
            &engine,
            &mut source,
            &mut stage,
            &control,
            2,
        );
        let plan = transition.finish(&engine, &mut stage, &control).unwrap();
        let authorized = control
            .authorize_submission(plan.target_snapshot())
            .unwrap();
        let mut changed_plan = plan.clone();
        changed_plan.prior_head[0] ^= 1;
        assert!(matches!(
            engine.authorize_protective_submission(&transition, &changed_plan, &authorized),
            Err(Error::Conflict)
        ));
        assert_eq!(engine.pending_request(), None);
        engine
            .authorize_protective_submission(&transition, &plan, &authorized)
            .unwrap();
        assert!(matches!(
            engine.lookup(&mut source, &[1; 16]),
            Err(Error::OutcomeUnknown { .. })
        ));
        assert!(matches!(
            engine.begin_reconcile_snapshot(&plan.prior_descriptor, &plan.prior_head, REQUEST),
            Err(Error::OutcomeUnknown { .. })
        ));
        assert!(matches!(
            engine.begin_reconcile_snapshot(&plan.descriptor_bytes, &plan.head_bytes, REQUEST),
            Err(Error::UnsupportedCapability)
        ));
        // The host has now atomically installed the graph and independently
        // persisted exact completion. Synthetic control state is not a physical store.
        let complete = authorized.confirm_target(plan.target_snapshot()).unwrap();
        engine
            .confirm_protective_transition(
                transition,
                &complete,
                &plan.descriptor_bytes,
                &plan.head_bytes,
            )
            .unwrap();
        let encrypted = stage.rows[&[1; 16]].1.clone();
        assert_eq!(&encrypted[..8], b"FGVR0003");
        assert_eq!(&encrypted[32..40], &1u64.to_be_bytes());
        assert!(format::decrypt_record(
            &target_descriptor,
            &old_wrapping,
            &[1; 16],
            1,
            &encrypted,
            limits()
        )
        .is_err());
        let key: &[u8; 32] = old_key.as_slice().try_into().unwrap();
        assert!(crypto::open(
            key,
            &aad(
                &target_descriptor,
                &[1; 16],
                1,
                b"fogvault/prototype/record-body/v1"
            ),
            &encrypted[120..]
        )
        .is_err());
        assert!(Engine::diagnostic_open_with_access(
            &plan.descriptor_bytes,
            limits(),
            KdfPolicy::baseline(),
            admission()
        )
        .is_err());
        let mut reopened = Engine::open_epoch_access(
            &plan.descriptor_bytes,
            limits(),
            KdfPolicy::baseline(),
            admission(),
        )
        .unwrap();
        reopened
            .begin_unlock_access(
                AccessPath::Device {
                    slot_id: slot,
                    password: Some(PASSWORD),
                },
                &mut Provider,
            )
            .unwrap();
        audit_target(&mut reopened, &plan.head_bytes, &stage);
        reopened.activate_audit().unwrap();
        let proof = reopened.lookup(&mut stage, &[1; 16]).unwrap();
        assert_eq!(
            reopened
                .read_verified(proof.entry().unwrap(), 1, &encrypted)
                .unwrap()
                .payload
                .as_slice(),
            &[1; 8]
        );
    }

    #[test]
    fn protective_resume_requires_original_independent_target_commitment_and_intact_stage() {
        let (engine, mut source, _) = source();
        let (mut transition, _, control) = prepare(&engine);
        let mut stage = Memory::default();
        transform(
            &mut transition,
            &engine,
            &mut source,
            &mut stage,
            &control,
            1,
        );
        let checkpoint = transition.checkpoint(&engine, &control).unwrap();
        let target = transition.target_descriptor.clone();
        let slot = target.access().unwrap().info().device_slots[0].0;
        let bare =
            ControlState::register(engine.vault_id(), [0x52; 16], transition.source_snapshot());
        assert!(ProtectiveTransition::resume(
            &engine,
            target.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD)
            },
            &mut Provider,
            admission(),
            &bare,
            &mut stage
        )
        .is_err());
        let forged = format::AccessDescriptor::new(
            engine.vault_id(),
            1,
            2,
            &[0x77; 32],
            PASSWORD,
            KdfProfile::baseline(),
            AccessProfile::PasswordAndDevice,
            &[identity()],
            true,
            &mut Provider,
            &admission(),
            &KdfPolicy::baseline(),
        )
        .unwrap()
        .0
        .epoch_content()
        .unwrap()
        .descriptor();
        let forged_slot = forged.access().unwrap().info().device_slots[0].0;
        assert!(ProtectiveTransition::resume(
            &engine,
            forged.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: forged_slot,
                password: Some(PASSWORD)
            },
            &mut Provider,
            admission(),
            &control,
            &mut stage
        )
        .is_err());
        for offset in [0, 8, 40, CHECKPOINT_BYTES - 1] {
            let mut altered = checkpoint.clone();
            altered[offset] ^= 1;
            assert!(ProtectiveTransition::resume(
                &engine,
                target.bytes(),
                &altered,
                AccessPath::Device {
                    slot_id: slot,
                    password: Some(PASSWORD)
                },
                &mut Provider,
                admission(),
                &control,
                &mut stage
            )
            .is_err());
        }
        stage.rows.remove(&[1; 16]);
        assert!(ProtectiveTransition::resume(
            &engine,
            target.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD)
            },
            &mut Provider,
            admission(),
            &control,
            &mut stage
        )
        .is_err());
        assert_eq!(
            engine.descriptor_bytes(),
            transition.source_descriptor.bytes()
        );
    }

    #[test]
    fn protective_source_conflict_duplicate_and_revocation_never_publish() {
        let (mut engine, mut source, _) = source();
        let (mut transition, _, control) = prepare(&engine);
        let mut stage = Memory::default();
        transform(
            &mut transition,
            &engine,
            &mut source,
            &mut stage,
            &control,
            1,
        );
        let proof = engine.lookup(&mut source, &[1; 16]).unwrap();
        let (revision, body) = source.rows.get(&[1; 16]).unwrap();
        assert!(matches!(
            transition.transform_record(
                &engine,
                proof.entry().unwrap(),
                *revision,
                body,
                &mut stage,
                &control
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(transition.processed_records(), 1);
        let checkpoint = transition.checkpoint(&engine, &control).unwrap();
        let target = transition.target_descriptor.clone();
        let slot = target.access().unwrap().info().device_slots[0].0;
        let (revision, previous) = source.rows.get(&[2; 16]).unwrap().clone();
        let newer = engine
            .prepare_save(
                &mut source,
                [2; 16],
                Some(revision),
                b"",
                b"new",
                [3; 16],
                Some(StoredRecord {
                    revision,
                    envelope: &previous,
                }),
            )
            .unwrap();
        engine.confirm_commit(&newer.head_bytes).unwrap();
        assert!(matches!(
            transition.checkpoint(&engine, &control),
            Err(Error::Conflict)
        ));
        engine.lock();
        assert!(transition.checkpoint(&engine, &control).is_err());
        assert!(ProtectiveTransition::resume(
            &engine,
            target.bytes(),
            &checkpoint,
            AccessPath::Device {
                slot_id: slot,
                password: Some(PASSWORD)
            },
            &mut Provider,
            admission(),
            &control,
            &mut stage
        )
        .is_err());
    }

    #[test]
    fn protective_recovery_reencrypts_without_publishing_source_plaintext_authority() {
        let (mut engine, mut source, key) = source();
        let head = engine.head_bytes().to_vec();
        engine.begin_recovery(&key).unwrap();
        audit_target(&mut engine, &head, &source);
        engine.activate_audit().unwrap();
        assert!(engine.current_session().is_err());
        assert!(engine.lookup(&mut source, &[1; 16]).is_err());
        assert!(matches!(
            engine.draft_recovery_maintenance(
                &key,
                PASSWORD,
                AccessProfile::PasswordAndDevice,
                &[identity()],
                true,
                &mut Provider,
                [0x70; 16]
            ),
            Err(Error::UnsupportedCapability)
        ));
        let (mut transition, new_key) = engine
            .draft_protective_transition(
                ProtectiveSource::Recovery(&key),
                PASSWORD,
                AccessProfile::PasswordAndDevice,
                &[identity()],
                true,
                &mut Provider,
                admission(),
                REQUEST,
            )
            .unwrap();
        let control =
            ControlState::register(engine.vault_id(), [0x52; 16], transition.source_snapshot())
                .prepare(
                    ControlOperation::ProtectiveTransition,
                    REQUEST,
                    transition.target_descriptor_digest(),
                    transition.owner_commitment(),
                )
                .unwrap();
        let mut stage = Memory::default();
        for n in 1..=2 {
            let proof = engine.protective_lookup(&mut source, &[n; 16]).unwrap();
            let (revision, body) = source.rows.get(&[n; 16]).unwrap();
            let encrypted = transition
                .transform_record(
                    &engine,
                    proof.entry().unwrap(),
                    *revision,
                    body,
                    &mut stage,
                    &control,
                )
                .unwrap();
            assert!(engine
                .read_verified(proof.entry().unwrap(), *revision, body)
                .is_err());
            stage.rows.insert([n; 16], (*revision, encrypted));
        }
        let plan = transition.finish(&engine, &mut stage, &control).unwrap();
        let authorized = control
            .authorize_submission(plan.target_snapshot())
            .unwrap();
        engine
            .authorize_protective_submission(&transition, &plan, &authorized)
            .unwrap();
        assert!(engine.current_session().is_err());
        let completed = authorized.confirm_target(plan.target_snapshot()).unwrap();
        engine
            .confirm_protective_transition(
                transition,
                &completed,
                &plan.descriptor_bytes,
                &plan.head_bytes,
            )
            .unwrap();
        assert!(engine.is_unlocked());
        assert!(engine.descriptor.access().unwrap().recover(&key).is_err());
        assert!(engine
            .descriptor
            .access()
            .unwrap()
            .recover(new_key.as_ref().unwrap())
            .is_ok());
    }

    fn epoch_descriptor(
        root: &[u8; 32],
        epoch: u64,
        policy: &KdfPolicy,
    ) -> (Descriptor, RecoveryKey) {
        let (descriptor, key) = format::AccessDescriptor::new(
            [0x31; 16],
            epoch,
            9,
            root,
            PASSWORD,
            KdfProfile::baseline(),
            AccessProfile::Portable,
            &[],
            true,
            &mut Provider,
            &admission(),
            policy,
        )
        .unwrap();
        (
            descriptor.epoch_content().unwrap().descriptor(),
            key.unwrap(),
        )
    }

    #[test]
    fn epoch_wrapping_rotation_binds_epoch_without_reencrypting_body() {
        let policy = KdfPolicy::baseline();
        let (old, _) = epoch_descriptor(&[0x11; 32], 1, &policy);
        let (new, _) = epoch_descriptor(&[0x22; 32], 2, &policy);
        let old_wrapping =
            crypto::derive(&[0x11; 32], &old.vault_id, b"record-key-wrapping").unwrap();
        let new_wrapping =
            crypto::derive(&[0x22; 32], &new.vault_id, b"record-key-wrapping").unwrap();
        let id = [0x42; 16];
        let original = format::encrypt_record(
            &old,
            &old_wrapping,
            &id,
            3,
            b"metadata",
            b"payload",
            limits(),
        )
        .unwrap();
        let rewrapped = format::rotate_record(
            &old,
            &old_wrapping,
            &new,
            &new_wrapping,
            &id,
            3,
            &original,
            limits(),
            false,
        )
        .unwrap();
        assert_eq!(&original[112..], &rewrapped[112..]);
        assert_eq!(&rewrapped[32..40], &2u64.to_be_bytes());
        assert_eq!(
            format::decrypt_record(&new, &new_wrapping, &id, 3, &rewrapped, limits())
                .unwrap()
                .payload
                .as_slice(),
            b"payload"
        );
        let mut altered = original.clone();
        altered[32..40].copy_from_slice(&2u64.to_be_bytes());
        // Even with the old wrapping key supplied, changing only the epoch does
        // not authenticate: the epoch itself is in wrap AAD.
        assert!(format::decrypt_record(&new, &old_wrapping, &id, 3, &altered, limits()).is_err());
        let cek = crypto::open(
            &old_wrapping,
            &aad(&old, &id, 3, b"fogvault/prototype/record-wrap/v1"),
            &original[40..112],
        )
        .unwrap();
        let cek: &[u8; 32] = cek.as_slice().try_into().unwrap();
        assert!(crypto::open(
            cek,
            &aad(&new, &id, 3, b"fogvault/prototype/record-body/v1"),
            &rewrapped[120..]
        )
        .is_ok());
        let full = format::rotate_record(
            &old,
            &old_wrapping,
            &new,
            &new_wrapping,
            &id,
            3,
            &original,
            limits(),
            true,
        )
        .unwrap();
        assert!(crypto::open(
            cek,
            &aad(&new, &id, 3, b"fogvault/prototype/record-body/v1"),
            &full[120..]
        )
        .is_err());
    }

    #[test]
    fn epoch_header_changes_preserve_content_context_for_password_kdf_setup_and_repair() {
        let stronger = KdfProfile::argon2id(
            KdfProfile::baseline().memory_kib(),
            KdfProfile::baseline().passes() + 1,
        )
        .unwrap();
        let policy = KdfPolicy::new(vec![KdfProfile::baseline(), stronger]).unwrap();
        let (descriptor, _) = epoch_descriptor(&[0x11; 32], 1, &policy);
        let wrapping =
            crypto::derive(&[0x11; 32], &descriptor.vault_id, b"record-key-wrapping").unwrap();
        let head_key =
            crypto::derive(&[0x11; 32], &descriptor.vault_id, b"head-authentication").unwrap();
        let id = [0x42; 16];
        let body = format::encrypt_record(
            &descriptor,
            &wrapping,
            &id,
            3,
            b"metadata",
            b"payload",
            limits(),
        )
        .unwrap();
        let mut stage = Memory::default();
        let root = index::upsert(
            &mut stage,
            None,
            id,
            Entry {
                revision: 3,
                digest: crypto::digest(&body),
            },
        )
        .unwrap()
        .root;
        stage.rows.insert(id, (3, body.clone()));
        let head = IndexHead {
            generation: 1,
            request_id: [1; 16],
            operation_digest: [2; 32],
            count: 1,
            root: Some(root),
        }
        .encode(&descriptor, &head_key);
        let mut engine =
            Engine::open_epoch_access(descriptor.bytes(), limits(), policy, admission()).unwrap();
        engine
            .begin_unlock_access(AccessPath::Password(PASSWORD), &mut Provider)
            .unwrap();
        audit_target(&mut engine, &head, &stage);
        engine.activate_audit().unwrap();
        let changed = b"synthetic changed password";
        let draft = engine
            .draft_password_change(PASSWORD, changed, [3; 16])
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert_eq!(engine.content_format(), 3);
        let draft = engine
            .draft_kdf_upgrade(changed, stronger, [4; 16])
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert_eq!(engine.content_format(), 3);
        let (draft, key) = engine
            .draft_access_setup_maintenance(
                changed,
                Some(AccessPath::Password(changed)),
                changed,
                AccessProfile::Portable,
                &[],
                true,
                &mut Provider,
                admission(),
                [5; 16],
            )
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert_eq!(engine.content_format(), 3);
        let current_head = engine.head_bytes().to_vec();
        engine.begin_recovery(key.as_ref().unwrap()).unwrap();
        audit_target(&mut engine, &current_head, &stage);
        engine.activate_audit().unwrap();
        let (draft, _) = engine
            .draft_recovery_maintenance(
                key.as_ref().unwrap(),
                PASSWORD,
                AccessProfile::Portable,
                &[],
                true,
                &mut Provider,
                [6; 16],
            )
            .unwrap();
        let plan = engine.stage_credential_change(&draft).unwrap();
        engine
            .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
            .unwrap();
        assert_eq!(engine.content_format(), 3);
        let proof = engine.lookup(&mut stage, &id).unwrap();
        assert_eq!(
            engine
                .read_verified(proof.entry().unwrap(), 3, &body)
                .unwrap()
                .payload
                .as_slice(),
            b"payload"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[test]
    fn fixed_epoch_vectors_pin_bytes_and_reject_epoch_magic_truncation_and_context_changes() {
        for (bytes,expected) in [
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/content-key.bin")).as_slice(), "4d4713ba96f4dd179f46ffacd66daa3c5fa83631073018f08746c85b1d47955c"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/descriptor.bin")).as_slice(), "5ad0820847f1ade4bbd379698841e0e7c8294594cea8ad62e1ac9ff55efaae5a"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/head.bin")).as_slice(), "040abd17d0a8b2e8bc233e7bd60910d49d393cab165d3de7f4b74f9e9f95b52c"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/node-37e851f52a18f40dbabf045525f4122bdcddb0dbd685d89f541c6c17b2e8ef8c.bin")).as_slice(), "0ec12ba7c04146b2173ec21fb8d7a34b82334495c50aa2696ccb68afe85327a7"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/record.bin")).as_slice(), "0c160cf70ecf9df1f72d808782322a611eef15387687d2fbf7776610e1155291"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/recovery-kit.bin")).as_slice(), "69477007d9bbfded2db92c6b20b370c26e66cfed455640f3f26a63358eb6e09b"),
            (include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/epoch-vectors/root-key.bin")).as_slice(), "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc"),
        ] { assert_eq!(hex(&crypto::digest(bytes)),expected); }
        let descriptor_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/epoch-vectors/descriptor.bin"
        ));
        let head = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/epoch-vectors/head.bin"
        ));
        let record = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/epoch-vectors/record.bin"
        ));
        let node=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../conformance/epoch-vectors/node-37e851f52a18f40dbabf045525f4122bdcddb0dbd685d89f541c6c17b2e8ef8c.bin"));
        let kit = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/epoch-vectors/recovery-kit.bin"
        ));
        let descriptor =
            Descriptor::parse_epoch_access(descriptor_bytes, &admission(), &KdfPolicy::baseline())
                .unwrap();
        let root = descriptor
            .access()
            .unwrap()
            .unlock_password(PASSWORD, &KdfPolicy::baseline())
            .unwrap();
        assert_eq!(root.as_slice(), &[0x11; 32]);
        assert_eq!(
            descriptor
                .access()
                .unwrap()
                .recover(&RecoveryKey::import(kit).unwrap())
                .unwrap()
                .as_slice(),
            root.as_slice()
        );
        let wrapping = crypto::derive(&root, &descriptor.vault_id, b"record-key-wrapping").unwrap();
        let head_key = crypto::derive(&root, &descriptor.vault_id, b"head-authentication").unwrap();
        let parsed = IndexHead::parse(head, &descriptor, &head_key, limits()).unwrap();
        assert_eq!(parsed.generation, 11);
        let mut nodes = Memory::default();
        nodes.nodes.insert(parsed.root.unwrap(), node.to_vec());
        let entry = index::lookup(&mut nodes, parsed.root, &[0x42; 16])
            .unwrap()
            .entry
            .unwrap();
        assert_eq!(entry.revision, 3);
        assert_eq!(entry.digest, crypto::digest(record));
        let decoded =
            format::decrypt_record(&descriptor, &wrapping, &[0x42; 16], 3, record, limits())
                .unwrap();
        assert_eq!(decoded.metadata.as_slice(), b"fixed metadata");
        assert_eq!(decoded.payload.as_slice(), b"epoch profile fixture");
        assert_eq!(&record[32..40], &7u64.to_be_bytes());
        assert!(Engine::diagnostic_open_with_access(
            descriptor_bytes,
            limits(),
            KdfPolicy::baseline(),
            admission()
        )
        .is_err());
        for n in 0..record.len() {
            assert!(
                format::decrypt_record(
                    &descriptor,
                    &wrapping,
                    &[0x42; 16],
                    3,
                    &record[..n],
                    limits()
                )
                .is_err(),
                "truncation {n}"
            );
        }
        for n in 0..descriptor_bytes.len() {
            assert!(
                Descriptor::parse_epoch_access(
                    &descriptor_bytes[..n],
                    &admission(),
                    &KdfPolicy::baseline()
                )
                .is_err(),
                "descriptor truncation {n}"
            );
        }
        let mut descriptor_extended = descriptor_bytes.to_vec();
        descriptor_extended.push(0);
        assert!(Descriptor::parse_epoch_access(
            &descriptor_extended,
            &admission(),
            &KdfPolicy::baseline()
        )
        .is_err());
        let mut extended = record.to_vec();
        extended.push(0);
        assert!(format::decrypt_record(
            &descriptor,
            &wrapping,
            &[0x42; 16],
            3,
            &extended,
            limits()
        )
        .is_err());
        for epoch in [0, 6, 8, u64::MAX] {
            let mut altered = record.to_vec();
            altered[32..40].copy_from_slice(&epoch.to_be_bytes());
            assert!(format::decrypt_record(
                &descriptor,
                &wrapping,
                &[0x42; 16],
                3,
                &altered,
                limits()
            )
            .is_err());
        }
        for offset in [0, 8, 24, 40, 64, 111, 112, 119, 120, record.len() - 1] {
            let mut altered = record.to_vec();
            altered[offset] ^= 1;
            assert!(
                format::decrypt_record(&descriptor, &wrapping, &[0x42; 16], 3, &altered, limits())
                    .is_err(),
                "offset {offset}"
            );
        }
        let mut old_magic = record.to_vec();
        old_magic[..8].copy_from_slice(b"FGVR0002");
        assert!(format::decrypt_record(
            &descriptor,
            &wrapping,
            &[0x42; 16],
            3,
            &old_magic,
            limits()
        )
        .is_err());
        assert!(
            format::decrypt_record(&descriptor, &wrapping, &[0x43; 16], 3, record, limits())
                .is_err()
        );
        assert!(
            format::decrypt_record(&descriptor, &wrapping, &[0x42; 16], 4, record, limits())
                .is_err()
        );
        let mut unknown = descriptor_bytes.to_vec();
        unknown[12..14].copy_from_slice(&4u16.to_be_bytes());
        assert!(
            Descriptor::parse_epoch_access(&unknown, &admission(), &KdfPolicy::baseline()).is_err()
        );
        let mut changed_epoch = descriptor_bytes.to_vec();
        changed_epoch[30..38].copy_from_slice(&8u64.to_be_bytes());
        let altered =
            Descriptor::parse_epoch_access(&changed_epoch, &admission(), &KdfPolicy::baseline())
                .unwrap();
        assert!(IndexHead::parse(head, &altered, &head_key, limits()).is_err());
        assert!(altered
            .access()
            .unwrap()
            .unlock_password(PASSWORD, &KdfPolicy::baseline())
            .is_err());
    }
    #[test]
    fn protective_staging_orphans_are_not_authority_to_publish_extra_objects() {
        let (engine, mut source, _) = source();
        let (mut transition, _, control) = prepare(&engine);
        let mut stage = Memory::default();
        for n in 1..=2 {
            transform(
                &mut transition,
                &engine,
                &mut source,
                &mut stage,
                &control,
                n,
            );
        }
        stage.rows.insert([0x99; 16], (1, vec![0; 176]));
        stage.nodes.insert([0x99; 32], vec![0; 82]);
        let plan = transition.finish(&engine, &mut stage, &control).unwrap();
        assert_eq!(plan.record_count, 2);
        let target = transition.target_descriptor.clone();
        let slot = target.access().unwrap().info().device_slots[0].0;
        let mut opened = Engine::open_epoch_access(
            &plan.descriptor_bytes,
            limits(),
            KdfPolicy::baseline(),
            admission(),
        )
        .unwrap();
        opened
            .begin_unlock_access(
                AccessPath::Device {
                    slot_id: slot,
                    password: Some(PASSWORD),
                },
                &mut Provider,
            )
            .unwrap();
        opened.begin_audit(&plan.head_bytes).unwrap();
        loop {
            match opened.audit_next().unwrap() {
                AuditRequest::Node(hash) => {
                    opened.supply_node(stage.nodes.get(&hash).unwrap()).unwrap()
                }
                AuditRequest::Record { id, .. } => {
                    let (revision, bytes) = stage.rows.get(&id).unwrap();
                    opened
                        .supply_record(*revision, bytes.len() as u64, Some(bytes))
                        .unwrap();
                }
                AuditRequest::Done => break,
            }
        }
        // Blindly copying all physical staging objects yields wrong inventory;
        // the adapter must publish only the authenticated reachable graph.
        assert!(matches!(
            opened.finish_audit(stage.rows.len() as u64, stage.nodes.len() as u64),
            Err(Error::Integrity)
        ));
        assert!(opened.current_session().is_err());
    }
    #[test]
    fn protective_confirmation_rejects_another_draft_with_same_source_and_request() {
        let (mut engine, mut source, _) = source();
        let original_descriptor = engine.descriptor_bytes().to_vec();
        let original_head = engine.head_bytes().to_vec();
        // Two owner-created drafts deliberately use the same source/request.
        // Correct trusted CAS would select one; a mixed callback must still not
        // combine one draft's pending head with the other draft's keys.
        let (mut first, _, first_control) = prepare(&engine);
        let (mut second, _, second_control) = prepare(&engine);
        assert_ne!(
            first.target_descriptor_digest(),
            second.target_descriptor_digest()
        );
        let mut first_stage = Memory::default();
        let mut second_stage = Memory::default();
        for n in 1..=2 {
            transform(
                &mut first,
                &engine,
                &mut source,
                &mut first_stage,
                &first_control,
                n,
            );
            transform(
                &mut second,
                &engine,
                &mut source,
                &mut second_stage,
                &second_control,
                n,
            );
        }
        let first_plan = first
            .finish(&engine, &mut first_stage, &first_control)
            .unwrap();
        let second_plan = second
            .finish(&engine, &mut second_stage, &second_control)
            .unwrap();
        let authorized_first = first_control
            .authorize_submission(first_plan.target_snapshot())
            .unwrap();
        engine
            .authorize_protective_submission(&first, &first_plan, &authorized_first)
            .unwrap();
        let completed_second = second_control
            .authorize_submission(second_plan.target_snapshot())
            .unwrap()
            .confirm_target(second_plan.target_snapshot())
            .unwrap();
        assert!(matches!(
            engine.confirm_protective_transition(
                second,
                &completed_second,
                &second_plan.descriptor_bytes,
                &second_plan.head_bytes
            ),
            Err(Error::Conflict)
        ));
        assert_eq!(engine.descriptor_bytes(), original_descriptor);
        assert_eq!(engine.head_bytes(), original_head);
        assert!(engine.is_uncertain());
        assert_eq!(engine.pending_request(), Some(REQUEST));
        let pending = engine.pending.as_ref().unwrap();
        assert_eq!(pending.bytes, first_plan.head_bytes);
        assert_eq!(
            pending.descriptor.as_ref().unwrap().bytes(),
            first_plan.descriptor_bytes
        );
        assert!(matches!(
            engine.lookup(&mut source, &[1; 16]),
            Err(Error::OutcomeUnknown { .. })
        ));
        let completed_first = authorized_first
            .confirm_target(first_plan.target_snapshot())
            .unwrap();
        let accepted = engine
            .confirm_protective_transition(
                first,
                &completed_first,
                &first_plan.descriptor_bytes,
                &first_plan.head_bytes,
            )
            .unwrap();
        assert_eq!(accepted.receipt, first_plan.receipt);
        assert_eq!(engine.current_receipt().unwrap(), first_plan.receipt);
        assert_eq!(engine.descriptor_bytes(), first_plan.descriptor_bytes);
        assert_eq!(
            IndexHead::parse(
                engine.head_bytes(),
                &engine.descriptor,
                &engine.raw_keys().unwrap().head,
                engine.limits
            )
            .unwrap(),
            engine.head
        );
        let proof = engine.lookup(&mut first_stage, &[1; 16]).unwrap();
        let (revision, body) = &first_stage.rows[&[1; 16]];
        assert_eq!(
            engine
                .read_verified(proof.entry().unwrap(), *revision, body)
                .unwrap()
                .payload
                .as_slice(),
            &[1; 8]
        );
    }
}
