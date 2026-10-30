//! Cooperative provider operations for hosts whose secure-key APIs are async.
//! Each job is bound to one exact operation, provider context and phase. Only
//! the seed already allowed by KeyProvider::wrap_seed crosses this boundary;
//! root keys and password-derived keys remain in Rust zeroizing owners.
use super::*;
use crate::{
    AccessAdmission, AccessProfile, ProviderCapabilityKind, ProviderContext, ProviderError,
    ProviderIdentity, RecoveryKey,
};

pub enum ProviderRequest {
    WrapSeed {
        id: [u8; 16],
        context: ProviderContext,
        seed: Zeroizing<[u8; 32]>,
    },
    UnwrapSeed {
        id: [u8; 16],
        context: ProviderContext,
        wrapped: Vec<u8>,
    },
}
impl ProviderRequest {
    pub fn id(&self) -> [u8; 16] {
        match self {
            Self::WrapSeed { id, .. } | Self::UnwrapSeed { id, .. } => *id,
        }
    }
    pub fn context(&self) -> ProviderContext {
        match self {
            Self::WrapSeed { context, .. } | Self::UnwrapSeed { context, .. } => *context,
        }
    }
}
impl fmt::Debug for ProviderRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrapSeed { id, context, .. } => f
                .debug_struct("WrapSeed")
                .field("id", id)
                .field("context", context)
                .field("seed", &"[redacted]")
                .finish(),
            Self::UnwrapSeed { id, context, .. } => f
                .debug_struct("UnwrapSeed")
                .field("id", id)
                .field("context", context)
                .field("wrapped", &"[opaque]")
                .finish(),
        }
    }
}
pub enum ProviderReply {
    Wrapped(Vec<u8>),
    Unwrapped(Zeroizing<[u8; 32]>),
    Failed(ProviderError),
}

enum DevicePhase {
    Wrap,
    RoundTrip,
}
struct DeviceWork {
    pending: format::PendingDevice,
    id: [u8; 16],
    phase: DevicePhase,
}
/// Shared descriptor builder; future enrollment/protective continuations reuse
/// this exact slot allocation and authenticated wrapping implementation.
pub(super) struct AsyncAccessBuilder {
    pub(super) access: format::AccessDescriptor,
    pub(super) root: Zeroizing<[u8; 32]>,
    password_key: Zeroizing<[u8; 32]>,
    devices: Vec<ProviderIdentity>,
    next: usize,
    pending: Option<DeviceWork>,
    recovery: bool,
    admission: AccessAdmission,
    policy: KdfPolicy,
    work: WorkGuard,
}
impl AsyncAccessBuilder {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        vault: [u8; 16],
        root_epoch: u64,
        policy_epoch: u64,
        root: Zeroizing<[u8; 32]>,
        password: &[u8],
        kdf: KdfProfile,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        policy: KdfPolicy,
        work: WorkGuard,
    ) -> Result<Self> {
        work.check()?;
        let (access, password_key) = format::AccessDescriptor::prepare_new(
            format::EPOCH_FORMAT_ID,
            vault,
            root_epoch,
            policy_epoch,
            &root,
            password,
            kdf,
            profile,
            devices,
            recovery,
            &admission,
            &policy,
        )?;
        let mut value = Self {
            access,
            root,
            password_key,
            devices: devices.to_vec(),
            next: 0,
            pending: None,
            recovery,
            admission,
            policy,
            work,
        };
        value.advance()?;
        Ok(value)
    }
    pub(super) fn enrollment(
        access: format::AccessDescriptor,
        root: Zeroizing<[u8; 32]>,
        password_key: Zeroizing<[u8; 32]>,
        identity: ProviderIdentity,
        admission: AccessAdmission,
        policy: KdfPolicy,
        work: WorkGuard,
    ) -> Result<Self> {
        let mut value = Self {
            access,
            root,
            password_key,
            devices: vec![identity],
            next: 0,
            pending: None,
            recovery: false,
            admission,
            policy,
            work,
        };
        value.advance()?;
        Ok(value)
    }
    fn advance(&mut self) -> Result<()> {
        self.work.check()?;
        if self.next < self.devices.len() {
            self.pending = Some(DeviceWork {
                pending: self
                    .access
                    .prepare_device(self.devices[self.next], &self.admission)?,
                id: crypto::random()?,
                phase: DevicePhase::Wrap,
            });
        }
        Ok(())
    }
    pub(super) fn request(&self) -> Result<Option<ProviderRequest>> {
        self.work.check()?;
        let Some(job) = self.pending.as_ref() else {
            return Ok(None);
        };
        let context = self.access.pending_context(&job.pending);
        Ok(Some(match job.phase {
            DevicePhase::Wrap => ProviderRequest::WrapSeed {
                id: job.id,
                context,
                seed: Zeroizing::new(*job.pending.seed()),
            },
            DevicePhase::RoundTrip => ProviderRequest::UnwrapSeed {
                id: job.id,
                context,
                wrapped: job.pending.protected_seed().to_vec(),
            },
        }))
    }
    pub(super) fn complete(
        &mut self,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        self.work.check()?;
        let job = self.pending.as_mut().ok_or(Error::Conflict)?;
        if job.id != id || self.access.pending_context(&job.pending) != *context {
            return Err(Error::Conflict);
        }
        match (&job.phase, reply) {
            (_, ProviderReply::Failed(error)) => Err(Error::Provider(error)),
            (DevicePhase::Wrap, ProviderReply::Wrapped(bytes)) => {
                self.access
                    .admit_wrapped_seed(&mut job.pending, bytes, &self.admission)?;
                job.id = crypto::random()?;
                job.phase = DevicePhase::RoundTrip;
                self.work.check()
            }
            (DevicePhase::RoundTrip, ProviderReply::Unwrapped(seed)) => {
                let job = self.pending.take().ok_or(Error::Conflict)?;
                self.access
                    .finish_device(job.pending, &self.root, &self.password_key, &seed)?;
                self.next = self.next.checked_add(1).ok_or(Error::ResourceLimit)?;
                self.advance()
            }
            _ => Err(Error::Conflict),
        }
    }
    pub(super) fn finish(
        mut self,
    ) -> Result<(
        format::AccessDescriptor,
        Zeroizing<[u8; 32]>,
        Option<RecoveryKey>,
    )> {
        self.work.check()?;
        if self.pending.is_some() || self.next != self.devices.len() {
            return Err(Error::Conflict);
        }
        let recovery =
            self.access
                .finish_new(&self.root, self.recovery, &self.admission, &self.policy)?;
        self.work.check()?;
        Ok((self.access, self.root, recovery))
    }
}

/// Secret-owning cooperative current-format creator. No Engine, session or
/// saved descriptor is released while provider jobs are incomplete.
pub struct AsyncCreation {
    builder: Option<AsyncAccessBuilder>,
    authority: PublicationAuthority,
    revoker: ScopedRevocationHandle,
    limits: Limits,
    policy: KdfPolicy,
    admission: AccessAdmission,
}
impl AsyncCreation {
    pub fn revocation_handle(&self) -> ScopedRevocationHandle {
        self.revoker.clone()
    }
    pub fn request(&self) -> Result<Option<ProviderRequest>> {
        self.builder.as_ref().ok_or(Error::Locked)?.request()
    }
    pub fn complete(
        &mut self,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        let result = self
            .builder
            .as_mut()
            .ok_or(Error::Locked)?
            .complete(id, context, reply);
        // Identity/order errors leave the original in-flight job intact; a bad
        // provider result terminates the operation and clears its private keys.
        if matches!(&result,Err(error) if !matches!(error,Error::Conflict)) {
            self.cancel();
        }
        result
    }
    pub fn cancel(&mut self) {
        self.revoker.revoke();
        self.builder = None;
        self.authority.clear_keys();
    }
    pub fn finish(mut self) -> Result<(Engine, Option<RecoveryKey>)> {
        let builder = self.builder.take().ok_or(Error::Locked)?;
        let work = self.authority.work()?;
        let (access, root, key) = builder.finish()?;
        let engine = Engine::finish_created_access(
            access,
            &root,
            self.limits,
            self.policy,
            self.admission,
            self.authority,
            &work,
        )?;
        Ok((engine, key))
    }
}

/// Opaque one-device unlock continuation. Completing it only admits private
/// candidate keys; the host must still audit a consistent storage snapshot.
pub struct AsyncUnlock {
    access: format::AccessDescriptor,
    descriptor_digest: [u8; 32],
    admission: AccessAdmission,
    pending: Option<format::PendingUnlock>,
    root: Option<Zeroizing<[u8; 32]>>,
    id: [u8; 16],
    work: WorkGuard,
}
impl AsyncUnlock {
    pub fn revocation_handle(&self) -> ScopedRevocationHandle {
        self.work.revocation_handle()
    }
    pub fn request(&self) -> Result<Option<ProviderRequest>> {
        self.work.check()?;
        Ok(self
            .pending
            .as_ref()
            .map(|pending| ProviderRequest::UnwrapSeed {
                id: self.id,
                context: pending.context(&self.access),
                wrapped: pending.protected_seed().to_vec(),
            }))
    }
    pub fn complete(
        &mut self,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        self.work.check()?;
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if id != self.id || pending.context(&self.access) != *context {
            return Err(Error::Conflict);
        }
        match reply {
            ProviderReply::Unwrapped(seed) => {
                let pending = self.pending.take().ok_or(Error::Conflict)?;
                self.root = Some(self.access.finish_unlock_device(pending, &seed)?);
                self.work.check()
            }
            ProviderReply::Failed(error) => {
                self.pending = None;
                Err(Error::Provider(error))
            }
            _ => Err(Error::Conflict),
        }
    }
    pub fn cancel(&mut self) {
        self.work.revocation_handle().revoke();
        self.pending = None;
        self.root = None;
    }
}

fn admit_capabilities(
    devices: &[ProviderIdentity],
    capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
) -> Result<()> {
    for (i, identity) in devices.iter().enumerate() {
        if devices[..i].contains(identity) {
            return Err(Error::Conflict);
        }
        let mut kinds = capabilities
            .iter()
            .filter(|(candidate, _)| candidate == identity);
        if kinds.next().map(|(_, kind)| *kind)
            != Some(ProviderCapabilityKind::NonExportableOperation)
            || kinds.next().is_some()
        {
            return Err(Error::UnsupportedCapability);
        }
    }
    Ok(())
}
impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn begin_create_access_async(
        password: &[u8],
        limits: Limits,
        policy: KdfPolicy,
        admission: AccessAdmission,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
    ) -> Result<AsyncCreation> {
        crate::validate_policy(limits)?;
        format::current_envelope_limit(limits)?;
        format::AccessDescriptor::admit_new(
            KdfProfile::baseline(),
            profile,
            devices,
            recovery,
            &admission,
            &policy,
        )?;
        if capabilities.len() != devices.len() {
            return Err(Error::UnsupportedCapability);
        }
        admit_capabilities(devices, capabilities)?;
        let authority = PublicationAuthority::new(false);
        let work = authority.begin_attempt()?;
        let builder = AsyncAccessBuilder::new(
            crypto::random()?,
            0,
            1,
            Zeroizing::new(crypto::random()?),
            password,
            KdfProfile::baseline(),
            profile,
            devices,
            recovery,
            admission.clone(),
            policy.clone(),
            work,
        )?;
        let revoker = builder.work.revocation_handle();
        Ok(AsyncCreation {
            builder: Some(builder),
            authority,
            revoker,
            limits,
            policy,
            admission,
        })
    }
    pub fn begin_unlock_device_async(
        &mut self,
        slot: [u8; 16],
        password: Option<&[u8]>,
        capability: ProviderCapabilityKind,
    ) -> Result<AsyncUnlock> {
        if self.initializing {
            return Err(Error::Conflict);
        }
        self.lock();
        let work = self.authority.begin_attempt()?;
        let admission = self
            .access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let access = self.descriptor.access()?.clone();
        let pending = access.prepare_unlock_device(
            slot,
            password,
            capability,
            admission,
            &self.kdf_policy,
        )?;
        work.check()?;
        Ok(AsyncUnlock {
            access,
            descriptor_digest: self.descriptor.hash(),
            admission: admission.clone(),
            pending: Some(pending),
            root: None,
            id: crypto::random()?,
            work,
        })
    }
    pub fn finish_unlock_device_async(&mut self, mut operation: AsyncUnlock) -> Result<()> {
        operation.work.check()?;
        if self.descriptor.hash() != operation.descriptor_digest
            || self.access_admission.as_ref() != Some(&operation.admission)
            || operation.pending.is_some()
        {
            return Err(Error::Conflict);
        }
        let root = operation.root.take().ok_or(Error::Conflict)?;
        let keys = Self::derive(&root, &self.descriptor)?;
        self.authority.retain_keys(&operation.work)?;
        self.keys = Some(keys);
        Ok(())
    }
}

/// Cancellation of one pending provider operation, until `finish` transfers
/// ownership to a normal credential draft or protective planner. This does not
/// revoke the source vault's existing read session. Source lock independently invalidates
/// every operation through its captured WorkGuard.
#[derive(Clone)]
pub struct ProviderCancellation(std::sync::Arc<std::sync::atomic::AtomicBool>);
impl ProviderCancellation {
    fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )))
    }
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn check(&self) -> Result<()> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            Err(Error::Locked)
        } else {
            Ok(())
        }
    }
}
struct SourceBinding {
    session: SessionToken,
    descriptor: [u8; 32],
    head: [u8; 32],
    admission: Option<AccessAdmission>,
    recovery: bool,
}
impl SourceBinding {
    fn check(&self, engine: &Engine) -> Result<()> {
        engine.raw_keys()?;
        engine.ensure_known_outcome()?;
        if engine.session != Some(self.session)
            || engine.descriptor.hash() != self.descriptor
            || crypto::digest(&engine.head_bytes) != self.head
            || engine.access_admission != self.admission
            || engine.recovery_candidate != self.recovery
            || engine.audit.is_some()
            || engine.pending.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
struct TargetConfiguration {
    password: Zeroizing<Vec<u8>>,
    profile: AccessProfile,
    devices: Vec<ProviderIdentity>,
    recovery: bool,
    admission: AccessAdmission,
    source_password: Option<Zeroizing<Vec<u8>>>,
}
enum TargetGoal {
    Setup {
        intent: Vec<u8>,
        replay: bool,
        recovery: bool,
    },
    Password {
        intent: Vec<u8>,
        replay: bool,
        target: KdfProfile,
    },
    Enroll {
        intent: Vec<u8>,
        replay: bool,
        identity: ProviderIdentity,
    },
    Protective,
}
impl TargetGoal {
    fn is_replay(&self) -> bool {
        matches!(
            self,
            Self::Setup { replay: true, .. }
                | Self::Password { replay: true, .. }
                | Self::Enroll { replay: true, .. }
        )
    }
    fn password_equivalence(&self) -> bool {
        matches!(
            self,
            Self::Setup { replay: true, .. } | Self::Password { replay: true, .. }
        )
    }
}
fn replay_error(replay: bool, error: Error) -> Error {
    if replay
        && matches!(
            error,
            Error::Crypto(crypto::CryptoError::AuthenticationFailed)
        )
    {
        Error::OperationIdReuse
    } else {
        error
    }
}
// Exactly one secret-owning phase exists per admitted operation. Keep its
// zeroizing owners inline rather than adding another heap allocation for state.
#[allow(clippy::large_enum_variant)]
enum TargetPhase {
    Source {
        access: format::AccessDescriptor,
        pending: format::PendingUnlock,
        id: [u8; 16],
    },
    Build(AsyncAccessBuilder),
    Descriptor(format::AccessDescriptor),
    Replay,
}
struct AsyncTargetOperation {
    source: SourceBinding,
    target: TargetConfiguration,
    goal: TargetGoal,
    request: [u8; 16],
    phase: Option<TargetPhase>,
    cancellation: ProviderCancellation,
    work: WorkGuard,
}
impl AsyncTargetOperation {
    fn check(&self, engine: &Engine) -> Result<()> {
        self.cancellation.check()?;
        self.work.check()?;
        self.source.check(engine)
    }
    fn start_builder(&mut self, engine: &Engine, root: Zeroizing<[u8; 32]>) -> Result<()> {
        self.check(engine)?;
        let authenticated = Engine::derive(&root, &engine.descriptor)?;
        if !crypto::tags_match(&authenticated.wrapping, &engine.raw_keys()?.wrapping) {
            return Err(Error::Integrity);
        }
        if self.goal.is_replay() {
            self.phase = Some(TargetPhase::Replay);
            return Ok(());
        }
        if let TargetGoal::Enroll { identity, .. } = self.goal {
            let password = self
                .target
                .source_password
                .as_ref()
                .map(|value| value.as_slice());
            let (access, key) = engine.descriptor.access()?.prepare_enrollment(
                password,
                identity,
                &self.target.admission,
                &engine.kdf_policy,
            )?;
            let builder = AsyncAccessBuilder::enrollment(
                access,
                root,
                key,
                identity,
                self.target.admission.clone(),
                engine.kdf_policy.clone(),
                engine.authority.work()?,
            )?;
            self.target.password = Zeroizing::new(Vec::new());
            self.target.source_password = None;
            self.phase = Some(TargetPhase::Build(builder));
            return Ok(());
        }
        if let TargetGoal::Password { target, .. } = self.goal {
            let source_password = self.target.source_password.as_ref().map(|p| p.as_slice());
            let descriptor = engine.descriptor.access()?.rewrap_password(
                &root,
                source_password,
                &self.target.password,
                target,
                &engine.kdf_policy,
            )?;
            self.target.password = Zeroizing::new(Vec::new());
            self.target.source_password = None;
            self.phase = Some(TargetPhase::Descriptor(descriptor));
            return Ok(());
        }
        let root_epoch = engine.descriptor.root_epoch();
        let policy_epoch = engine
            .access_info()?
            .policy_epoch
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let (target_root, target_epoch) = if matches!(self.goal, TargetGoal::Protective) {
            let new = Zeroizing::new(crypto::random()?);
            if crypto::tags_match(&root, &new) {
                return Err(Error::Integrity);
            }
            (new, root_epoch.checked_add(1).ok_or(Error::ResourceLimit)?)
        } else {
            (root, root_epoch)
        };
        let builder = AsyncAccessBuilder::new(
            engine.vault_id(),
            target_epoch,
            policy_epoch,
            target_root,
            &self.target.password,
            engine.kdf_profile(),
            self.target.profile,
            &self.target.devices,
            self.target.recovery,
            self.target.admission.clone(),
            engine.kdf_policy.clone(),
            engine.authority.work()?,
        )?;
        // Retain only the derived password key while waiting for target jobs.
        self.target.password = Zeroizing::new(Vec::new());
        self.phase = Some(TargetPhase::Build(builder));
        Ok(())
    }
    fn request(&self, engine: &Engine) -> Result<Option<ProviderRequest>> {
        self.check(engine)?;
        match self.phase.as_ref().ok_or(Error::Locked)? {
            TargetPhase::Source {
                access,
                pending,
                id,
            } => Ok(Some(ProviderRequest::UnwrapSeed {
                id: *id,
                context: pending.context(access),
                wrapped: pending.protected_seed().to_vec(),
            })),
            TargetPhase::Build(builder) => builder.request(),
            TargetPhase::Descriptor(_) | TargetPhase::Replay => Ok(None),
        }
    }
    fn complete(
        &mut self,
        engine: &Engine,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        self.check(engine)?;
        match self.phase.as_mut().ok_or(Error::Locked)? {
            TargetPhase::Source {
                access,
                pending,
                id: expected,
            } => {
                if *expected != id || pending.context(access) != *context {
                    return Err(Error::Conflict);
                }
                match reply {
                    ProviderReply::Unwrapped(seed) => {
                        let Some(TargetPhase::Source {
                            access, pending, ..
                        }) = self.phase.take()
                        else {
                            return Err(Error::Conflict);
                        };
                        let root = access.finish_unlock_device(pending, &seed)?;
                        self.start_builder(engine, root)
                    }
                    ProviderReply::Failed(error) => Err(Error::Provider(error)),
                    _ => Err(Error::Conflict),
                }
            }
            TargetPhase::Build(builder) => builder.complete(id, context, reply),
            TargetPhase::Descriptor(_) | TargetPhase::Replay => Err(Error::Conflict),
        }
    }
    fn cancel(&mut self) {
        self.cancellation.cancel();
        self.phase = None;
        self.target.password = Zeroizing::new(Vec::new());
        self.target.source_password = None;
    }
}

/// Asynchronous first-route setup or explicitly unchanged-key maintenance.
/// Each request/reply is rechecked against the live Engine session and head.
pub struct AsyncAccessSetup(AsyncTargetOperation);
impl AsyncAccessSetup {
    pub fn cancellation_handle(&self) -> ProviderCancellation {
        self.0.cancellation.clone()
    }
    pub fn request(&self, engine: &Engine) -> Result<Option<ProviderRequest>> {
        self.0.request(engine)
    }
    pub fn complete(
        &mut self,
        engine: &Engine,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        let result = self
            .0
            .complete(engine, id, context, reply)
            .map_err(|error| replay_error(self.0.goal.password_equivalence(), error));
        if matches!(&result,Err(error) if !matches!(error,Error::Conflict)) {
            self.0.cancel();
        }
        result
    }
    pub fn cancel(&mut self) {
        self.0.cancel();
    }
    pub fn finish(mut self, engine: &Engine) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.0.check(engine)?;
        let (intent, replay, recovery) = match self.0.goal {
            TargetGoal::Setup {
                intent,
                replay,
                recovery,
            } => (intent, replay, recovery),
            TargetGoal::Password { intent, replay, .. }
            | TargetGoal::Enroll { intent, replay, .. } => (intent, replay, false),
            _ => return Err(Error::Conflict),
        };
        if replay {
            if !matches!(self.0.phase, Some(TargetPhase::Replay)) {
                return Err(Error::Conflict);
            }
            return Ok((
                engine.access_draft(None, &intent, self.0.request, false)?,
                None,
            ));
        }
        let (access, key) = match self.0.phase.take() {
            Some(TargetPhase::Build(builder)) => {
                let (access, _root, key) = builder.finish()?;
                (access, key)
            }
            Some(TargetPhase::Descriptor(access)) => (access, None),
            _ => return Err(Error::Conflict),
        };
        let mut draft =
            engine.access_draft(Some(access.descriptor()), &intent, self.0.request, recovery)?;
        draft.access_admission = Some(self.0.target.admission);
        Ok((draft, key))
    }
}

/// Asynchronous target-factor construction for a full fresh-root/content
/// replacement. It returns the same protective planner used by native hosts.
pub struct AsyncProtectiveAccess(AsyncTargetOperation);
impl AsyncProtectiveAccess {
    pub fn cancellation_handle(&self) -> ProviderCancellation {
        self.0.cancellation.clone()
    }
    pub fn request(&self, engine: &Engine) -> Result<Option<ProviderRequest>> {
        self.0.request(engine)
    }
    pub fn complete(
        &mut self,
        engine: &Engine,
        id: [u8; 16],
        context: &ProviderContext,
        reply: ProviderReply,
    ) -> Result<()> {
        let result = self.0.complete(engine, id, context, reply);
        if matches!(&result,Err(error) if !matches!(error,Error::Conflict)) {
            self.0.cancel();
        }
        result
    }
    pub fn cancel(&mut self) {
        self.0.cancel();
    }
    pub fn finish(
        mut self,
        engine: &Engine,
    ) -> Result<(ProtectiveTransition, Option<RecoveryKey>)> {
        self.0.check(engine)?;
        let Some(TargetPhase::Build(builder)) = self.0.phase.take() else {
            return Err(Error::Conflict);
        };
        let (access, root, key) = builder.finish()?;
        let transition = engine.finish_protective_access(
            access,
            &root,
            self.0.target.admission,
            self.0.request,
            self.0.source.session,
            engine.authority.work()?,
        )?;
        Ok((transition, key))
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn begin_async_target(
        &self,
        source: ProtectiveSource<'_>,
        source_capability: ProviderCapabilityKind,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
        goal: TargetGoal,
    ) -> Result<AsyncTargetOperation> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        if self.pending.is_some() || self.audit.is_some() || self.initializing {
            return Err(Error::Conflict);
        }
        if matches!(goal, TargetGoal::Password { .. }) {
            self.descriptor
                .access()?
                .admit(&admission, &self.kdf_policy)?;
            if !capabilities.is_empty() {
                return Err(Error::UnsupportedCapability);
            }
        } else {
            format::AccessDescriptor::admit_new(
                self.kdf_profile(),
                profile,
                devices,
                recovery,
                &admission,
                &self.kdf_policy,
            )?;
            if capabilities.len() != devices.len() {
                return Err(Error::UnsupportedCapability);
            }
            admit_capabilities(devices, capabilities)?;
        }
        if self.descriptor.format_id() != format::EPOCH_FORMAT_ID {
            return Err(Error::UnsupportedCapability);
        }
        let source_binding = SourceBinding {
            session: self.session.ok_or(Error::Locked)?,
            descriptor: self.descriptor.hash(),
            head: crypto::digest(&self.head_bytes),
            admission: self.access_admission.clone(),
            recovery: self.recovery_candidate,
        };
        let source_password = if matches!(
            goal,
            TargetGoal::Password { .. } | TargetGoal::Enroll { .. }
        ) {
            match &source {
                ProtectiveSource::Password(value)
                | ProtectiveSource::Access(crate::AccessPath::Password(value)) => {
                    Some(Zeroizing::new(value.to_vec()))
                }
                ProtectiveSource::Access(crate::AccessPath::Device { password, .. }) => {
                    password.map(|value| Zeroizing::new(value.to_vec()))
                }
                _ => None,
            }
        } else {
            None
        };
        let mut operation = AsyncTargetOperation {
            source: source_binding,
            target: TargetConfiguration {
                password: Zeroizing::new(password.to_vec()),
                profile,
                devices: devices.to_vec(),
                recovery,
                admission,
                source_password,
            },
            goal,
            request,
            phase: None,
            cancellation: ProviderCancellation::new(),
            work: self.authority.work()?,
        };
        let root = match source {
            ProtectiveSource::Password(value) if !self.recovery_candidate => Some(
                self.descriptor
                    .unlock_with_policy(value, &self.kdf_policy)?,
            ),
            ProtectiveSource::Recovery(key) if self.recovery_candidate => {
                Some(self.descriptor.access()?.recover(key)?)
            }
            ProtectiveSource::Access(crate::AccessPath::Password(value))
                if !self.recovery_candidate =>
            {
                Some(
                    self.descriptor
                        .access()?
                        .unlock_password(value, &self.kdf_policy)?,
                )
            }
            ProtectiveSource::Access(crate::AccessPath::Device { slot_id, password })
                if !self.recovery_candidate =>
            {
                let access = self.descriptor.access()?.clone();
                let pending = access.prepare_unlock_device(
                    slot_id,
                    password,
                    source_capability,
                    self.access_admission
                        .as_ref()
                        .ok_or(Error::UnsupportedCapability)?,
                    &self.kdf_policy,
                )?;
                operation.phase = Some(TargetPhase::Source {
                    access,
                    pending,
                    id: crypto::random()?,
                });
                None
            }
            _ => return Err(Error::UnsupportedCapability),
        };
        if let Some(root) = root {
            operation.start_builder(self, root)?;
        }
        Ok(operation)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_access_setup_async(
        &self,
        source: crate::AccessPath<'_>,
        source_capability: ProviderCapabilityKind,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
    ) -> Result<AsyncAccessSetup> {
        self.operation_keys()?;
        if self.head.request_id != request {
            let info = self.access_info()?;
            if !info.device_slots.is_empty() || info.recovery_enabled {
                return Err(Error::UnsupportedCapability);
            }
        }
        self.begin_access_setup_maintenance_async(
            source,
            source_capability,
            password,
            profile,
            devices,
            recovery,
            admission,
            capabilities,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_access_setup_maintenance_async(
        &self,
        source: crate::AccessPath<'_>,
        source_capability: ProviderCapabilityKind,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
    ) -> Result<AsyncAccessSetup> {
        self.operation_keys()?;
        if profile == AccessProfile::PasswordAndDevice
            && self.access_info()?.profile != AccessProfile::PasswordAndDevice
        {
            return Err(Error::UnsupportedCapability);
        }
        let intent = Self::setup_intent(7, profile, devices, recovery);
        let replay = self.head.request_id == request;
        let source = if replay {
            if self.access_info()?.profile == AccessProfile::PasswordAndDevice {
                let slot_id = self
                    .access_info()?
                    .device_slots
                    .iter()
                    .find(|(_, id)| devices.contains(id))
                    .map(|(slot, _)| *slot)
                    .ok_or(Error::OperationIdReuse)?;
                crate::AccessPath::Device {
                    slot_id,
                    password: Some(password),
                }
            } else {
                crate::AccessPath::Password(password)
            }
        } else {
            source
        };
        self.begin_async_target(
            ProtectiveSource::Access(source),
            source_capability,
            password,
            profile,
            devices,
            recovery,
            admission,
            capabilities,
            request,
            TargetGoal::Setup {
                intent,
                replay,
                recovery: false,
            },
        )
        .map(AsyncAccessSetup)
        .map_err(|error| replay_error(replay, error))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_protective_access_async(
        &self,
        source: ProtectiveSource<'_>,
        source_capability: ProviderCapabilityKind,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
    ) -> Result<AsyncProtectiveAccess> {
        self.protective_source_session()?;
        if self.head.request_id == request {
            return Err(Error::OperationIdReuse);
        }
        self.head
            .generation
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        self.begin_async_target(
            source,
            source_capability,
            password,
            profile,
            devices,
            recovery,
            admission,
            capabilities,
            request,
            TargetGoal::Protective,
        )
        .map(AsyncProtectiveAccess)
    }
}

impl Engine {
    /// Loss/exposure response. Re-enrolling the same lost provider/key identity
    /// is refused before provider work, including a mere change of flags.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_device_replacement_async(
        &self,
        source: ProtectiveSource<'_>,
        source_capability: ProviderCapabilityKind,
        removed_slots: &[[u8; 16]],
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
    ) -> Result<AsyncProtectiveAccess> {
        self.protective_source_session()?;
        let current = self.access_info()?;
        if removed_slots.is_empty() {
            return Err(Error::Malformed("missing replaced device"));
        }
        if removed_slots.len() > current.device_slots.len() {
            return Err(Error::Conflict);
        }
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
                .any(|new| new.provider_id == old.provider_id && new.key_id == old.key_id)
            {
                return Err(Error::UnsupportedCapability);
            }
        }
        self.begin_protective_access_async(
            source,
            source_capability,
            password,
            profile,
            devices,
            recovery,
            admission,
            capabilities,
            request,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn begin_recovery_replacement_async(
        &self,
        key: &RecoveryKey,
        password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        admission: AccessAdmission,
        capabilities: &[(ProviderIdentity, ProviderCapabilityKind)],
        request: [u8; 16],
    ) -> Result<AsyncProtectiveAccess> {
        self.begin_protective_access_async(
            ProtectiveSource::Recovery(key),
            ProviderCapabilityKind::RawSecret,
            password,
            profile,
            devices,
            recovery,
            admission,
            capabilities,
            request,
        )
    }
}

impl Engine {
    /// Rewrap existing password/device outer wrappers after one admitted async
    /// source authentication. Device seeds and owner recovery remain unchanged.
    pub fn begin_access_password_change_async(
        &self,
        auth: crate::AccessPath<'_>,
        source_capability: ProviderCapabilityKind,
        password: &[u8],
        target: KdfProfile,
        request: [u8; 16],
    ) -> Result<AsyncAccessSetup> {
        self.operation_keys()?;
        self.kdf_policy.admit(target)?;
        if target.memory_kib() < self.kdf_profile().memory_kib()
            || target.passes() < self.kdf_profile().passes()
        {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        let info = self.access_info()?;
        let replay = self.head.request_id == request;
        let mut intent = vec![9];
        intent.extend_from_slice(&target.memory_kib().to_be_bytes());
        intent.extend_from_slice(&target.passes().to_be_bytes());
        let source = if replay {
            if info.profile == AccessProfile::PasswordAndDevice {
                match auth {
                    crate::AccessPath::Device { slot_id, .. } => crate::AccessPath::Device {
                        slot_id,
                        password: Some(password),
                    },
                    _ => return Err(Error::UnsupportedCapability),
                }
            } else {
                crate::AccessPath::Password(password)
            }
        } else {
            auth
        };
        let devices: Vec<_> = info
            .device_slots
            .iter()
            .map(|(_, identity)| *identity)
            .collect();
        self.begin_async_target(
            ProtectiveSource::Access(source),
            source_capability,
            password,
            info.profile,
            &devices,
            info.recovery_enabled,
            self.access_admission
                .clone()
                .ok_or(Error::UnsupportedCapability)?,
            &[],
            request,
            TargetGoal::Password {
                intent,
                replay,
                target,
            },
        )
        .map(AsyncAccessSetup)
        .map_err(|error| replay_error(replay, error))
    }
    /// Preserve the current password and every existing recovery/device path.
    /// OR profiles authenticate the password wrapper explicitly rather than
    /// treating a convenience device's successful unwrap as password equality.
    pub fn begin_kdf_upgrade_access_async(
        &self,
        auth: crate::AccessPath<'_>,
        source_capability: ProviderCapabilityKind,
        target: KdfProfile,
        request: [u8; 16],
    ) -> Result<AsyncAccessSetup> {
        self.operation_keys()?;
        self.kdf_policy.admit(target)?;
        if self.head.request_id != request && !target.is_strict_upgrade_from(self.kdf_profile()) {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        let password = match &auth {
            crate::AccessPath::Password(value) => Some(*value),
            crate::AccessPath::Device { password, .. } => *password,
        }
        .ok_or(Error::UnsupportedCapability)?;
        let auth = if self.access_info()?.profile == AccessProfile::PasswordAndDevice {
            auth
        } else {
            crate::AccessPath::Password(password)
        };
        self.begin_access_password_change_async(auth, source_capability, password, target, request)
    }
}

impl Engine {
    /// Add one provider slot while preserving every existing slot and recovery
    /// wrapper. Existing devices need not be available when a password path can
    /// authenticate the source. Only the new slot performs wrap/round-trip jobs.
    pub fn begin_enroll_device_async(
        &self,
        auth: crate::AccessPath<'_>,
        source_capability: ProviderCapabilityKind,
        identity: ProviderIdentity,
        admission: AccessAdmission,
        new_capability: ProviderCapabilityKind,
        request: [u8; 16],
    ) -> Result<AsyncAccessSetup> {
        self.operation_keys()?;
        let info = self.access_info()?;
        if info.profile == AccessProfile::Portable {
            return Err(Error::UnsupportedCapability);
        }
        let mut intent = vec![4];
        intent.extend_from_slice(&identity.provider_id);
        intent.extend_from_slice(&identity.key_id);
        intent.push(u8::from(identity.device_bound));
        intent.push(u8::from(identity.nonexportable));
        let replay = self.head.request_id == request;
        self.begin_async_target(
            ProtectiveSource::Access(auth),
            source_capability,
            &[],
            info.profile,
            &[identity],
            false,
            admission,
            &[(identity, new_capability)],
            request,
            TargetGoal::Enroll {
                intent,
                replay,
                identity,
            },
        )
        .map(AsyncAccessSetup)
    }
}
