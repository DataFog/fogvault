use super::*;
use crate::access::{
    AccessAdmission, AccessChange, AccessInfo, AccessPath, AccessProfile, KeyProvider,
    ProviderContext, ProviderError, ProviderIdentity, ProviderResult, RecoveryKey,
};

struct GuardedProvider<'a> {
    provider: &'a mut dyn KeyProvider,
    work: &'a WorkGuard,
}
impl KeyProvider for GuardedProvider<'_> {
    fn capability_kind(
        &self,
        identity: &ProviderIdentity,
    ) -> crate::access::ProviderCapabilityKind {
        self.provider.capability_kind(identity)
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        self.work.check().map_err(|_| ProviderError::Cancelled)?;
        let result = self.provider.wrap_seed(context, seed);
        self.work.check().map_err(|_| ProviderError::Cancelled)?;
        result
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        self.work.check().map_err(|_| ProviderError::Cancelled)?;
        let result = self.provider.unwrap_seed(context, wrapped);
        self.work.check().map_err(|_| ProviderError::Cancelled)?;
        result
    }
}

impl Engine {
    pub(super) fn setup_intent(
        kind: u8,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
    ) -> Vec<u8> {
        let mut intent = vec![kind, profile.code(), u8::from(recovery)];
        intent.extend_from_slice(&(devices.len() as u64).to_be_bytes());
        for identity in devices {
            intent.extend_from_slice(&identity.provider_id);
            intent.extend_from_slice(&identity.key_id);
            intent.push(u8::from(identity.device_bound));
            intent.push(u8::from(identity.nonexportable));
        }
        intent
    }
    fn verify_new_access(
        &self,
        password: &[u8],
        devices: &[ProviderIdentity],
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
    ) -> Result<()> {
        let value = self.descriptor.access()?;
        let slot = if value.profile == AccessProfile::PasswordAndDevice {
            Some(
                value
                    .info()
                    .device_slots
                    .iter()
                    .find(|(_, identity)| devices.contains(identity))
                    .map(|slot| slot.0)
                    .ok_or(Error::OperationIdReuse)?,
            )
        } else {
            None
        };
        self.verify_replacement_password(password, slot, provider, admission)
    }
    fn verify_replacement_password(
        &self,
        password: &[u8],
        device_slot: Option<[u8; 16]>,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
    ) -> Result<()> {
        let value = self.descriptor.access()?;
        // A convenience device path deliberately ignores passwords. It cannot
        // establish equality of a requested replacement password on retry.
        // Authenticate the current password wrapper at its admitted KDF cost;
        // strict AND additionally needs only the caller-selected device.
        let path = if value.profile == AccessProfile::PasswordAndDevice {
            AccessPath::Device {
                slot_id: device_slot.ok_or(Error::UnsupportedCapability)?,
                password: Some(password),
            }
        } else {
            AccessPath::Password(password)
        };
        match value.unlock(&path, provider, admission, &self.kdf_policy) {
            Ok(root) => {
                drop(root);
                Ok(())
            }
            Err(Error::Crypto(crate::CryptoError::AuthenticationFailed)) => {
                Err(Error::OperationIdReuse)
            }
            Err(error) => Err(error),
        }
    }
    /// Create the single maintained P3/content-three profile at root epoch zero.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_access(
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        Self::create_access(
            password, limits, kdf_policy, admission, profile, devices, recovery, provider, false,
        )
    }
    /// Historical content-two creation for fixed diagnostics, never a current write profile.
    #[allow(clippy::too_many_arguments)]
    pub fn diagnostic_create_with_access(
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        Self::create_access(
            password, limits, kdf_policy, admission, profile, devices, recovery, provider, true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn create_access(
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        legacy: bool,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        crate::validate_policy(limits)?;
        if !legacy {
            format::current_envelope_limit(limits)?;
        }
        admission.profile(profile)?;
        kdf_policy.admit(KdfProfile::baseline())?;
        let vault_id = crypto::random()?;
        let root = Zeroizing::new(crypto::random::<32>()?);
        let authority = PublicationAuthority::new(false);
        let work = authority.begin_attempt()?;
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        let (access, key) = if legacy {
            format::AccessDescriptor::diagnostic_new_legacy(
                vault_id,
                0,
                1,
                &root,
                password,
                KdfProfile::baseline(),
                profile,
                devices,
                recovery,
                &mut guarded,
                &admission,
                &kdf_policy,
            )?
        } else {
            format::AccessDescriptor::new(
                vault_id,
                0,
                1,
                &root,
                password,
                KdfProfile::baseline(),
                profile,
                devices,
                recovery,
                &mut guarded,
                &admission,
                &kdf_policy,
            )?
        };
        let engine = Self::finish_created_access(
            access, &root, limits, kdf_policy, admission, authority, &work,
        )?;
        Ok((engine, key))
    }
    pub(super) fn finish_created_access(
        access: format::AccessDescriptor,
        root: &[u8; 32],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
        authority: PublicationAuthority,
        work: &WorkGuard,
    ) -> Result<Self> {
        work.check()?;
        let descriptor = access.descriptor();
        let keys = Self::derive(root, &descriptor)?;
        let head = Self::empty_head()?;
        let head_bytes = head.encode(&descriptor, &keys.head);
        authority.retain_keys(work)?;
        let engine = Self {
            descriptor,
            head,
            head_bytes,
            limits,
            kdf_policy,
            keys: Some(keys),
            session: None,
            initializing: true,
            pending: None,
            audit: None,
            authority,
            access_admission: Some(admission),
            recovery_candidate: false,
        };
        Ok(engine)
    }
    /// Open only the maintained content-three profile under explicit host admission.
    pub fn open_with_access(
        descriptor: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Self> {
        Self::open_access(descriptor, limits, kdf_policy, admission, false)
    }
    /// Read old content-two P3 fixtures through an explicitly named diagnostic path.
    pub fn diagnostic_open_with_access(
        descriptor: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
    ) -> Result<Self> {
        Self::open_access(descriptor, limits, kdf_policy, admission, true)
    }
    fn open_access(
        descriptor: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
        admission: AccessAdmission,
        legacy: bool,
    ) -> Result<Self> {
        crate::validate_policy(limits)?;
        if !legacy {
            format::current_envelope_limit(limits)?;
        }
        let descriptor = if legacy {
            Descriptor::parse_access(descriptor, &admission, &kdf_policy)?
        } else {
            Descriptor::parse_epoch_access(descriptor, &admission, &kdf_policy)?
        };
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
    pub fn access_info(&self) -> Result<AccessInfo> {
        Ok(self.descriptor.access()?.info())
    }
    /// Explicit local configuration, never selected by saved bytes. This does
    /// not enroll a path or authenticate the vault.
    pub fn configure_access_admission(&mut self, admission: AccessAdmission) -> Result<()> {
        admission.validate()?;
        if self.descriptor.credential_format_id() == 3 {
            self.descriptor
                .access()?
                .admit(&admission, &self.kdf_policy)?;
        }
        self.access_admission = Some(admission);
        Ok(())
    }
    pub fn begin_unlock_access(
        &mut self,
        path: AccessPath<'_>,
        provider: &mut dyn KeyProvider,
    ) -> Result<()> {
        if self.initializing {
            return Err(Error::Conflict);
        }
        self.lock();
        let work = self.authority.begin_attempt()?;
        let admission = self
            .access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        let root =
            self.descriptor
                .access()?
                .unlock(&path, &mut guarded, admission, &self.kdf_policy)?;
        let keys = Self::derive(&root, &self.descriptor)?;
        work.check()?;
        self.authority.retain_keys(&work)?;
        self.keys = Some(keys);
        Ok(())
    }
    /// Recovery prepares only restricted authority. Audit the accepted snapshot;
    /// normal sessions/reads remain unavailable until repair commits.
    pub fn begin_recovery(&mut self, key: &RecoveryKey) -> Result<()> {
        if self.initializing {
            return Err(Error::Conflict);
        }
        self.lock();
        let work = self.authority.begin_attempt()?;
        self.access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let root = self.descriptor.access()?.recover(key)?;
        let keys = Self::derive(&root, &self.descriptor)?;
        work.check()?;
        self.authority.retain_keys(&work)?;
        self.keys = Some(keys);
        self.recovery_candidate = true;
        Ok(())
    }
    fn access_identity(&self, descriptor: &Descriptor, intent: &[u8]) -> Result<[u8; 32]> {
        let mut input = format::frame(b"fogvault/prototype/access-change/v3");
        input.extend_from_slice(intent);
        input.extend_from_slice(&descriptor.hash());
        Ok(crypto::mac(&self.raw_keys()?.operation, &input))
    }
    pub(super) fn access_draft(
        &self,
        descriptor: Option<Descriptor>,
        intent: &[u8],
        request: [u8; 16],
        recovery: bool,
    ) -> Result<CredentialDraft> {
        let target = descriptor.as_ref().unwrap_or(&self.descriptor);
        let operation_digest = self.access_identity(target, intent)?;
        if descriptor.is_none()
            && !crypto::tags_match(&operation_digest, &self.head.operation_digest)
        {
            return Err(Error::OperationIdReuse);
        }
        Ok(CredentialDraft {
            session: self.session.ok_or(Error::Locked)?,
            descriptor_digest: self.descriptor.hash(),
            head_digest: crypto::digest(&self.head_bytes),
            request,
            operation_digest,
            replacement_session: if descriptor.is_some() {
                Some(SessionToken {
                    vault_id: self.vault_id(),
                    nonce: crypto::random()?,
                })
            } else {
                None
            },
            descriptor,
            recovery,
            access_admission: None,
        })
    }
    /// Generic access changes add routes without silently removing old authority.
    /// Removing/replacing routes requires explicitly named maintenance or a full
    /// protective replacement when a factor may have been lost/exposed.
    pub fn draft_access_change(
        &self,
        auth: AccessPath<'_>,
        change: AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.operation_keys()?;
        let removes_route = matches!(
            &change,
            AccessChange::RemoveDevice(_)
                | AccessChange::ReplaceRecovery
                | AccessChange::DisableRecovery
        ) || matches!(&change, AccessChange::SetProfile { profile: AccessProfile::Portable, .. }
                if !self.access_info()?.device_slots.is_empty());
        if removes_route {
            return Err(Error::UnsupportedCapability);
        }
        self.draft_access_maintenance(auth, change, provider, request)
    }
    /// Deliberate header-only maintenance. Retained historical wrappers can
    /// still recover the same root; this is not lost-factor revocation.
    pub fn draft_access_maintenance(
        &self,
        auth: AccessPath<'_>,
        change: AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let work = self.authority.work()?;
        let admission = self
            .access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let mut intent = Vec::new();
        match &change {
            AccessChange::EnableRecovery => intent.push(1),
            AccessChange::ReplaceRecovery => intent.push(2),
            AccessChange::DisableRecovery => intent.push(3),
            AccessChange::EnrollDevice(identity) => {
                intent.push(4);
                intent.extend_from_slice(&identity.provider_id);
                intent.extend_from_slice(&identity.key_id);
                intent.push(u8::from(identity.device_bound));
                intent.push(u8::from(identity.nonexportable));
            }
            AccessChange::RemoveDevice(id) => {
                intent.push(5);
                intent.extend_from_slice(id);
            }
            AccessChange::SetProfile { profile, .. } => {
                intent.push(6);
                intent.push(profile.code());
            }
        }
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        if self.head.request_id == request {
            if let AccessChange::SetProfile { password, .. } = &change {
                let draft = self.access_draft(None, &intent, request, false)?;
                let slot = match &auth {
                    AccessPath::Device { slot_id, .. } => Some(*slot_id),
                    AccessPath::Password(_) => None,
                };
                self.verify_replacement_password(password, slot, &mut guarded, admission)?;
                work.check()?;
                return Ok((draft, None));
            }
        }
        let root =
            self.descriptor
                .access()?
                .unlock(&auth, &mut guarded, admission, &self.kdf_policy)?;
        work.check()?;
        if self.head.request_id == request {
            return Ok((self.access_draft(None, &intent, request, false)?, None));
        }
        let (descriptor, key) = self.descriptor.access()?.change(
            &root,
            &auth,
            change,
            &mut guarded,
            admission,
            &self.kdf_policy,
        )?;
        work.check()?;
        Ok((
            self.access_draft(Some(descriptor.descriptor()), &intent, request, false)?,
            key,
        ))
    }
    /// Explicit profile setup/transition. New devices must be available for
    /// proof; omitted old slots are deliberately removed, never silently kept.
    #[allow(clippy::too_many_arguments)]
    /// Setup may add the first device/recovery route. Rebuilding existing
    /// routes must explicitly choose maintenance or protective replacement.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_access_setup(
        &mut self,
        current_password: &[u8],
        auth: Option<AccessPath<'_>>,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.operation_keys()?;
        if self.head.request_id != request && self.descriptor.credential_format_id() == 3 {
            let info = self.access_info()?;
            if !info.device_slots.is_empty() || info.recovery_enabled {
                return Err(Error::UnsupportedCapability);
            }
        }
        // Only the exact latest request may reach the existing replay branch;
        // it authenticates replacement credentials and the complete setup intent.
        // A request-ID collision never authorizes a new route-removal operation.
        self.draft_access_setup_maintenance(
            current_password,
            auth,
            new_password,
            profile,
            devices,
            recovery,
            provider,
            admission,
            request,
        )
    }
    /// Explicit unchanged-key reconstruction of device/recovery wrappers.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_access_setup_maintenance(
        &mut self,
        current_password: &[u8],
        auth: Option<AccessPath<'_>>,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: AccessAdmission,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let work = self.authority.work()?;
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        let intent = Self::setup_intent(7, profile, devices, recovery);
        if profile == AccessProfile::PasswordAndDevice
            && (self.descriptor.credential_format_id() != 3
                || self.access_info()?.profile != AccessProfile::PasswordAndDevice)
        {
            return Err(Error::UnsupportedCapability);
        }
        if self.head.request_id == request {
            if self.descriptor.credential_format_id() != 3 {
                return Err(Error::OperationIdReuse);
            }
            self.verify_new_access(new_password, devices, &mut guarded, &admission)?;
            work.check()?;
            return Ok((self.access_draft(None, &intent, request, false)?, None));
        }
        let root = if let Some(path) = auth {
            self.descriptor.access()?.unlock(
                &path,
                &mut guarded,
                self.access_admission
                    .as_ref()
                    .ok_or(Error::UnsupportedCapability)?,
                &self.kdf_policy,
            )?
        } else {
            self.descriptor
                .unlock_with_policy(current_password, &self.kdf_policy)?
        };
        let epoch = if self.descriptor.credential_format_id() == 3 {
            self.descriptor
                .access()?
                .info()
                .policy_epoch
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?
        } else {
            1
        };
        let root_epoch = if self.descriptor.credential_format_id() == 3 {
            self.descriptor.access()?.root_epoch
        } else {
            0
        };
        let (descriptor, key) = if self.descriptor.format_id() == format::EPOCH_FORMAT_ID {
            format::AccessDescriptor::new(
                self.vault_id(),
                root_epoch,
                epoch,
                &root,
                new_password,
                self.kdf_profile(),
                profile,
                devices,
                recovery,
                &mut guarded,
                &admission,
                &self.kdf_policy,
            )?
        } else {
            format::AccessDescriptor::diagnostic_new_legacy(
                self.vault_id(),
                root_epoch,
                epoch,
                &root,
                new_password,
                self.kdf_profile(),
                profile,
                devices,
                recovery,
                &mut guarded,
                &admission,
                &self.kdf_policy,
            )?
        };
        work.check()?;
        let descriptor = if self.descriptor.format_id() == format::EPOCH_FORMAT_ID {
            descriptor.epoch_content()?
        } else {
            descriptor
        };
        let mut draft =
            self.access_draft(Some(descriptor.descriptor()), &intent, request, false)?;
        // This explicit trusted-host configuration belongs to the proposed
        // transition. Abandonment/abort must leave accepted configuration alone.
        draft.access_admission = Some(admission);
        Ok((draft, key))
    }
    #[allow(clippy::too_many_arguments)]
    /// Recovery replacement defaults to the full protective planner. Call
    /// draft_recovery_replacement; choose draft_recovery_maintenance explicitly
    /// only when preserving historical root/content authority is intended.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_recovery_repair(
        &self,
        _key: &RecoveryKey,
        _new_password: &[u8],
        _profile: AccessProfile,
        _devices: &[ProviderIdentity],
        _recovery: bool,
        _provider: &mut dyn KeyProvider,
        _request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        Err(Error::UnsupportedCapability)
    }
    /// Deliberate unchanged-root recovery maintenance; not compromise recovery.
    #[allow(clippy::too_many_arguments)]
    pub fn draft_recovery_maintenance(
        &self,
        key: &RecoveryKey,
        new_password: &[u8],
        profile: AccessProfile,
        devices: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<(CredentialDraft, Option<RecoveryKey>)> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        if profile == AccessProfile::PasswordAndDevice
            && self.access_info()?.profile != AccessProfile::PasswordAndDevice
        {
            return Err(Error::UnsupportedCapability);
        }
        let intent = Self::setup_intent(8, profile, devices, recovery);
        if self.head.request_id == request && !self.recovery_candidate {
            self.operation_keys()?;
            let work = self.authority.work()?;
            let admission = self
                .access_admission
                .as_ref()
                .ok_or(Error::UnsupportedCapability)?;
            let mut guarded = GuardedProvider {
                provider,
                work: &work,
            };
            self.verify_new_access(new_password, devices, &mut guarded, admission)?;
            work.check()?;
            return Ok((self.access_draft(None, &intent, request, false)?, None));
        }
        if !self.recovery_candidate
            || self.session.is_none()
            || self.audit.is_some()
            || self.pending.is_some()
        {
            return Err(Error::Conflict);
        }
        let work = self.authority.work()?;
        let admission = self
            .access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let root = self.descriptor.access()?.recover(key)?;
        let source = self.descriptor.access()?;
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        let (descriptor, new_key) = if self.descriptor.format_id() == format::EPOCH_FORMAT_ID {
            format::AccessDescriptor::new(
                self.vault_id(),
                source.root_epoch,
                source
                    .info()
                    .policy_epoch
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?,
                &root,
                new_password,
                self.kdf_profile(),
                profile,
                devices,
                recovery,
                &mut guarded,
                admission,
                &self.kdf_policy,
            )?
        } else {
            format::AccessDescriptor::diagnostic_new_legacy(
                self.vault_id(),
                source.root_epoch,
                source
                    .info()
                    .policy_epoch
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?,
                &root,
                new_password,
                self.kdf_profile(),
                profile,
                devices,
                recovery,
                &mut guarded,
                admission,
                &self.kdf_policy,
            )?
        };
        work.check()?;
        let descriptor = if self.descriptor.format_id() == format::EPOCH_FORMAT_ID {
            descriptor.epoch_content()?
        } else {
            descriptor
        };
        Ok((
            self.access_draft(Some(descriptor.descriptor()), &intent, request, true)?,
            new_key,
        ))
    }
    pub fn draft_access_password_change(
        &self,
        auth: AccessPath<'_>,
        new_password: &[u8],
        target: KdfProfile,
        provider: &mut dyn KeyProvider,
        request: [u8; 16],
    ) -> Result<CredentialDraft> {
        self.operation_keys()?;
        self.kdf_policy.admit(target)?;
        if target.memory_kib() < self.kdf_profile().memory_kib()
            || target.passes() < self.kdf_profile().passes()
        {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let work = self.authority.work()?;
        let admission = self
            .access_admission
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        let mut guarded = GuardedProvider {
            provider,
            work: &work,
        };
        let mut intent = vec![9];
        intent.extend_from_slice(&target.memory_kib().to_be_bytes());
        intent.extend_from_slice(&target.passes().to_be_bytes());
        if self.head.request_id == request {
            let slot = match auth {
                AccessPath::Password(_) => None,
                AccessPath::Device { slot_id, .. } => Some(slot_id),
            };
            self.verify_replacement_password(new_password, slot, &mut guarded, admission)?;
            work.check()?;
            return self.access_draft(None, &intent, request, false);
        }
        let root =
            self.descriptor
                .access()?
                .unlock(&auth, &mut guarded, admission, &self.kdf_policy)?;
        let password = match auth {
            AccessPath::Password(value) => Some(value),
            AccessPath::Device { password, .. } => password,
        };
        let descriptor = self.descriptor.access()?.rewrap_password(
            &root,
            password,
            new_password,
            target,
            &self.kdf_policy,
        )?;
        work.check()?;
        self.access_draft(Some(descriptor.descriptor()), &intent, request, false)
    }
}
