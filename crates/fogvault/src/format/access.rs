use super::*;
use crate::access::{
    AccessAdmission, AccessInfo, AccessPath, AccessProfile, KeyProvider, ProviderContext,
    ProviderIdentity, RecoveryKey,
};

const MAGIC: &[u8; 8] = b"FGVP0003";

#[derive(Clone, Debug)]
struct DeviceSlot {
    id: [u8; 16],
    revision: u64,
    identity: ProviderIdentity,
    protected_seed: Vec<u8>,
    root_wrapper: Vec<u8>,
}
#[derive(Clone, Debug)]
struct RecoverySlot {
    id: [u8; 16],
    revision: u64,
    root_wrapper: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct AccessDescriptor {
    pub(crate) vault_id: [u8; 16],
    pub(crate) root_epoch: u64,
    pub(crate) content_format: u16,
    policy_epoch: u64,
    pub(crate) profile: AccessProfile,
    password_id: [u8; 16],
    password_revision: u64,
    pub(crate) salt: [u8; 16],
    pub(crate) kdf: KdfProfile,
    password_wrapper: Vec<u8>,
    devices: Vec<DeviceSlot>,
    recovery: Option<RecoverySlot>,
}

impl AccessDescriptor {
    pub(crate) fn descriptor(self) -> Descriptor {
        Descriptor {
            bytes: self.encode(),
            vault_id: self.vault_id,
            salt: self.salt,
            profile: self.kdf,
            access: Some(self),
        }
    }
    pub(crate) fn info(&self) -> AccessInfo {
        AccessInfo {
            profile: self.profile,
            root_epoch: self.root_epoch,
            policy_epoch: self.policy_epoch,
            device_slots: self
                .devices
                .iter()
                .map(|slot| (slot.id, slot.identity))
                .collect(),
            recovery_enabled: self.recovery.is_some(),
        }
    }
    fn password_aad(&self, purpose: &[u8]) -> Vec<u8> {
        let mut bytes = frame(purpose);
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.root_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.password_id);
        bytes.extend_from_slice(&self.password_revision.to_be_bytes());
        bytes.extend_from_slice(&KDF_ID.to_be_bytes());
        for n in [self.kdf.memory_kib(), self.kdf.passes(), self.kdf.lanes()] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
        bytes.extend_from_slice(&self.salt);
        bytes
    }
    fn device_context(&self, slot: &DeviceSlot) -> ProviderContext {
        ProviderContext {
            vault_id: self.vault_id,
            root_epoch: self.root_epoch,
            slot_id: slot.id,
            slot_revision: slot.revision,
            identity: slot.identity,
        }
    }
    fn device_aad(&self, slot: &DeviceSlot) -> Vec<u8> {
        let mut bytes = frame(b"fogvault/prototype/device-component/v3");
        bytes.extend_from_slice(&self.device_context(slot).authenticated_bytes());
        bytes.extend_from_slice(&crypto::digest(&slot.protected_seed));
        bytes
    }
    fn outer_aad(&self, slot: &DeviceSlot) -> Vec<u8> {
        let mut bytes = self.password_aad(b"fogvault/prototype/password-device-outer/v3");
        bytes.extend_from_slice(&self.device_aad(slot));
        bytes
    }
    fn recovery_aad(&self, id: &[u8; 16], revision: u64) -> Vec<u8> {
        let mut bytes = frame(b"fogvault/prototype/owner-recovery/v3");
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.root_epoch.to_be_bytes());
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&revision.to_be_bytes());
        bytes
    }
    fn password_key(&self, password: &[u8], policy: &KdfPolicy) -> Result<Zeroizing<[u8; 32]>> {
        Ok(crypto::password_key_with_policy(
            password, &self.salt, self.kdf, policy,
        )?)
    }
    fn root(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>> {
        let array = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("access root width"))?;
        Ok(Zeroizing::new(array))
    }
    pub(crate) fn unlock_password(
        &self,
        password: &[u8],
        policy: &KdfPolicy,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if self.profile == AccessProfile::PasswordAndDevice {
            return Err(Error::UnsupportedCapability);
        }
        let key = self.password_key(password, policy)?;
        Self::root(crypto::open(
            &key,
            &self.password_aad(b"fogvault/prototype/password-root/v3"),
            &self.password_wrapper,
        )?)
    }
    pub(crate) fn unlock(
        &self,
        path: &AccessPath<'_>,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<Zeroizing<[u8; 32]>> {
        admission.profile(self.profile)?;
        match path {
            AccessPath::Password(password) => self.unlock_password(password, policy),
            AccessPath::Device { slot_id, password } => {
                let slot = self
                    .devices
                    .iter()
                    .find(|slot| &slot.id == slot_id)
                    .ok_or(Error::NotFound)?;
                admission.provider(slot.identity)?;
                if provider.capability_kind(&slot.identity)
                    != crate::access::ProviderCapabilityKind::NonExportableOperation
                {
                    return Err(Error::UnsupportedCapability);
                }
                let inner = if self.profile == AccessProfile::PasswordAndDevice {
                    let password = password.ok_or(Error::UnsupportedCapability)?;
                    let key = self.password_key(password, policy)?;
                    crypto::open(&key, &self.outer_aad(slot), &slot.root_wrapper)?
                } else if self.profile == AccessProfile::PasswordOrDevice {
                    Zeroizing::new(slot.root_wrapper.clone())
                } else {
                    return Err(Error::UnsupportedCapability);
                };
                let seed = provider
                    .unwrap_seed(&self.device_context(slot), &slot.protected_seed)
                    .map_err(Error::Provider)?;
                let key = crypto::derive(&seed, &self.vault_id, &self.device_aad(slot))?;
                Self::root(crypto::open(&key, &self.device_aad(slot), &inner)?)
            }
        }
    }
    pub(crate) fn recover(&self, key: &RecoveryKey) -> Result<Zeroizing<[u8; 32]>> {
        let slot = self.recovery.as_ref().ok_or(Error::UnsupportedCapability)?;
        if key.vault_id != self.vault_id
            || key.root_epoch != self.root_epoch
            || key.slot_id != slot.id
        {
            return Err(Error::Integrity);
        }
        let aad = self.recovery_aad(&slot.id, slot.revision);
        let wrapping = crypto::derive(&key.secret, &self.vault_id, &aad)?;
        Self::root(crypto::open(&wrapping, &aad, &slot.root_wrapper)?)
    }
    /// The sole maintained fresh descriptor uses the epoch-bound content format.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        vault_id: [u8; 16],
        root_epoch: u64,
        policy_epoch: u64,
        root: &[u8; 32],
        password: &[u8],
        kdf: KdfProfile,
        profile: AccessProfile,
        identities: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        Self::new_for_content(
            EPOCH_FORMAT_ID,
            vault_id,
            root_epoch,
            policy_epoch,
            root,
            password,
            kdf,
            profile,
            identities,
            recovery,
            provider,
            admission,
            policy,
        )
    }

    /// Explicit constructor for immutable legacy fixture/diagnostic workflows.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn diagnostic_new_legacy(
        vault_id: [u8; 16],
        root_epoch: u64,
        policy_epoch: u64,
        root: &[u8; 32],
        password: &[u8],
        kdf: KdfProfile,
        profile: AccessProfile,
        identities: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        Self::new_for_content(
            INDEX_FORMAT_ID,
            vault_id,
            root_epoch,
            policy_epoch,
            root,
            password,
            kdf,
            profile,
            identities,
            recovery,
            provider,
            admission,
            policy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_for_content(
        content_format: u16,
        vault_id: [u8; 16],
        root_epoch: u64,
        policy_epoch: u64,
        root: &[u8; 32],
        password: &[u8],
        kdf: KdfProfile,
        profile: AccessProfile,
        identities: &[ProviderIdentity],
        recovery: bool,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        admission.profile(profile)?;
        policy.admit(kdf)?;
        if identities.len() > admission.max_device_slots
            || (profile == AccessProfile::Portable) != identities.is_empty()
        {
            return Err(Error::UnsupportedCapability);
        }
        let per_device = 64usize
            .checked_add(admission.max_provider_blob_bytes)
            .and_then(|n| {
                n.checked_add(if profile == AccessProfile::PasswordAndDevice {
                    112
                } else {
                    72
                })
            })
            .ok_or(Error::ResourceLimit)?;
        let bound = 108usize
            .checked_add(if profile == AccessProfile::PasswordAndDevice {
                0
            } else {
                72
            })
            .and_then(|n| {
                per_device
                    .checked_mul(identities.len())
                    .and_then(|slots| n.checked_add(slots))
            })
            .and_then(|n| n.checked_add(if recovery { 96 } else { 0 }))
            .ok_or(Error::ResourceLimit)?;
        if bound > admission.max_descriptor_bytes {
            return Err(Error::ResourceLimit);
        }
        for identity in identities {
            admission.provider(*identity)?;
        }
        let mut value = Self {
            vault_id,
            root_epoch,
            content_format,
            policy_epoch,
            profile,
            password_id: crypto::random()?,
            password_revision: 1,
            salt: crypto::random()?,
            kdf,
            password_wrapper: Vec::new(),
            devices: Vec::new(),
            recovery: None,
        };
        let password_key = value.password_key(password, policy)?;
        if profile != AccessProfile::PasswordAndDevice {
            value.password_wrapper = crypto::seal(
                &password_key,
                &value.password_aad(b"fogvault/prototype/password-root/v3"),
                root,
            )?;
        }
        for identity in identities {
            value.add_device(root, &password_key, *identity, provider, admission)?;
        }
        let recovery_key = if recovery {
            Some(value.set_recovery(root)?)
        } else {
            None
        };
        value.admit(admission, policy)?;
        Ok((value, recovery_key))
    }
    fn add_device(
        &mut self,
        root: &[u8; 32],
        password_key: &[u8; 32],
        identity: ProviderIdentity,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
    ) -> Result<()> {
        admission.provider(identity)?;
        if provider.capability_kind(&identity)
            != crate::access::ProviderCapabilityKind::NonExportableOperation
        {
            return Err(Error::UnsupportedCapability);
        }
        if self.devices.len() >= admission.max_device_slots
            || self.devices.iter().any(|slot| slot.identity == identity)
        {
            return Err(Error::Conflict);
        }
        let mut slot = DeviceSlot {
            id: crypto::random()?,
            revision: 1,
            identity,
            protected_seed: Vec::new(),
            root_wrapper: Vec::new(),
        };
        if slot.id == self.password_id
            || self.devices.iter().any(|old| old.id == slot.id)
            || self.recovery.as_ref().is_some_and(|old| old.id == slot.id)
        {
            return Err(Error::Conflict);
        }
        let seed = Zeroizing::new(crypto::random::<32>()?);
        let context = self.device_context(&slot);
        slot.protected_seed = provider
            .wrap_seed(&context, &seed)
            .map_err(Error::Provider)?;
        if slot.protected_seed.len() > admission.max_provider_blob_bytes {
            return Err(Error::ResourceLimit);
        }
        let proof = provider
            .unwrap_seed(&context, &slot.protected_seed)
            .map_err(Error::Provider)?;
        if !crypto::tags_match(&seed, &proof) {
            return Err(Error::Integrity);
        }
        let aad = self.device_aad(&slot);
        let key = crypto::derive(&seed, &self.vault_id, &aad)?;
        let inner = Zeroizing::new(crypto::seal(&key, &aad, root)?);
        slot.root_wrapper = if self.profile == AccessProfile::PasswordAndDevice {
            crypto::seal(password_key, &self.outer_aad(&slot), &inner)?
        } else {
            inner.to_vec()
        };
        self.devices.push(slot);
        self.devices.sort_by_key(|slot| slot.id);
        Ok(())
    }
    fn set_recovery(&mut self, root: &[u8; 32]) -> Result<RecoveryKey> {
        let key = RecoveryKey::generate(self.vault_id, self.root_epoch)?;
        if key.slot_id == self.password_id || self.devices.iter().any(|slot| slot.id == key.slot_id)
        {
            return Err(Error::Conflict);
        }
        let revision = self
            .recovery
            .as_ref()
            .map(|slot| slot.revision.checked_add(1).ok_or(Error::ResourceLimit))
            .transpose()?
            .unwrap_or(1);
        let aad = self.recovery_aad(&key.slot_id, revision);
        let wrapping = crypto::derive(&key.secret, &self.vault_id, &aad)?;
        self.recovery = Some(RecoverySlot {
            id: key.slot_id,
            revision,
            root_wrapper: crypto::seal(&wrapping, &aad, root)?,
        });
        Ok(key)
    }
    pub(crate) fn rewrap_password(
        &self,
        root: &[u8; 32],
        old_password: Option<&[u8]>,
        new_password: &[u8],
        target: KdfProfile,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        policy.admit(target)?;
        if target.memory_kib() < self.kdf.memory_kib() || target.passes() < self.kdf.passes() {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        let old_key = if self.profile == AccessProfile::PasswordAndDevice {
            Some(self.password_key(old_password.ok_or(Error::UnsupportedCapability)?, policy)?)
        } else {
            None
        };
        let mut next = self.clone();
        next.policy_epoch = next
            .policy_epoch
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        next.password_revision = next
            .password_revision
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        next.salt = crypto::random()?;
        next.kdf = target;
        let key = next.password_key(new_password, policy)?;
        if let Some(old_key) = old_key {
            let password_aad = next.password_aad(b"fogvault/prototype/password-device-outer/v3");
            for (source, destination) in self.devices.iter().zip(&mut next.devices) {
                let inner = crypto::open(&old_key, &self.outer_aad(source), &source.root_wrapper)?;
                // Compute next context without borrowing mutable devices.
                let mut aad = password_aad.clone();
                aad.extend_from_slice(&self.device_aad(source));
                destination.root_wrapper = crypto::seal(&key, &aad, &inner)?;
            }
        } else {
            next.password_wrapper = crypto::seal(
                &key,
                &next.password_aad(b"fogvault/prototype/password-root/v3"),
                root,
            )?;
        }
        Ok(next)
    }
    pub(crate) fn change(
        &self,
        root: &[u8; 32],
        auth: &AccessPath<'_>,
        change: crate::access::AccessChange<'_>,
        provider: &mut dyn KeyProvider,
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<(Self, Option<RecoveryKey>)> {
        use crate::access::AccessChange;
        let mut next = self.clone();
        next.policy_epoch = next
            .policy_epoch
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let key = match change {
            AccessChange::EnableRecovery => {
                if self.recovery.is_some() {
                    return Err(Error::Conflict);
                }
                Some(next.set_recovery(root)?)
            }
            AccessChange::ReplaceRecovery => {
                if self.recovery.is_none() {
                    return Err(Error::Conflict);
                }
                Some(next.set_recovery(root)?)
            }
            AccessChange::DisableRecovery => {
                next.recovery = None;
                None
            }
            AccessChange::RemoveDevice(id) => {
                let before = next.devices.len();
                next.devices.retain(|slot| slot.id != id);
                if next.devices.len() == before || next.devices.is_empty() {
                    return Err(Error::Conflict);
                }
                None
            }
            AccessChange::EnrollDevice(identity) => {
                if self.profile == AccessProfile::Portable {
                    return Err(Error::UnsupportedCapability);
                }
                let password = match auth {
                    AccessPath::Password(value) => Some(*value),
                    AccessPath::Device { password, .. } => *password,
                };
                let key = if self.profile == AccessProfile::PasswordAndDevice {
                    self.password_key(password.ok_or(Error::UnsupportedCapability)?, policy)?
                } else {
                    Zeroizing::new([0; 32])
                };
                next.add_device(root, &key, identity, provider, admission)?;
                None
            }
            AccessChange::SetProfile { profile, password } => {
                admission.profile(profile)?;
                // Header-only transitions cannot revoke historical root paths.
                // Entry into strict access requires the explicit fresh-root,
                // full-content protective transition instead.
                if profile == AccessProfile::PasswordAndDevice
                    && self.profile != AccessProfile::PasswordAndDevice
                {
                    return Err(Error::UnsupportedCapability);
                }
                if profile != AccessProfile::Portable && self.devices.is_empty() {
                    return Err(Error::UnsupportedCapability);
                }
                let source_key = if self.profile == AccessProfile::PasswordAndDevice {
                    let old = match auth {
                        AccessPath::Password(value) => Some(*value),
                        AccessPath::Device { password, .. } => *password,
                    }
                    .ok_or(Error::UnsupportedCapability)?;
                    Some(self.password_key(old, policy)?)
                } else {
                    None
                };
                next.profile = profile;
                next.password_revision = next
                    .password_revision
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?;
                next.salt = crypto::random()?;
                let key = next.password_key(password, policy)?;
                if profile == AccessProfile::Portable {
                    next.devices.clear();
                } else {
                    let outer = next.password_aad(b"fogvault/prototype/password-device-outer/v3");
                    for (source, destination) in self.devices.iter().zip(&mut next.devices) {
                        let inner = if let Some(source_key) = &source_key {
                            crypto::open(source_key, &self.outer_aad(source), &source.root_wrapper)?
                        } else {
                            Zeroizing::new(source.root_wrapper.clone())
                        };
                        // Reusing a stored slot is not proof the selected
                        // provider still works. Prove every retained target
                        // route before removing/changing the current route.
                        admission.provider(destination.identity)?;
                        if provider.capability_kind(&destination.identity)
                            != crate::access::ProviderCapabilityKind::NonExportableOperation
                        {
                            return Err(Error::UnsupportedCapability);
                        }
                        let seed = provider
                            .unwrap_seed(&self.device_context(source), &source.protected_seed)
                            .map_err(Error::Provider)?;
                        let device_aad = self.device_aad(source);
                        let device_key = crypto::derive(&seed, &self.vault_id, &device_aad)?;
                        let proof = Self::root(crypto::open(&device_key, &device_aad, &inner)?)?;
                        if !crypto::tags_match(&proof, root) {
                            return Err(Error::Integrity);
                        }
                        destination.root_wrapper = if profile == AccessProfile::PasswordAndDevice {
                            let mut aad = outer.clone();
                            aad.extend_from_slice(&device_aad);
                            crypto::seal(&key, &aad, &inner)?
                        } else {
                            inner.to_vec()
                        };
                    }
                }
                next.password_wrapper = if profile == AccessProfile::PasswordAndDevice {
                    Vec::new()
                } else {
                    crypto::seal(
                        &key,
                        &next.password_aad(b"fogvault/prototype/password-root/v3"),
                        root,
                    )?
                };
                None
            }
        };
        next.admit(admission, policy)?;
        Ok((next, key))
    }
    /// Used while preparing a fresh descriptor, never to relabel live records.
    /// Epoch zero is the first authenticated wrapping epoch for new vaults.
    pub(crate) fn epoch_content(mut self) -> Result<Self> {
        self.content_format = EPOCH_FORMAT_ID;
        Ok(self)
    }
    pub(crate) fn admit(&self, admission: &AccessAdmission, policy: &KdfPolicy) -> Result<()> {
        if !matches!(self.content_format, INDEX_FORMAT_ID | EPOCH_FORMAT_ID) {
            return Err(Error::Malformed("content/epoch profile"));
        }
        admission.profile(self.profile)?;
        policy.admit(self.kdf)?;
        if self.encode().len() > admission.max_descriptor_bytes
            || self.devices.len() > admission.max_device_slots
            || u32::try_from(self.devices.len()).is_err()
        {
            return Err(Error::ResourceLimit);
        }
        if (self.profile == AccessProfile::Portable) != self.devices.is_empty() {
            return Err(Error::Malformed("profile/device count"));
        }
        if self.password_wrapper.len()
            != if self.profile == AccessProfile::PasswordAndDevice {
                0
            } else {
                72
            }
        {
            return Err(Error::Malformed("password wrapper width"));
        }
        for slot in &self.devices {
            admission.provider(slot.identity)?;
            if slot.protected_seed.is_empty()
                || slot.protected_seed.len() > admission.max_provider_blob_bytes
                || u32::try_from(slot.protected_seed.len()).is_err()
                || slot.root_wrapper.len()
                    != if self.profile == AccessProfile::PasswordAndDevice {
                        112
                    } else {
                        72
                    }
            {
                return Err(Error::Malformed("device wrapper width"));
            }
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        for value in [3u16, SUITE_ID, self.content_format] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.root_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.policy_epoch.to_be_bytes());
        bytes.push(self.profile.code());
        bytes.extend_from_slice(&self.password_id);
        bytes.extend_from_slice(&self.password_revision.to_be_bytes());
        bytes.extend_from_slice(&KDF_ID.to_be_bytes());
        for value in [self.kdf.memory_kib(), self.kdf.passes(), self.kdf.lanes()] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&(self.password_wrapper.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.password_wrapper);
        bytes.extend_from_slice(&(self.devices.len() as u32).to_be_bytes());
        for slot in &self.devices {
            bytes.extend_from_slice(&slot.id);
            bytes.extend_from_slice(&slot.revision.to_be_bytes());
            bytes.extend_from_slice(&slot.identity.provider_id);
            bytes.extend_from_slice(&slot.identity.key_id);
            bytes.push(u8::from(slot.identity.device_bound));
            bytes.push(u8::from(slot.identity.nonexportable));
            bytes.extend_from_slice(&(slot.protected_seed.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&slot.protected_seed);
            bytes.extend_from_slice(&(slot.root_wrapper.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&slot.root_wrapper);
        }
        bytes.push(u8::from(self.recovery.is_some()));
        if let Some(slot) = &self.recovery {
            bytes.extend_from_slice(&slot.id);
            bytes.extend_from_slice(&slot.revision.to_be_bytes());
            bytes.extend_from_slice(&slot.root_wrapper);
        }
        bytes
    }
    pub(crate) fn parse(
        bytes: &[u8],
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        admission.validate()?;
        if bytes.len() > admission.max_descriptor_bytes {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < 107 || &bytes[..8] != MAGIC {
            return Err(Error::Malformed("P3 descriptor width/magic"));
        }
        let mut r = Reader::new(&bytes[8..]);
        if r.u16()? != 3 || r.u16()? != SUITE_ID {
            return Err(Error::Malformed("P3 suite/content context"));
        }
        let content_format = r.u16()?;
        if !matches!(content_format, INDEX_FORMAT_ID | EPOCH_FORMAT_ID) {
            return Err(Error::Malformed("P3 suite/content context"));
        }
        let vault_id = r.array()?;
        let root_epoch = r.u64()?;
        let policy_epoch = r.u64()?;
        let profile = AccessProfile::parse(r.u8()?)?;
        admission.profile(profile)?;
        let password_id = r.array()?;
        let password_revision = r.u64()?;
        if r.u16()? != KDF_ID {
            return Err(Error::UnsupportedCapability);
        }
        let kdf = KdfProfile::argon2id(r.u32()?, r.u32()?)?;
        if r.u32()? != 1 {
            return Err(Error::Malformed("P3 KDF lanes"));
        }
        policy.admit(kdf)?;
        let salt = r.array()?;
        let n = r.u16()? as usize;
        let password_wrapper = r.take(n)?.to_vec();
        let count = r.u32()? as usize;
        if count > admission.max_device_slots {
            return Err(Error::ResourceLimit);
        }
        let mut devices = Vec::new();
        for _ in 0..count {
            let id = r.array()?;
            let revision = r.u64()?;
            let provider_id = r.array()?;
            let key_id = r.array()?;
            let flags = [r.u8()?, r.u8()?];
            if flags.iter().any(|v| *v > 1) {
                return Err(Error::Malformed("P3 provider flags"));
            }
            let identity = ProviderIdentity {
                provider_id,
                key_id,
                device_bound: flags[0] == 1,
                nonexportable: flags[1] == 1,
            };
            admission.provider(identity)?;
            let n = r.u32()? as usize;
            if n > admission.max_provider_blob_bytes {
                return Err(Error::ResourceLimit);
            }
            let protected_seed = r.take(n)?.to_vec();
            let n = r.u16()? as usize;
            let root_wrapper = r.take(n)?.to_vec();
            if devices.last().is_some_and(|old: &DeviceSlot| old.id >= id)
                || id == password_id
                || revision == 0
            {
                return Err(Error::Malformed("P3 slot ordering/identity"));
            }
            devices.push(DeviceSlot {
                id,
                revision,
                identity,
                protected_seed,
                root_wrapper,
            });
        }
        let recovery = match r.u8()? {
            0 => None,
            1 => {
                let id = r.array()?;
                let revision = r.u64()?;
                if id == password_id || devices.iter().any(|d| d.id == id) || revision == 0 {
                    return Err(Error::Malformed("P3 recovery identity"));
                }
                Some(RecoverySlot {
                    id,
                    revision,
                    root_wrapper: r.take(72)?.to_vec(),
                })
            }
            _ => return Err(Error::Malformed("P3 recovery marker")),
        };
        r.finish()?;
        if policy_epoch == 0 || password_revision == 0 {
            return Err(Error::Malformed("P3 policy epoch"));
        }
        let value = Self {
            vault_id,
            root_epoch,
            content_format,
            policy_epoch,
            profile,
            password_id,
            password_revision,
            salt,
            kdf,
            password_wrapper,
            devices,
            recovery,
        };
        value.admit(admission, policy)?;
        if value.encode() != bytes {
            return Err(Error::Malformed("noncanonical P3 descriptor"));
        }
        Ok(value)
    }
}

impl Descriptor {
    pub(crate) fn parse_access(
        bytes: &[u8],
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        if bytes.get(12..14) == Some(EPOCH_FORMAT_ID.to_be_bytes().as_slice()) {
            return Err(Error::UnsupportedCapability);
        }
        AccessDescriptor::parse(bytes, admission, policy).map(AccessDescriptor::descriptor)
    }
    pub(crate) fn parse_epoch_access(
        bytes: &[u8],
        admission: &AccessAdmission,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        if bytes.get(12..14) != Some(EPOCH_FORMAT_ID.to_be_bytes().as_slice()) {
            return Err(Error::UnsupportedCapability);
        }
        AccessDescriptor::parse(bytes, admission, policy).map(AccessDescriptor::descriptor)
    }
    pub(crate) fn access(&self) -> Result<&AccessDescriptor> {
        self.access.as_ref().ok_or(Error::UnsupportedCapability)
    }
}
