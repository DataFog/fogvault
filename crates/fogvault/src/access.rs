//! Explicitly admitted P3 access-policy experiment. No hardware qualification.
use crate::{crypto, Error, Result};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessProfile {
    Portable,
    PasswordOrDevice,
    PasswordAndDevice,
}
impl AccessProfile {
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Portable => 0,
            Self::PasswordOrDevice => 1,
            Self::PasswordAndDevice => 2,
        }
    }
    pub(crate) fn parse(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Portable),
            1 => Ok(Self::PasswordOrDevice),
            2 => Ok(Self::PasswordAndDevice),
            _ => Err(Error::Malformed("access profile")),
        }
    }
}

/// Opaque local registration identifiers, never a provider-discovery URL.
/// Capability declarations need separate host/provider qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub provider_id: [u8; 16],
    pub key_id: [u8; 16],
    pub device_bound: bool,
    pub nonexportable: bool,
}

/// Trusted host admission. The saved descriptor cannot add profiles/providers
/// or raise any byte/slot limit. No universal production limits are selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessAdmission {
    pub allowed_profiles: Vec<AccessProfile>,
    pub providers: Vec<ProviderIdentity>,
    pub max_descriptor_bytes: usize,
    pub max_device_slots: usize,
    pub max_provider_blob_bytes: usize,
}
impl AccessAdmission {
    pub(crate) fn validate(&self) -> Result<()> {
        if u32::try_from(self.max_device_slots).is_err()
            || u32::try_from(self.max_provider_blob_bytes).is_err()
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    pub(crate) fn profile(&self, profile: AccessProfile) -> Result<()> {
        self.validate()?;
        if self.allowed_profiles.contains(&profile) {
            Ok(())
        } else {
            Err(Error::UnsupportedCapability)
        }
    }
    pub(crate) fn provider(&self, identity: ProviderIdentity) -> Result<()> {
        if !identity.device_bound || !identity.nonexportable || !self.providers.contains(&identity)
        {
            Err(Error::UnsupportedCapability)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderError {
    Denied,
    Cancelled,
    Unavailable,
    IdentityChanged,
    Unsupported,
    InvalidResponse,
    Failure,
}
impl ProviderError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Denied => "ProviderDenied",
            Self::Cancelled => "Cancelled",
            Self::Unavailable => "ProviderUnavailable",
            Self::IdentityChanged => "ProviderIdentityChanged",
            Self::Unsupported => "UnsupportedCapability",
            Self::InvalidResponse => "ProviderInvalidResponse",
            Self::Failure => "ProviderFailure",
        }
    }
}
impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "provider permission denied",
            Self::Cancelled => "provider request cancelled",
            Self::Unavailable => "provider unavailable",
            Self::IdentityChanged => "provider identity changed",
            Self::Unsupported => "provider operation unsupported",
            Self::InvalidResponse => "provider returned invalid material",
            Self::Failure => "provider operation failed",
        })
    }
}
impl std::error::Error for ProviderError {}
pub type ProviderResult<T> = std::result::Result<T, ProviderError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCapabilityKind {
    RawSecret,
    DerivedSecret,
    NonExportableOperation,
    ConvenienceCache,
}

/// Complete fixed-width context for the selected seed-wrapping operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderContext {
    pub vault_id: [u8; 16],
    pub root_epoch: u64,
    pub slot_id: [u8; 16],
    pub slot_revision: u64,
    pub identity: ProviderIdentity,
}
impl ProviderContext {
    pub fn authenticated_bytes(&self) -> Vec<u8> {
        let mut bytes = crate::format::frame(b"fogvault/prototype/provider-seed/v3");
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.root_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.slot_id);
        bytes.extend_from_slice(&self.slot_revision.to_be_bytes());
        bytes.extend_from_slice(&self.identity.provider_id);
        bytes.extend_from_slice(&self.identity.key_id);
        bytes.push(u8::from(self.identity.device_bound));
        bytes.push(u8::from(self.identity.nonexportable));
        bytes
    }
}

/// Synchronous operation boundary, called without storage/registry locks.
/// Providers see independent 32-byte slot seeds, never the vault root. They must
/// preserve the exact identity/context and fail rather than select another key.
/// Async platform bridges and real hardware remain separately qualified work.
pub trait KeyProvider {
    /// Explicit local declaration, not hardware attestation or an I/O operation.
    /// There is deliberately no strongest-capability default. The trusted host
    /// must qualify the selected implementation and configuration separately.
    fn capability_kind(&self, identity: &ProviderIdentity) -> ProviderCapabilityKind;
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>>;
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>>;
}

pub enum AccessPath<'a> {
    Password(&'a [u8]),
    Device {
        slot_id: [u8; 16],
        password: Option<&'a [u8]>,
    },
}

/// Owner-held random recovery material. It is deliberately not Clone/Debug or
/// automatically serializable. Export is an explicit secret-owning operation.
pub struct RecoveryKey {
    pub(crate) vault_id: [u8; 16],
    pub(crate) slot_id: [u8; 16],
    pub(crate) root_epoch: u64,
    pub(crate) secret: Zeroizing<[u8; 32]>,
}
impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey([redacted])")
    }
}
impl RecoveryKey {
    pub(crate) fn generate(vault_id: [u8; 16], root_epoch: u64) -> Result<Self> {
        Ok(Self {
            vault_id,
            root_epoch,
            slot_id: crypto::random()?,
            secret: Zeroizing::new(crypto::random()?),
        })
    }
    /// Binary owner kit: fixed magic, vault/slot IDs, root epoch, secret32. The
    /// kit supplies access material, not a backup of the encrypted vault data.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"FGVRKEY3".to_vec());
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.slot_id);
        bytes.extend_from_slice(&self.root_epoch.to_be_bytes());
        bytes.extend_from_slice(self.secret.as_ref());
        bytes
    }
    pub fn import(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 80 || &bytes[..8] != b"FGVRKEY3" {
            return Err(Error::Malformed("recovery kit"));
        }
        Ok(Self {
            vault_id: bytes[8..24]
                .try_into()
                .map_err(|_| Error::Malformed("recovery vault"))?,
            slot_id: bytes[24..40]
                .try_into()
                .map_err(|_| Error::Malformed("recovery slot"))?,
            root_epoch: u64::from_be_bytes(
                bytes[40..48]
                    .try_into()
                    .map_err(|_| Error::Malformed("recovery epoch"))?,
            ),
            secret: Zeroizing::new(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| Error::Malformed("recovery secret"))?,
            ),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessInfo {
    pub profile: AccessProfile,
    pub root_epoch: u64,
    pub policy_epoch: u64,
    pub device_slots: Vec<([u8; 16], ProviderIdentity)>,
    pub recovery_enabled: bool,
}

/// The key material changed by a completed or proposed authority operation.
/// This describes the operation, not erasure of historical copies or plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEffect {
    /// Only credential wrappers/policy change; prior root authority survives.
    Preserved,
    /// Fresh root and fresh content keys protect the selected current graph.
    FreshRootAndContentKeys,
}

pub enum AccessChange<'a> {
    EnableRecovery,
    ReplaceRecovery,
    DisableRecovery,
    EnrollDevice(ProviderIdentity),
    RemoveDevice([u8; 16]),
    SetProfile {
        profile: AccessProfile,
        password: &'a [u8],
    },
}
