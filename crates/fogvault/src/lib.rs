//! Portable FogVault candidate engine. Storage adapters own I/O, this crate owns lifecycle.
//! No production compatibility or security audit is implied.
//!
//! Construction modules are private in the ordinary API:
//! ```compile_fail
//! use fogvault::crypto::password_key;
//! ```
//! ```compile_fail
//! use fogvault::format::Descriptor;
//! ```
//! ```compile_fail
//! use fogvault::index::upsert;
//! ```
//! ```compile_fail
//! fn leak(engine: &fogvault::Engine) { let _ = engine.root_key(); }
//! ```

mod access;
pub mod budget;
pub mod control;
mod crypto;
mod format;
mod index;
mod kdf;
mod lifecycle;
mod password;
pub use access::*;
pub use budget::{WorkBudget, WorkReservation, WorkUsage};
pub use control::*;
pub use crypto::CryptoError;
pub use format::Entry as IndexEntry;
pub use format::{DESCRIPTOR_LEN, INDEX_HEAD_LEN};
pub use index::{NodeHash, NodeStore, Stats as IndexStats, MAX_NODE_BYTES, MAX_PATH_NODES};
pub use kdf::{KdfPolicy, KdfProfile};
pub use lifecycle::*;
pub use password::password_utf8_bytes;

/// Legacy codec/primitive fixture surface, excluded from the default public API.
/// This unpublished diagnostic feature is not a supported product feature.
#[cfg(feature = "experimental-codecs")]
#[doc(hidden)]
pub mod experimental {
    pub mod crypto {
        pub use crate::crypto::*;
    }
    pub mod format {
        pub use crate::format::*;
    }
    pub mod index {
        pub use crate::index::*;
    }
}

use std::fmt;

pub type RecordId = [u8; 16];

/// Explicit host policy, not a proposed universal production limit.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_payload_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_records: usize,
}

impl Limits {
    pub fn head_bytes(self) -> Result<usize> {
        Ok(format::INDEX_HEAD_LEN)
    }

    /// Explicit bound for legacy content-one/content-two diagnostics.
    /// Maintained callers use `Engine::envelope_byte_limit()` for an opened
    /// descriptor or `current_envelope_bytes()` before current creation.
    pub fn diagnostic_legacy_envelope_bytes(self) -> Result<usize> {
        self.max_payload_bytes
            .checked_add(self.max_metadata_bytes)
            .and_then(|n| n.checked_add(168))
            .ok_or(Error::ResourceLimit)
    }

    /// Checked frame size for the selected current content-three format.
    /// This is local host policy arithmetic, never file-selected admission.
    pub fn current_envelope_bytes(self) -> Result<usize> {
        self.max_payload_bytes
            .checked_add(self.max_metadata_bytes)
            .and_then(|n| n.checked_add(176))
            .ok_or(Error::ResourceLimit)
    }

    pub fn validate_record(self, metadata: &[u8], payload: &[u8]) -> Result<()> {
        if metadata.len() > self.max_metadata_bytes || payload.len() > self.max_payload_bytes {
            return Err(Error::ResourceLimit);
        }
        // Common minimum-frame arithmetic. The descriptor-specific encoder
        // additionally checks its selected format's exact overhead.
        self.diagnostic_legacy_envelope_bytes()?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Crypto(crypto::CryptoError),
    Malformed(&'static str),
    ResourceLimit,
    Capacity,
    Storage,
    Exists,
    NotFound,
    Locked,
    StaleSession,
    Conflict,
    Integrity,
    OperationIdReuse,
    OutcomeUnknown { request_id: [u8; 16] },
    InjectedFailure,
    UnsupportedCapability,
    Provider(ProviderError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => error.fmt(f),
            Self::Malformed(message) => write!(f, "invalid experiment format: {message}"),
            Self::ResourceLimit => f.write_str("host resource policy rejected input"),
            Self::Capacity => f.write_str("storage capacity or quota is exhausted"),
            Self::Storage => f.write_str("scratch storage operation failed"),
            Self::Exists => f.write_str("destination already exists"),
            Self::NotFound => f.write_str("record or latest receipt not found"),
            Self::Locked => f.write_str("vault is locked"),
            Self::StaleSession => {
                f.write_str("session has been revoked or belongs to another vault")
            }
            Self::Conflict => f.write_str("accepted head or record revision changed"),
            Self::Integrity => f.write_str("committed vault content is inconsistent"),
            Self::OperationIdReuse => f.write_str("request ID was reused with different contents"),
            Self::OutcomeUnknown { .. } => f.write_str("commit outcome requires reconciliation"),
            Self::InjectedFailure => f.write_str("experiment interrupted before commit"),
            Self::UnsupportedCapability => f.write_str("required capability is unsupported"),
            Self::Provider(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<crypto::CryptoError> for Error {
    fn from(value: crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

pub fn validate_policy(limits: Limits) -> Result<()> {
    limits.head_bytes()?;
    limits.diagnostic_legacy_envelope_bytes()?;
    Ok(())
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Crypto(CryptoError::AuthenticationFailed) => "Authentication",
            Self::Crypto(CryptoError::RejectedKdfParameters | CryptoError::AllocationFailed)
            | Self::ResourceLimit => "ResourceLimit",
            Self::Crypto(CryptoError::InvalidEnvelope) | Self::Integrity => "Integrity",
            Self::Crypto(_) => "Crypto",
            Self::Malformed(_) => "InvalidInput",
            Self::Capacity => "Capacity",
            Self::Storage => "Storage",
            Self::Exists => "Exists",
            Self::NotFound => "NotFound",
            Self::Locked => "Locked",
            Self::StaleSession => "StaleSession",
            Self::Conflict => "Conflict",
            Self::OperationIdReuse => "OperationIdReuse",
            Self::OutcomeUnknown { .. } => "OutcomeUnknown",
            Self::InjectedFailure => "InjectedFailure",
            Self::UnsupportedCapability => "UnsupportedCapability",
            Self::Provider(error) => error.code(),
        }
    }
}
