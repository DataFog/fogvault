//! Disposable profile implementation. This is not a frozen or audited protocol.

use crate::kdf::{KdfPolicy, KdfProfile};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;

// The current consumer's observed profile, not a portable production default.
pub const MEMORY_KIB: u32 = 65_536;
pub const PASSES: u32 = 3;
pub const LANES: u32 = 1;

const DERIVATION_DOMAIN: &[u8] = b"fogvault/prototype/key-derivation/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    EntropyUnavailable,
    RejectedKdfParameters,
    AllocationFailed,
    KeyDerivationFailed,
    InvalidEnvelope,
    AuthenticationFailed,
    EncryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "secure entropy is unavailable",
            Self::RejectedKdfParameters => "KDF parameters do not match the experiment profile",
            Self::AllocationFailed => "unable to allocate bounded cryptographic work memory",
            Self::KeyDerivationFailed => "key derivation failed",
            Self::InvalidEnvelope => "invalid encrypted envelope",
            Self::AuthenticationFailed => "authentication failed",
            Self::EncryptionFailed => "encryption failed",
        })
    }
}

impl std::error::Error for CryptoError {}

pub fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut output = [0u8; N];
    if getrandom::fill(&mut output).is_err() {
        output.zeroize();
        return Err(CryptoError::EntropyUnavailable);
    }
    Ok(output)
}

#[cfg(any(test, feature = "experimental-codecs"))]
pub fn password_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    memory: u32,
    passes: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    // Reject untrusted costs before the library constructs or allocates the KDF.
    if (memory, passes, lanes) != (MEMORY_KIB, PASSES, LANES) {
        return Err(CryptoError::RejectedKdfParameters);
    }
    password_key_with_policy(
        password,
        salt,
        KdfProfile::baseline(),
        &KdfPolicy::baseline(),
    )
}

/// Policy admission precedes parameter construction and work-memory allocation.
pub fn password_key_with_policy(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    profile: KdfProfile,
    policy: &KdfPolicy,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    policy
        .admit(profile)
        .map_err(|_| CryptoError::RejectedKdfParameters)?;
    let parameters = Params::new(
        profile.memory_kib(),
        profile.passes(),
        profile.lanes(),
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::RejectedKdfParameters)?;
    let count = parameters.block_count();
    let workspace_bytes = count
        .checked_mul(std::mem::size_of::<Block>())
        .ok_or(CryptoError::AllocationFailed)?;
    // The reservation lives until after the zeroizing block owner is dropped.
    // Refuse aggregate work before allocating the Argon2 block vector.
    let _reservation = policy
        .work_budget()
        .map(|budget| budget.reserve(workspace_bytes))
        .transpose()
        .map_err(|_| CryptoError::AllocationFailed)?;
    let mut blocks = Zeroizing::new(Vec::<Block>::new());
    blocks
        .try_reserve_exact(count)
        .map_err(|_| CryptoError::AllocationFailed)?;
    blocks.resize(count, Block::new());
    let mut output = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into_with_memory(password, salt, output.as_mut(), blocks.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

pub fn derive(
    root: &[u8; KEY_LEN],
    vault_id: &[u8; 16],
    purpose: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let length = u64::try_from(purpose.len())
        .map_err(|_| CryptoError::KeyDerivationFailed)?
        .to_be_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), root);
    let mut output = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand_multi_info(&[DERIVATION_DOMAIN, &length, purpose], output.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce = random::<NONCE_LEN>()?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let total = nonce
        .len()
        .checked_add(ciphertext.len())
        .ok_or(CryptoError::AllocationFailed)?;
    let mut envelope = Vec::new();
    envelope
        .try_reserve_exact(total)
        .map_err(|_| CryptoError::AllocationFailed)?;
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    let nonce: [u8; NONCE_LEN] = envelope[..NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidEnvelope)?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &envelope[NONCE_LEN..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn digest(data: &[u8]) -> [u8; KEY_LEN] {
    Sha256::digest(data).into()
}

pub fn mac(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; KEY_LEN] {
    let mut authenticator = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts every fixed 32-byte key");
    authenticator.update(data);
    authenticator.finalize().into_bytes().into()
}

pub fn verify_mac(
    key: &[u8; KEY_LEN],
    data: &[u8],
    tag: &[u8; KEY_LEN],
) -> Result<(), CryptoError> {
    let mut authenticator = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts every fixed 32-byte key");
    authenticator.update(data);
    authenticator
        .verify_slice(tag)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Compare already-computed full HMAC tags using RustCrypto's constant-time Eq.
/// Keeps a save draft free of plaintext after preparation has returned.
pub(crate) fn tags_match(left: &[u8; KEY_LEN], right: &[u8; KEY_LEN]) -> bool {
    use hmac::digest::CtOutput;
    CtOutput::<Hmac<Sha256>>::new((*left).into()) == CtOutput::<Hmac<Sha256>>::new((*right).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_reject_wrong_key_context_and_modification() {
        let key = [7u8; KEY_LEN];
        let envelope = seal(&key, b"vault-A/record-A/version-1", b"secret").unwrap();
        assert_eq!(
            open(&key, b"vault-A/record-A/version-1", &envelope)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert!(open(&[8u8; KEY_LEN], b"vault-A/record-A/version-1", &envelope).is_err());
        assert!(open(&key, b"vault-A/record-B/version-1", &envelope).is_err());
        let mut altered = envelope;
        *altered.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"vault-A/record-A/version-1", &altered).is_err());
    }

    #[test]
    fn empty_plaintext_requires_a_complete_authenticated_envelope() {
        let key = [7u8; KEY_LEN];
        let envelope = seal(&key, b"context", b"").unwrap();
        assert_eq!(envelope.len(), NONCE_LEN + TAG_LEN);
        assert!(open(&key, b"context", &envelope).unwrap().is_empty());
        for length in 0..NONCE_LEN + TAG_LEN {
            assert_eq!(
                open(&key, b"context", &envelope[..length]).unwrap_err(),
                CryptoError::InvalidEnvelope
            );
        }
    }

    #[test]
    fn key_derivation_binds_vault_and_purpose() {
        let root = [9u8; KEY_LEN];
        let first = derive(&root, &[1u8; 16], b"index").unwrap();
        assert_eq!(*first, *derive(&root, &[1u8; 16], b"index").unwrap());
        assert_ne!(*first, *derive(&root, &[1u8; 16], b"record-wrap").unwrap());
        assert_ne!(*first, *derive(&root, &[2u8; 16], b"index").unwrap());
    }

    #[test]
    fn kdf_rejects_unapproved_costs_before_allocation() {
        for costs in [
            (u32::MAX, PASSES, LANES),
            (MEMORY_KIB, u32::MAX, LANES),
            (MEMORY_KIB, PASSES, 0),
        ] {
            assert_eq!(
                password_key(b"password", &[0u8; SALT_LEN], costs.0, costs.1, costs.2).unwrap_err(),
                CryptoError::RejectedKdfParameters
            );
        }
    }

    #[test]
    fn unadmitted_upgrade_rejects_before_password_derivation() {
        let base = KdfProfile::baseline();
        let explicit_upgrade = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
        assert_eq!(
            password_key_with_policy(
                b"not-derived",
                &[0; SALT_LEN],
                explicit_upgrade,
                &KdfPolicy::baseline()
            )
            .unwrap_err(),
            CryptoError::RejectedKdfParameters
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case_one_and_rejects_changes() {
        // RFC 4231 case 1 uses a 20-byte key; zero extension to 32 bytes has the
        // same HMAC block padding, letting this vector exercise the fixed-key API.
        let mut key = [0u8; KEY_LEN];
        key[..20].fill(0x0b);
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac(&key, b"Hi There"), expected);
        assert!(tags_match(&mac(&key, b"Hi There"), &expected));
        assert!(!tags_match(&mac(&key, b"Hi there"), &expected));
        verify_mac(&key, b"Hi There", &expected).unwrap();
        assert!(verify_mac(&key, b"Hi there", &expected).is_err());
    }
}
