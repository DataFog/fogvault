//! Exact experimental byte contracts. These IDs are not a production protocol.

#[cfg(any(test, feature = "experimental-codecs"))]
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::{
    crypto,
    kdf::{KdfPolicy, KdfProfile},
    Error, Limits, RecordId, Result,
};
mod access;
pub(crate) use access::{AccessDescriptor, PendingDevice, PendingUnlock};
#[cfg(any(test, feature = "experimental-codecs"))]
mod rotation;
#[cfg(any(test, feature = "experimental-codecs"))]
#[allow(unused_imports)]
pub use rotation::rotate_record;

pub const DESCRIPTOR_LEN: usize = 130;
pub const DESCRIPTOR_PREFIX_LEN: usize = 58;
#[cfg(any(test, feature = "experimental-codecs"))]
pub const HEAD_BASE_LEN: usize = 96;
#[cfg(any(test, feature = "experimental-codecs"))]
pub const ENTRY_LEN: usize = 56;
pub const INDEX_HEAD_LEN: usize = 129;
const DESCRIPTOR_MAGIC: &[u8; 8] = b"FGVP0001";
const INDEX_DESCRIPTOR_MAGIC: &[u8; 8] = b"FGVP0002";
const RECORD_MAGIC: &[u8; 8] = b"FGVR0001";
const INDEX_RECORD_MAGIC: &[u8; 8] = b"FGVR0002";
const EPOCH_RECORD_MAGIC: &[u8; 8] = b"FGVR0003";
const FORMAT_ID: u16 = 1;
const INDEX_FORMAT_ID: u16 = 2;
pub(crate) const EPOCH_FORMAT_ID: u16 = 3;
const SUITE_ID: u16 = 1;
const KDF_ID: u16 = 1;

/// Descriptor-independent admission for the maintained content-three overhead.
/// The 176-byte frame is eight bytes wider than legacy content one/two.
pub(crate) fn current_envelope_limit(limits: Limits) -> Result<usize> {
    limits.current_envelope_bytes()
}

pub(crate) fn current_portable_admission() -> crate::AccessAdmission {
    // Exact credential frame: fixed P3 fields 108 + password wrapper 72.
    crate::AccessAdmission {
        allowed_profiles: vec![crate::AccessProfile::Portable],
        providers: vec![],
        max_descriptor_bytes: 180,
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    }
}

pub fn frame(label: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + label.len());
    bytes.extend_from_slice(&(label.len() as u64).to_be_bytes());
    bytes.extend_from_slice(label);
    bytes
}

#[derive(Clone, Debug)]
pub struct Descriptor {
    bytes: Vec<u8>,
    pub vault_id: [u8; 16],
    salt: [u8; 16],
    profile: KdfProfile,
    access: Option<AccessDescriptor>,
}

impl Descriptor {
    /// Explicit diagnostic parser for synthetic current-format codec fixtures.
    /// Ordinary consumers use the Engine and never obtain an unwrapped root.
    #[cfg(feature = "experimental-codecs")]
    pub fn diagnostic_parse_current_portable_with_policy(
        bytes: &[u8],
        policy: &KdfPolicy,
    ) -> Result<Self> {
        Self::parse_epoch_access(bytes, &current_portable_admission(), policy)
    }
    #[cfg(any(test, feature = "experimental-codecs"))]
    pub fn create(password: &[u8]) -> Result<(Self, Zeroizing<[u8; 32]>)> {
        Self::create_with_policy(password, &KdfPolicy::baseline())
    }
    pub fn create_with_policy(
        password: &[u8],
        policy: &KdfPolicy,
    ) -> Result<(Self, Zeroizing<[u8; 32]>)> {
        policy.admit(KdfProfile::baseline())?;
        let vault_id = crypto::random()?;
        let salt = crypto::random()?;
        let root = Zeroizing::new(crypto::random::<32>()?);
        let mut bytes = Vec::with_capacity(DESCRIPTOR_LEN);
        bytes.extend_from_slice(INDEX_DESCRIPTOR_MAGIC);
        for id in [INDEX_FORMAT_ID, SUITE_ID, KDF_ID] {
            bytes.extend_from_slice(&id.to_be_bytes());
        }
        for parameter in [crypto::MEMORY_KIB, crypto::PASSES, crypto::LANES] {
            bytes.extend_from_slice(&parameter.to_be_bytes());
        }
        bytes.extend_from_slice(&vault_id);
        bytes.extend_from_slice(&salt);
        let wrapping_key =
            crypto::password_key_with_policy(password, &salt, KdfProfile::baseline(), policy)?;
        let mut aad = frame(b"fogvault/prototype/root-wrap/v1");
        aad.extend_from_slice(&bytes);
        bytes.extend_from_slice(&crypto::seal(&wrapping_key, &aad, root.as_ref())?);
        Ok((
            Self {
                bytes,
                vault_id,
                salt,
                profile: KdfProfile::baseline(),
                access: None,
            },
            root,
        ))
    }

    #[cfg(any(test, feature = "experimental-codecs"))]
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_with_policy(bytes, &KdfPolicy::baseline())
    }

    pub fn parse_with_policy(bytes: &[u8], policy: &KdfPolicy) -> Result<Self> {
        if bytes.len() != DESCRIPTOR_LEN {
            return Err(Error::Malformed("descriptor length or magic"));
        }
        let mut reader = Reader::new(&bytes[8..]);
        let format = reader.u16()?;
        if !((&bytes[..8] == DESCRIPTOR_MAGIC && format == FORMAT_ID)
            || (&bytes[..8] == INDEX_DESCRIPTOR_MAGIC && format == INDEX_FORMAT_ID))
            || reader.u16()? != SUITE_ID
            || reader.u16()? != KDF_ID
        {
            return Err(Error::Malformed("unsupported version or profile"));
        }
        let memory = reader.u32()?;
        let passes = reader.u32()?;
        let lanes = reader.u32()?;
        if lanes != crypto::LANES {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        let profile = KdfProfile::argon2id(memory, passes)?;
        policy.admit(profile)?;
        let vault_id = reader.array()?;
        let salt = reader.array()?;
        Ok(Self {
            bytes: bytes.to_vec(),
            vault_id,
            salt,
            profile,
            access: None,
        })
    }

    pub fn kdf_profile(&self) -> KdfProfile {
        self.profile
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn format_id(&self) -> u16 {
        // Credential policy evolves separately from immutable content context.
        if let Some(access) = &self.access {
            access.content_format
        } else {
            self.credential_format_id()
        }
    }

    pub(crate) fn root_epoch(&self) -> u64 {
        self.access.as_ref().map_or(0, |access| access.root_epoch)
    }
    pub(crate) fn envelope_minimum(&self) -> usize {
        if self.format_id() == EPOCH_FORMAT_ID {
            176
        } else {
            168
        }
    }
    pub(crate) fn envelope_limit(&self, limits: Limits) -> Result<usize> {
        limits
            .diagnostic_legacy_envelope_bytes()?
            .checked_add(self.envelope_minimum() - 168)
            .ok_or(Error::ResourceLimit)
    }
    pub fn credential_format_id(&self) -> u16 {
        u16::from_be_bytes([self.bytes[8], self.bytes[9]])
    }

    pub fn hash(&self) -> [u8; 32] {
        crypto::digest(&self.bytes)
    }

    pub fn context_hash(&self) -> [u8; 32] {
        let mut bytes = frame(b"fogvault/prototype/context/v1");
        bytes.extend_from_slice(&self.format_id().to_be_bytes());
        bytes.extend_from_slice(&SUITE_ID.to_be_bytes());
        bytes.extend_from_slice(&self.vault_id);
        crypto::digest(&bytes)
    }

    #[cfg(any(test, feature = "experimental-codecs"))]
    pub fn unlock(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        self.unlock_with_policy(password, &KdfPolicy::baseline())
    }

    pub fn unlock_with_policy(
        &self,
        password: &[u8],
        policy: &KdfPolicy,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(access) = &self.access {
            return access.unlock_password(password, policy);
        }
        let wrapping_key =
            crypto::password_key_with_policy(password, &self.salt, self.profile, policy)?;
        let mut aad = frame(b"fogvault/prototype/root-wrap/v1");
        aad.extend_from_slice(&self.bytes[..DESCRIPTOR_PREFIX_LEN]);
        let plaintext = crypto::open(&wrapping_key, &aad, &self.bytes[DESCRIPTOR_PREFIX_LEN..])?;
        let mut root = Zeroizing::new([0u8; 32]);
        if plaintext.len() != 32 {
            return Err(Error::Malformed("root length"));
        }
        root.copy_from_slice(&plaintext);
        Ok(root)
    }

    /// Protect the same caller-authenticated root with a fresh salt and nonce.
    /// Content context stays stable; a commit head must be re-authenticated for
    /// the new descriptor hash. Policy and downgrade checks precede KDF work.
    pub fn rewrap(
        &self,
        root: &[u8; 32],
        new_password: &[u8],
        target: KdfProfile,
        policy: &KdfPolicy,
    ) -> Result<Self> {
        if let Some(access) = &self.access {
            return access
                .rewrap_password(root, None, new_password, target, policy)
                .map(|value| value.descriptor());
        }
        policy.admit(target)?;
        if target.memory_kib() < self.profile.memory_kib()
            || target.passes() < self.profile.passes()
        {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        let salt = crypto::random()?;
        let mut bytes = Vec::with_capacity(DESCRIPTOR_LEN);
        bytes.extend_from_slice(&self.bytes[..14]);
        for parameter in [target.memory_kib(), target.passes(), target.lanes()] {
            bytes.extend_from_slice(&parameter.to_be_bytes());
        }
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&salt);
        let wrapping_key = crypto::password_key_with_policy(new_password, &salt, target, policy)?;
        let mut aad = frame(b"fogvault/prototype/root-wrap/v1");
        aad.extend_from_slice(&bytes);
        bytes.extend_from_slice(&crypto::seal(&wrapping_key, &aad, root)?);
        Ok(Self {
            bytes,
            vault_id: self.vault_id,
            salt,
            profile: target,
            access: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub revision: u64,
    pub digest: [u8; 32],
}

#[cfg(any(test, feature = "experimental-codecs"))]
#[derive(Clone, Debug)]
pub struct Head {
    pub generation: u64,
    pub request_id: [u8; 16],
    pub operation_digest: [u8; 32],
    pub entries: BTreeMap<RecordId, Entry>,
}

#[cfg(any(test, feature = "experimental-codecs"))]
impl Head {
    fn prefix(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.operation_digest);
        bytes.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for (id, entry) in &self.entries {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&entry.revision.to_be_bytes());
            bytes.extend_from_slice(&entry.digest);
        }
        bytes
    }

    fn mac_input(descriptor: &Descriptor, prefix: &[u8]) -> Vec<u8> {
        let mut bytes = frame(b"fogvault/prototype/head/v1");
        bytes.extend_from_slice(&descriptor.hash());
        bytes.extend_from_slice(prefix);
        bytes
    }

    pub fn encode(&self, descriptor: &Descriptor, key: &[u8; 32]) -> Vec<u8> {
        let mut bytes = self.prefix();
        let tag = crypto::mac(key, &Self::mac_input(descriptor, &bytes));
        bytes.extend_from_slice(&tag);
        bytes
    }

    pub fn parse(
        bytes: &[u8],
        descriptor: &Descriptor,
        key: &[u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        let max_bytes = limits
            .max_records
            .checked_mul(ENTRY_LEN)
            .and_then(|n| n.checked_add(HEAD_BASE_LEN))
            .ok_or(Error::ResourceLimit)?;
        if bytes.len() < HEAD_BASE_LEN || bytes.len() > max_bytes {
            return Err(Error::ResourceLimit);
        }
        let (prefix, tag) = bytes.split_at(bytes.len() - 32);
        crypto::verify_mac(
            key,
            &Self::mac_input(descriptor, prefix),
            tag.try_into().map_err(|_| Error::Malformed("head tag"))?,
        )?;
        let mut reader = Reader::new(prefix);
        let generation = reader.u64()?;
        let request_id = reader.array()?;
        let operation_digest = reader.array()?;
        let count = usize::try_from(reader.u64()?).map_err(|_| Error::ResourceLimit)?;
        if count > limits.max_records
            || count
                .checked_mul(ENTRY_LEN)
                .and_then(|n| n.checked_add(HEAD_BASE_LEN))
                != Some(bytes.len())
        {
            return Err(Error::Malformed("head entry count"));
        }
        let mut entries = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let id: RecordId = reader.array()?;
            if previous.is_some_and(|prior| prior >= id) {
                return Err(Error::Malformed("noncanonical or duplicate record ID"));
            }
            let revision = reader.u64()?;
            if revision == 0 || revision > i64::MAX as u64 {
                return Err(Error::Malformed("record revision"));
            }
            entries.insert(
                id,
                Entry {
                    revision,
                    digest: reader.array()?,
                },
            );
            previous = Some(id);
        }
        reader.finish()?;
        Ok(Self {
            generation,
            request_id,
            operation_digest,
            entries,
        })
    }
}

/// Constant-size v2 head. Its MAC authenticates the index root; node hashes alone
/// do not authenticate a root, and this head supplies no external replay anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexHead {
    pub generation: u64,
    pub request_id: [u8; 16],
    pub operation_digest: [u8; 32],
    pub count: u64,
    pub root: Option<crate::index::NodeHash>,
}

impl IndexHead {
    fn prefix(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INDEX_HEAD_LEN);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.operation_digest);
        bytes.extend_from_slice(&self.count.to_be_bytes());
        bytes.push(u8::from(self.root.is_some()));
        bytes.extend_from_slice(&self.root.unwrap_or([0; 32]));
        bytes
    }

    fn mac_input(descriptor: &Descriptor, prefix: &[u8]) -> Vec<u8> {
        let mut bytes = frame(b"fogvault/prototype/index-head/v2");
        bytes.extend_from_slice(&descriptor.hash());
        bytes.extend_from_slice(prefix);
        bytes
    }

    pub fn encode(&self, descriptor: &Descriptor, key: &[u8; 32]) -> Vec<u8> {
        let mut bytes = self.prefix();
        let tag = crypto::mac(key, &Self::mac_input(descriptor, &bytes));
        bytes.extend_from_slice(&tag);
        bytes
    }

    pub fn parse(
        bytes: &[u8],
        descriptor: &Descriptor,
        key: &[u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        if !matches!(descriptor.format_id(), INDEX_FORMAT_ID | EPOCH_FORMAT_ID)
            || bytes.len() != INDEX_HEAD_LEN
        {
            return Err(Error::Malformed("index head version or length"));
        }
        let (prefix, tag) = bytes.split_at(INDEX_HEAD_LEN - 32);
        crypto::verify_mac(
            key,
            &Self::mac_input(descriptor, prefix),
            tag.try_into()
                .map_err(|_| Error::Malformed("index head tag"))?,
        )?;
        let mut reader = Reader::new(prefix);
        let generation = reader.u64()?;
        let request_id = reader.array()?;
        let operation_digest = reader.array()?;
        let count = reader.u64()?;
        if usize::try_from(count).map_err(|_| Error::ResourceLimit)? > limits.max_records {
            return Err(Error::ResourceLimit);
        }
        let present = reader.u8()?;
        let hash = reader.array()?;
        let root = match present {
            0 if count == 0 && hash == [0; 32] => None,
            1 if count > 0 && generation > 0 => Some(hash),
            _ => return Err(Error::Malformed("noncanonical index root")),
        };
        reader.finish()?;
        Ok(Self {
            generation,
            request_id,
            operation_digest,
            count,
            root,
        })
    }
}

fn record_magic(descriptor: &Descriptor) -> &'static [u8; 8] {
    match descriptor.format_id() {
        EPOCH_FORMAT_ID => EPOCH_RECORD_MAGIC,
        INDEX_FORMAT_ID => INDEX_RECORD_MAGIC,
        _ => RECORD_MAGIC,
    }
}

fn record_aad(descriptor: &Descriptor, id: &RecordId, revision: u64, purpose: &[u8]) -> Vec<u8> {
    let mut bytes = frame(purpose);
    bytes.extend_from_slice(&descriptor.context_hash());
    bytes.extend_from_slice(&descriptor.vault_id);
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(&revision.to_be_bytes());
    // Wrapping epoch is mutable during wrapping-only rotation. It belongs to
    // the wrap context; the immutable body context remains unchanged.
    if descriptor.format_id() == EPOCH_FORMAT_ID && purpose == b"fogvault/prototype/record-wrap/v1"
    {
        bytes.extend_from_slice(&descriptor.root_epoch().to_be_bytes());
    }
    bytes
}

pub fn encrypt_record(
    descriptor: &Descriptor,
    wrapping_key: &[u8; 32],
    id: &RecordId,
    revision: u64,
    metadata: &[u8],
    payload: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    if revision == 0 || revision > i64::MAX as u64 {
        return Err(Error::Malformed("record revision"));
    }
    limits.validate_record(metadata, payload)?;
    let length = metadata
        .len()
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::ResourceLimit)?;
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(length)
        .map_err(|_| Error::ResourceLimit)?;
    body.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    body.extend_from_slice(metadata);
    body.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    body.extend_from_slice(payload);
    let data_key = Zeroizing::new(crypto::random::<32>()?);
    let wrapped_key = crypto::seal(
        wrapping_key,
        &record_aad(
            descriptor,
            id,
            revision,
            b"fogvault/prototype/record-wrap/v1",
        ),
        data_key.as_ref(),
    )?;
    let ciphertext = crypto::seal(
        &data_key,
        &record_aad(
            descriptor,
            id,
            revision,
            b"fogvault/prototype/record-body/v1",
        ),
        &body,
    )?;
    let mut envelope = Vec::new();
    envelope.extend_from_slice(record_magic(descriptor));
    envelope.extend_from_slice(id);
    envelope.extend_from_slice(&revision.to_be_bytes());
    if descriptor.format_id() == EPOCH_FORMAT_ID {
        envelope.extend_from_slice(&descriptor.root_epoch().to_be_bytes());
    }
    envelope.extend_from_slice(&wrapped_key);
    envelope.extend_from_slice(&(ciphertext.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub struct DecodedRecord {
    pub metadata: Zeroizing<Vec<u8>>,
    pub payload: Zeroizing<Vec<u8>>,
}

pub fn decrypt_record(
    descriptor: &Descriptor,
    wrapping_key: &[u8; 32],
    id: &RecordId,
    revision: u64,
    envelope: &[u8],
    limits: Limits,
) -> Result<DecodedRecord> {
    if revision == 0 || revision > i64::MAX as u64 {
        return Err(Error::Malformed("record revision"));
    }
    if envelope.len() > descriptor.envelope_limit(limits)? {
        return Err(Error::ResourceLimit);
    }
    let mut reader = Reader::new(envelope);
    if reader.take(8)? != record_magic(descriptor)
        || reader.array::<16>()? != *id
        || reader.u64()? != revision
    {
        return Err(Error::Integrity);
    }
    if descriptor.format_id() == EPOCH_FORMAT_ID && reader.u64()? != descriptor.root_epoch() {
        return Err(Error::Integrity);
    }
    let wrapped_key = reader.take(72)?;
    let length = usize::try_from(reader.u64()?).map_err(|_| Error::ResourceLimit)?;
    let ciphertext = reader.take(length)?;
    reader.finish()?;
    let key_bytes = crypto::open(
        wrapping_key,
        &record_aad(
            descriptor,
            id,
            revision,
            b"fogvault/prototype/record-wrap/v1",
        ),
        wrapped_key,
    )?;
    let key: &[u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("content key"))?;
    let plaintext = crypto::open(
        key,
        &record_aad(
            descriptor,
            id,
            revision,
            b"fogvault/prototype/record-body/v1",
        ),
        ciphertext,
    )?;
    let mut reader = Reader::new(&plaintext);
    let metadata_length = usize::try_from(reader.u64()?).map_err(|_| Error::ResourceLimit)?;
    if metadata_length > limits.max_metadata_bytes {
        return Err(Error::ResourceLimit);
    }
    let metadata = reader.take(metadata_length)?;
    let payload_length = usize::try_from(reader.u64()?).map_err(|_| Error::ResourceLimit)?;
    if payload_length > limits.max_payload_bytes {
        return Err(Error::ResourceLimit);
    }
    let payload = reader.take(payload_length)?;
    reader.finish()?;
    Ok(DecodedRecord {
        metadata: Zeroizing::new(metadata.to_vec()),
        payload: Zeroizing::new(payload.to_vec()),
    })
}

pub fn operation_input(
    id: &RecordId,
    expected_revision: Option<u64>,
    metadata: &[u8],
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let domain = frame(b"fogvault/prototype/save/v1");
    let length = domain
        .len()
        .checked_add(41)
        .and_then(|n| n.checked_add(metadata.len()))
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(Error::ResourceLimit)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::ResourceLimit)?;
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(id);
    bytes.push(u8::from(expected_revision.is_some()));
    bytes.extend_from_slice(&expected_revision.unwrap_or_default().to_be_bytes());
    bytes.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    bytes.extend_from_slice(metadata);
    bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.cursor.checked_add(count).ok_or(Error::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(Error::Malformed("truncated field"))?;
        self.cursor = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Malformed("fixed-width field"))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn finish(&self) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(Error::Malformed("trailing input"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: [u8; 16]) -> Descriptor {
        // Component-test fixture: a structurally valid descriptor, not an unlocked root.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DESCRIPTOR_MAGIC);
        for value in [FORMAT_ID, SUITE_ID, KDF_ID] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [crypto::MEMORY_KIB, crypto::PASSES, crypto::LANES] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0; 16]);
        bytes.resize(DESCRIPTOR_LEN, 0);
        Descriptor::parse(&bytes).unwrap()
    }

    fn index_descriptor(id: [u8; 16]) -> Descriptor {
        let mut bytes = descriptor(id).bytes;
        bytes[..8].copy_from_slice(INDEX_DESCRIPTOR_MAGIC);
        bytes[8..10].copy_from_slice(&INDEX_FORMAT_ID.to_be_bytes());
        Descriptor::parse(&bytes).unwrap()
    }

    #[test]
    fn credential_rewrap_preserves_root_record_context_and_authenticated_header() {
        let (original, root) = Descriptor::create(b"old synthetic password").unwrap();
        let policy = KdfPolicy::baseline();
        let changed = original
            .rewrap(
                &root,
                b"new synthetic password",
                original.kdf_profile(),
                &policy,
            )
            .unwrap();
        assert_eq!(changed.bytes().len(), DESCRIPTOR_LEN);
        assert_eq!(&original.bytes()[..42], &changed.bytes()[..42]);
        assert_ne!(&original.bytes()[42..58], &changed.bytes()[42..58]);
        assert_ne!(&original.bytes()[58..82], &changed.bytes()[58..82]);
        assert_eq!(original.context_hash(), changed.context_hash());
        assert_ne!(original.hash(), changed.hash());
        assert_eq!(*changed.unlock(b"new synthetic password").unwrap(), *root);
        assert!(changed.unlock(b"old synthetic password").is_err());
        let limits = Limits {
            max_payload_bytes: 7,
            max_metadata_bytes: 4,
            max_records: 1,
        };
        let wrapping = crypto::derive(&root, &original.vault_id, b"record-key-wrapping").unwrap();
        let envelope = encrypt_record(
            &original, &wrapping, &[4; 16], 1, b"meta", b"payload", limits,
        )
        .unwrap();
        assert_eq!(
            decrypt_record(&changed, &wrapping, &[4; 16], 1, &envelope, limits)
                .unwrap()
                .payload
                .as_slice(),
            b"payload"
        );
        let head_key = crypto::derive(&root, &original.vault_id, b"head-authentication").unwrap();
        let head = IndexHead {
            generation: 0,
            request_id: [7; 16],
            operation_digest: [0; 32],
            count: 0,
            root: None,
        };
        let prior_head = head.encode(&original, &head_key);
        assert!(IndexHead::parse(&prior_head, &changed, &head_key, limits).is_err());
        let changed_head = head.encode(&changed, &head_key);
        assert!(IndexHead::parse(&changed_head, &changed, &head_key, limits).is_ok());
        assert!(IndexHead::parse(&changed_head, &original, &head_key, limits).is_err());
    }

    #[test]
    fn upgraded_descriptors_require_explicit_policy_and_bind_kdf_costs() {
        let (original, root) = Descriptor::create(b"synthetic password").unwrap();
        let base = KdfProfile::baseline();
        // The smallest strict pass-count increase is an experiment input, not
        // a newly selected production default or universal device allowance.
        let target = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
        let policy = KdfPolicy::new(vec![base, target]).unwrap();
        let upgraded = original
            .rewrap(&root, b"synthetic password", target, &policy)
            .unwrap();
        assert!(Descriptor::parse(upgraded.bytes()).is_err());
        assert!(upgraded.unlock(b"synthetic password").is_err());
        let parsed = Descriptor::parse_with_policy(upgraded.bytes(), &policy).unwrap();
        assert_eq!(parsed.kdf_profile(), target);
        assert_eq!(parsed.context_hash(), original.context_hash());
        assert_eq!(
            *parsed
                .unlock_with_policy(b"synthetic password", &policy)
                .unwrap(),
            *root
        );
        assert!(parsed
            .rewrap(&root, b"weaker request", base, &policy)
            .is_err());
        // A permitted different header cost cannot authenticate the wrapped
        // root: costs are in the root envelope's authenticated context.
        let mut changed_cost = upgraded.bytes().to_vec();
        changed_cost[18..22].copy_from_slice(&base.passes().to_be_bytes());
        let altered = Descriptor::parse_with_policy(&changed_cost, &policy).unwrap();
        assert!(altered
            .unlock_with_policy(b"synthetic password", &policy)
            .is_err());
        changed_cost[18..22].copy_from_slice(&(target.passes() + 1).to_be_bytes());
        assert!(Descriptor::parse_with_policy(&changed_cost, &policy).is_err());
        changed_cost = upgraded.bytes().to_vec();
        changed_cost[22..26].copy_from_slice(&2u32.to_be_bytes());
        assert!(Descriptor::parse_with_policy(&changed_cost, &policy).is_err());
    }

    #[test]
    fn descriptor_and_record_versions_are_explicit_and_context_bound() {
        let old = descriptor([3; 16]);
        let new = index_descriptor([3; 16]);
        assert_eq!(old.format_id(), 1);
        assert_eq!(new.format_id(), 2);
        assert_ne!(old.context_hash(), new.context_hash());
        let mut inconsistent = new.bytes().to_vec();
        inconsistent[..8].copy_from_slice(DESCRIPTOR_MAGIC);
        assert!(Descriptor::parse(&inconsistent).is_err());
        inconsistent = old.bytes().to_vec();
        inconsistent[..8].copy_from_slice(INDEX_DESCRIPTOR_MAGIC);
        assert!(Descriptor::parse(&inconsistent).is_err());
        let limits = Limits {
            max_payload_bytes: 1,
            max_metadata_bytes: 0,
            max_records: 1,
        };
        let envelope = encrypt_record(&new, &[9; 32], &[4; 16], 1, b"", b"x", limits).unwrap();
        for invalid in [0, i64::MAX as u64 + 1, u64::MAX] {
            assert!(encrypt_record(&new, &[9; 32], &[4; 16], invalid, b"", b"x", limits).is_err());
            assert!(decrypt_record(&new, &[9; 32], &[4; 16], invalid, &envelope, limits).is_err());
        }
        assert_eq!(&envelope[..8], INDEX_RECORD_MAGIC);
        assert_eq!(
            decrypt_record(&new, &[9; 32], &[4; 16], 1, &envelope, limits)
                .unwrap()
                .payload
                .as_slice(),
            b"x"
        );
        assert!(decrypt_record(&old, &[9; 32], &[4; 16], 1, &envelope, limits).is_err());
        let mut wrong_magic = envelope;
        wrong_magic[..8].copy_from_slice(RECORD_MAGIC);
        assert!(decrypt_record(&new, &[9; 32], &[4; 16], 1, &wrong_magic, limits).is_err());
    }

    #[test]
    fn index_head_has_constant_exact_length_and_canonical_authenticated_fields() {
        let descriptor = index_descriptor([3; 16]);
        let key = [9; 32];
        let limits = Limits {
            max_payload_bytes: 0,
            max_metadata_bytes: 0,
            max_records: 1,
        };
        let empty = IndexHead {
            generation: 0,
            request_id: [0; 16],
            operation_digest: [0; 32],
            count: 0,
            root: None,
        };
        let head = IndexHead {
            generation: 1,
            request_id: [1; 16],
            operation_digest: [2; 32],
            count: 1,
            root: Some([7; 32]),
        };
        for value in [empty, head.clone()] {
            let bytes = value.encode(&descriptor, &key);
            assert_eq!(bytes.len(), INDEX_HEAD_LEN);
            assert_eq!(
                IndexHead::parse(&bytes, &descriptor, &key, limits).unwrap(),
                value
            );
        }
        let valid = head.encode(&descriptor, &key);
        for length in 0..INDEX_HEAD_LEN {
            assert!(IndexHead::parse(&valid[..length], &descriptor, &key, limits).is_err());
        }
        let mut extended = valid.clone();
        extended.push(0);
        assert!(IndexHead::parse(&extended, &descriptor, &key, limits).is_err());
        assert!(
            IndexHead::parse(&valid, &super::tests::descriptor([3; 16]), &key, limits).is_err()
        );
        let mut bad_tag = valid;
        bad_tag[128] ^= 1;
        assert!(IndexHead::parse(&bad_tag, &descriptor, &key, limits).is_err());
        // Even a correctly authenticated head must satisfy the typed root/count contract.
        for (offset, replacement) in [
            (0, 0u64.to_be_bytes().to_vec()),
            (56, 0u64.to_be_bytes().to_vec()),
            (56, 2u64.to_be_bytes().to_vec()),
            (64, vec![0]),
            (64, vec![2]),
        ] {
            let mut prefix = head.prefix();
            prefix[offset..offset + replacement.len()].copy_from_slice(&replacement);
            let tag = crypto::mac(&key, &IndexHead::mac_input(&descriptor, &prefix));
            prefix.extend_from_slice(&tag);
            assert!(IndexHead::parse(&prefix, &descriptor, &key, limits).is_err());
        }
    }

    #[test]
    fn descriptor_has_exact_bytes_and_rejects_every_truncated_or_extended_form() {
        let value = descriptor([3; 16]);
        assert_eq!(value.bytes().len(), 130);
        assert_eq!(&value.bytes()[8..14], &[0, 1, 0, 1, 0, 1]);
        assert_eq!(&value.bytes()[14..18], &65_536u32.to_be_bytes());
        assert_eq!(&value.bytes()[26..42], &[3; 16]);
        for length in 0..DESCRIPTOR_LEN {
            assert!(Descriptor::parse(&value.bytes()[..length]).is_err());
        }
        let mut extended = value.bytes().to_vec();
        extended.push(0);
        assert!(Descriptor::parse(&extended).is_err());
        // Changing a mutable credential salt does not change the content context.
        extended.truncate(DESCRIPTOR_LEN);
        extended[42] ^= 1;
        let alternate = Descriptor::parse(&extended).unwrap();
        assert_eq!(value.context_hash(), alternate.context_hash());
        assert_ne!(value.hash(), alternate.hash());
    }

    #[test]
    fn record_format_consumes_all_bytes_and_authenticates_identity_and_revision() {
        let descriptor = descriptor([3; 16]);
        let limits = Limits {
            max_payload_bytes: 7,
            max_metadata_bytes: 4,
            max_records: 1,
        };
        let envelope = encrypt_record(
            &descriptor,
            &[9; 32],
            &[4; 16],
            1,
            b"meta",
            b"payload",
            limits,
        )
        .unwrap();
        assert_eq!(envelope.len(), 168 + 4 + 7);
        assert_eq!(
            decrypt_record(&descriptor, &[9; 32], &[4; 16], 1, &envelope, limits)
                .unwrap()
                .payload
                .as_slice(),
            b"payload"
        );
        let next = encrypt_record(
            &descriptor,
            &[9; 32],
            &[4; 16],
            2,
            b"meta",
            b"payload",
            limits,
        )
        .unwrap();
        let first_key = crypto::open(
            &[9; 32],
            &record_aad(
                &descriptor,
                &[4; 16],
                1,
                b"fogvault/prototype/record-wrap/v1",
            ),
            &envelope[32..104],
        )
        .unwrap();
        let next_key = crypto::open(
            &[9; 32],
            &record_aad(
                &descriptor,
                &[4; 16],
                2,
                b"fogvault/prototype/record-wrap/v1",
            ),
            &next[32..104],
        )
        .unwrap();
        assert_ne!(first_key.as_slice(), next_key.as_slice());
        for length in 0..envelope.len() {
            assert!(decrypt_record(
                &descriptor,
                &[9; 32],
                &[4; 16],
                1,
                &envelope[..length],
                limits
            )
            .is_err());
        }
        assert!(decrypt_record(&descriptor, &[9; 32], &[5; 16], 1, &envelope, limits).is_err());
        assert!(decrypt_record(&descriptor, &[9; 32], &[4; 16], 2, &envelope, limits).is_err());
        let mut altered = envelope.clone();
        altered[8..24].copy_from_slice(&[5; 16]);
        assert!(decrypt_record(&descriptor, &[9; 32], &[5; 16], 1, &altered, limits).is_err());
        let mut changed_vault_bytes = descriptor.bytes().to_vec();
        changed_vault_bytes[26] ^= 1;
        let other = Descriptor::parse(&changed_vault_bytes).unwrap();
        assert!(decrypt_record(&other, &[9; 32], &[4; 16], 1, &envelope, limits).is_err());
        let mut extended = envelope;
        extended.push(0);
        assert!(decrypt_record(
            &descriptor,
            &[9; 32],
            &[4; 16],
            1,
            &extended,
            Limits {
                max_payload_bytes: 8,
                ..limits
            }
        )
        .is_err());
    }

    #[test]
    fn authenticated_head_still_rejects_duplicate_order_and_typed_count_errors() {
        let descriptor = descriptor([3; 16]);
        let key = [9; 32];
        let limits = Limits {
            max_payload_bytes: 0,
            max_metadata_bytes: 0,
            max_records: 2,
        };
        let head = Head {
            generation: 1,
            request_id: [1; 16],
            operation_digest: [2; 32],
            entries: BTreeMap::from([(
                [4; 16],
                Entry {
                    revision: 1,
                    digest: [7; 32],
                },
            )]),
        };
        let bytes = head.encode(&descriptor, &key);
        assert_eq!(bytes.len(), 152);
        assert_eq!(
            Head::parse(&bytes, &descriptor, &key, limits)
                .unwrap()
                .entries,
            head.entries
        );
        let mut prefix = head.prefix();
        prefix[56..64].copy_from_slice(&2u64.to_be_bytes());
        let duplicate = prefix[64..120].to_vec();
        prefix.extend_from_slice(&duplicate);
        let tag = crypto::mac(&key, &Head::mac_input(&descriptor, &prefix));
        prefix.extend_from_slice(&tag);
        assert!(matches!(
            Head::parse(&prefix, &descriptor, &key, limits),
            Err(Error::Malformed("noncanonical or duplicate record ID"))
        ));
        let mut wrong_count = head.prefix();
        wrong_count[56..64].copy_from_slice(&u64::MAX.to_be_bytes());
        let tag = crypto::mac(&key, &Head::mac_input(&descriptor, &wrong_count));
        wrong_count.extend_from_slice(&tag);
        assert!(Head::parse(&wrong_count, &descriptor, &key, limits).is_err());
        let mut altered = bytes;
        altered[0] ^= 1;
        assert!(Head::parse(&altered, &descriptor, &key, limits).is_err());
    }
}
