//! Candidate host control-state protocol. The store is a separately trusted
//! integrity/durability boundary, never data loaded from the vault itself.
//! This protocol does not turn an ordinary file into an anti-rollback service.
use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"FGVCTL01";
const OWNER_MAGIC: &[u8; 8] = b"FGVOWN01";
/// Exact version-one frame width; no untrusted length controls allocation.
pub const CONTROL_STATE_BYTES: usize = 275;
/// Fixed ordinary-operation owner frame: version8, vault16, registration16,
/// operation1, request16, source72 and target72. All integers are big endian.
pub const CONTROL_OWNER_BYTES: usize = 201;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotIdentity {
    pub descriptor_digest: [u8; 32],
    pub head_digest: [u8; 32],
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlOperation {
    Save = 1,
    Delete = 2,
    Credentials = 3,
    ProtectiveTransition = 4,
    Import = 5,
}
impl ControlOperation {
    fn parse(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Save),
            2 => Ok(Self::Delete),
            3 => Ok(Self::Credentials),
            4 => Ok(Self::ProtectiveTransition),
            5 => Ok(Self::Import),
            _ => Err(Error::Malformed("control operation")),
        }
    }
}

/// An exact ordinary target selected by the Engine, or decoded from retained
/// operation bytes. It contains no secrets and is not authority by itself.
/// The independently selected control store must retain and compare its owner
/// commitment before publication; decoding hostile bytes cannot enroll a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedControlOperation {
    vault_id: [u8; 16],
    registration_id: [u8; 16],
    operation: ControlOperation,
    request_id: [u8; 16],
    source: SnapshotIdentity,
    target: SnapshotIdentity,
}

impl PreparedControlOperation {
    pub(crate) fn new(
        vault_id: [u8; 16],
        registration_id: [u8; 16],
        operation: ControlOperation,
        request_id: [u8; 16],
        source: SnapshotIdentity,
        target: SnapshotIdentity,
    ) -> Result<Self> {
        if !matches!(
            operation,
            ControlOperation::Save | ControlOperation::Delete | ControlOperation::Credentials
        ) {
            return Err(Error::UnsupportedCapability);
        }
        if source.generation.checked_add(1) != Some(target.generation)
            || (operation != ControlOperation::Credentials
                && source.descriptor_digest != target.descriptor_digest)
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            vault_id,
            registration_id,
            operation,
            request_id,
            source,
            target,
        })
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }
    pub fn registration_id(&self) -> [u8; 16] {
        self.registration_id
    }
    pub fn operation(&self) -> ControlOperation {
        self.operation
    }
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
    pub fn source(&self) -> SnapshotIdentity {
        self.source
    }
    pub fn target(&self) -> SnapshotIdentity {
        self.target
    }

    /// Stable version-one owner bytes. Hashes are SHA-256 of these exact bytes;
    /// neither Rust layout nor display strings participate in the commitment.
    pub fn canonical_bytes(&self) -> [u8; CONTROL_OWNER_BYTES] {
        let mut bytes = [0u8; CONTROL_OWNER_BYTES];
        bytes[..8].copy_from_slice(OWNER_MAGIC);
        bytes[8..24].copy_from_slice(&self.vault_id);
        bytes[24..40].copy_from_slice(&self.registration_id);
        bytes[40] = self.operation as u8;
        bytes[41..57].copy_from_slice(&self.request_id);
        bytes[57..89].copy_from_slice(&self.source.descriptor_digest);
        bytes[89..121].copy_from_slice(&self.source.head_digest);
        bytes[121..129].copy_from_slice(&self.source.generation.to_be_bytes());
        bytes[129..161].copy_from_slice(&self.target.descriptor_digest);
        bytes[161..193].copy_from_slice(&self.target.head_digest);
        bytes[193..201].copy_from_slice(&self.target.generation.to_be_bytes());
        bytes
    }

    pub fn owner_commitment(&self) -> [u8; 32] {
        crate::crypto::digest(&self.canonical_bytes())
    }

    /// Decode retained public operation metadata. The caller must authenticate
    /// its encrypted target separately and match this commitment against the
    /// independently retained control intent. Parsing grants no authority.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTROL_OWNER_BYTES || &bytes[..8] != OWNER_MAGIC {
            return Err(Error::Malformed("control owner width/version"));
        }
        let mut reader = Reader { bytes, at: 8 };
        Self::new(
            reader.array()?,
            reader.array()?,
            ControlOperation::parse(reader.byte()?)?,
            reader.array()?,
            reader.snapshot()?,
            reader.snapshot()?,
        )
    }

    fn check_state(&self, state: &ControlState) -> Result<()> {
        if self.vault_id != state.vault_id
            || self.registration_id != state.registration_id
            || self.source != state.accepted
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlIntent {
    pub operation: ControlOperation,
    pub request_id: [u8; 16],
    pub target_descriptor_digest: [u8; 32],
    /// Commitment to the owner-prepared operation/source/target/mode. Its
    /// authority comes from this independently trusted store, not its hash.
    pub owner_commitment: [u8; 32],
    submission: Option<SnapshotIdentity>,
}
impl ControlIntent {
    pub fn submission(&self) -> Option<SnapshotIdentity> {
        self.submission
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlState {
    vault_id: [u8; 16],
    registration_id: [u8; 16],
    revision: u64,
    accepted: SnapshotIdentity,
    pending: Option<ControlIntent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlObservation {
    Accepted,
    StagingSource,
    /// Authenticated source observed after possible submission. This is not
    /// evidence that an earlier target commit never happened.
    StillUnknown {
        request_id: [u8; 16],
    },
    TargetObserved {
        request_id: [u8; 16],
    },
}

/// Implementations must be selected by trusted host registration. Capabilities
/// include atomic compare/exchange across clients and the stated durability.
/// A hostile vault adapter must never supply this interface implicitly.
/// Control CAS alone is not a live publication fence. Every writer using an
/// independent anchor must hold a shared per-registration coordinator from
/// revalidation of current control state through vault CAS and trusted outcome
/// completion. A cached submitted intent can otherwise match a replayed source
/// after a later independently accepted commit. Prepare factors/KDF outside
/// that scope; no untrusted callbacks run while publication is fenced.
pub trait TrustedControlStore {
    fn load(&mut self) -> Result<Option<ControlState>>;
    fn compare_exchange(
        &mut self,
        expected: Option<&ControlState>,
        replacement: &ControlState,
    ) -> Result<ControlWriteOutcome>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlWriteOutcome {
    Stored,
    Conflict,
    /// The owner must reload/reconcile this store; no vault submission is
    /// authorized by an uncertain intent persistence response.
    Unknown,
}

impl ControlState {
    /// Initial identity/anchor must come from explicit trusted registration and
    /// a completed authenticated snapshot, never automatic untrusted discovery.
    pub fn register(
        vault_id: [u8; 16],
        registration_id: [u8; 16],
        accepted: SnapshotIdentity,
    ) -> Self {
        Self {
            vault_id,
            registration_id,
            revision: 0,
            accepted,
            pending: None,
        }
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }
    pub fn registration_id(&self) -> [u8; 16] {
        self.registration_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn accepted(&self) -> SnapshotIdentity {
        self.accepted
    }
    pub fn pending(&self) -> Option<&ControlIntent> {
        self.pending.as_ref()
    }

    fn advanced(&self) -> Result<Self> {
        let mut next = self.clone();
        next.revision = next.revision.checked_add(1).ok_or(Error::ResourceLimit)?;
        Ok(next)
    }

    /// Persist this replacement through compare_exchange before staging that
    /// relies on the target commitment. It does not yet authorize submission.
    pub fn prepare(
        &self,
        operation: ControlOperation,
        request_id: [u8; 16],
        target_descriptor_digest: [u8; 32],
        owner_commitment: [u8; 32],
    ) -> Result<Self> {
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let mut next = self.advanced()?;
        next.pending = Some(ControlIntent {
            operation,
            request_id,
            target_descriptor_digest,
            owner_commitment,
            submission: None,
        });
        Ok(next)
    }

    /// Prepare an exact ordinary Engine operation. There is no caller-selected
    /// free-form commitment in this maintained ordinary-operation path.
    pub fn prepare_ordinary(&self, operation: &PreparedControlOperation) -> Result<Self> {
        operation.check_state(self)?;
        self.prepare(
            operation.operation,
            operation.request_id,
            operation.target.descriptor_digest,
            operation.owner_commitment(),
        )
    }

    /// Bind the same exact ordinary operation before any vault submission.
    /// Persist the returned replacement first; a returned value is not durable.
    pub fn authorize_ordinary_submission(
        &self,
        operation: &PreparedControlOperation,
    ) -> Result<Self> {
        self.validate_ordinary(operation)?;
        self.authorize_submission(operation.target)
    }

    /// Check retained ordinary metadata against this independently loaded
    /// Prepared or exact Submitted intent. This is not a live writer fence or
    /// authentication of the target's encrypted objects.
    pub fn validate_ordinary(&self, operation: &PreparedControlOperation) -> Result<()> {
        operation.check_state(self)?;
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if pending.operation != operation.operation
            || pending.request_id != operation.request_id
            || pending.target_descriptor_digest != operation.target.descriptor_digest
            || pending.owner_commitment != operation.owner_commitment()
            || pending
                .submission
                .is_some_and(|target| target != operation.target)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Persist the exact fully prepared target before the vault commit is
    /// submitted. The accepted snapshot remains the old source until confirmed.
    pub fn authorize_submission(&self, target: SnapshotIdentity) -> Result<Self> {
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if pending.submission.is_some()
            || target.descriptor_digest != pending.target_descriptor_digest
            || self.accepted.generation.checked_add(1) != Some(target.generation)
        {
            return Err(Error::Conflict);
        }
        let mut next = self.advanced()?;
        next.pending.as_mut().ok_or(Error::Conflict)?.submission = Some(target);
        Ok(next)
    }

    /// Only use an observation after the Engine has authenticated the paired
    /// descriptor/head and the required coherent inventory. Hash equality by
    /// itself does not establish authentication or durable sink completion.
    pub fn observe(&self, snapshot: SnapshotIdentity) -> Result<ControlObservation> {
        match &self.pending {
            None if snapshot == self.accepted => Ok(ControlObservation::Accepted),
            Some(pending) if pending.submission == Some(snapshot) => {
                Ok(ControlObservation::TargetObserved {
                    request_id: pending.request_id,
                })
            }
            Some(pending) if snapshot == self.accepted => Ok(if pending.submission.is_some() {
                ControlObservation::StillUnknown {
                    request_id: pending.request_id,
                }
            } else {
                ControlObservation::StagingSource
            }),
            _ => Err(Error::Conflict),
        }
    }

    /// Persist this completion before publishing normal target authority.
    pub fn confirm_target(&self, snapshot: SnapshotIdentity) -> Result<Self> {
        if !matches!(
            self.observe(snapshot)?,
            ControlObservation::TargetObserved { .. }
        ) {
            return Err(Error::Conflict);
        }
        let mut next = self.advanced()?;
        next.accepted = snapshot;
        next.pending = None;
        Ok(next)
    }

    /// Safe only before submission authorization. Once submission may have
    /// happened, source replay must never silently become a known abort.
    pub fn abandon_unsubmitted(&self) -> Result<Self> {
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if pending.submission.is_some() {
            return Err(Error::OutcomeUnknown {
                request_id: pending.request_id,
            });
        }
        let mut next = self.advanced()?;
        next.pending = None;
        Ok(next)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONTROL_STATE_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.registration_id);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        self.accepted.append(&mut bytes);
        bytes.push(u8::from(self.pending.is_some()));
        if let Some(pending) = &self.pending {
            bytes.push(pending.operation as u8);
            bytes.extend_from_slice(&pending.request_id);
            bytes.extend_from_slice(&pending.target_descriptor_digest);
            bytes.extend_from_slice(&pending.owner_commitment);
            bytes.push(u8::from(pending.submission.is_some()));
            if let Some(target) = pending.submission {
                target.append(&mut bytes);
            }
        }
        bytes.resize(CONTROL_STATE_BYTES, 0);
        bytes
    }

    /// Canonical bounded codec only. Callers may trust the result only when
    /// loaded from their independently admitted control store/owner receipt.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONTROL_STATE_BYTES || &bytes[..8] != MAGIC {
            return Err(Error::Malformed("control state width/version"));
        }
        let mut r = Reader { bytes, at: 8 };
        let vault_id = r.array()?;
        let registration_id = r.array()?;
        let revision = r.u64()?;
        let accepted = r.snapshot()?;
        let pending = match r.byte()? {
            0 => None,
            1 => {
                let operation = ControlOperation::parse(r.byte()?)?;
                let request_id = r.array()?;
                let target_descriptor_digest = r.array()?;
                let owner_commitment = r.array()?;
                let submission = match r.byte()? {
                    0 => None,
                    1 => Some(r.snapshot()?),
                    _ => return Err(Error::Malformed("control submission flag")),
                };
                if submission.is_some_and(|target| {
                    target.descriptor_digest != target_descriptor_digest
                        || accepted.generation.checked_add(1) != Some(target.generation)
                }) {
                    return Err(Error::Integrity);
                }
                Some(ControlIntent {
                    operation,
                    request_id,
                    target_descriptor_digest,
                    owner_commitment,
                    submission,
                })
            }
            _ => return Err(Error::Malformed("control pending flag")),
        };
        if bytes[r.at..].iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed("control reserved bytes"));
        }
        Ok(Self {
            vault_id,
            registration_id,
            revision,
            accepted,
            pending,
        })
    }
}

impl SnapshotIdentity {
    fn append(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.descriptor_digest);
        bytes.extend_from_slice(&self.head_digest);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.at.checked_add(N).ok_or(Error::ResourceLimit)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(Error::Integrity)?
            .try_into()
            .map_err(|_| Error::Integrity)?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn snapshot(&mut self) -> Result<SnapshotIdentity> {
        Ok(SnapshotIdentity {
            descriptor_digest: self.array()?,
            head_digest: self.array()?,
            generation: self.u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(operation: ControlOperation) -> PreparedControlOperation {
        PreparedControlOperation::new(
            [1; 16],
            [2; 16],
            operation,
            [6; 16],
            snapshot(3, 7),
            SnapshotIdentity {
                descriptor_digest: [if operation == ControlOperation::Credentials {
                    7
                } else {
                    3
                }; 32],
                head_digest: [5; 32],
                generation: 8,
            },
        )
        .unwrap()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn snapshot(value: u8, generation: u64) -> SnapshotIdentity {
        SnapshotIdentity {
            descriptor_digest: [value; 32],
            head_digest: [value + 1; 32],
            generation,
        }
    }
    fn state() -> ControlState {
        ControlState::register([1; 16], [2; 16], snapshot(3, 7))
    }
    fn prepared() -> ControlState {
        state()
            .prepare(
                ControlOperation::ProtectiveTransition,
                [8; 16],
                [9; 32],
                [10; 32],
            )
            .unwrap()
    }
    #[test]
    fn control_submission_intent_survives_codec_and_never_treats_source_as_abort() {
        let prepared = prepared();
        let submitted = prepared.authorize_submission(snapshot(9, 8)).unwrap();
        let reopened = ControlState::parse(&submitted.encode()).unwrap();
        assert_eq!(
            reopened.observe(state().accepted()).unwrap(),
            ControlObservation::StillUnknown {
                request_id: [8; 16]
            }
        );
        assert!(matches!(
            reopened.abandon_unsubmitted(),
            Err(Error::OutcomeUnknown { .. })
        ));
        assert_eq!(reopened.pending().unwrap().owner_commitment, [10; 32]);
        assert_eq!(
            reopened.observe(snapshot(9, 8)).unwrap(),
            ControlObservation::TargetObserved {
                request_id: [8; 16]
            }
        );
        let complete = reopened.confirm_target(snapshot(9, 8)).unwrap();
        assert!(complete.pending().is_none());
        assert!(matches!(
            complete.observe(state().accepted()),
            Err(Error::Conflict)
        ));
        assert_eq!(
            complete.observe(snapshot(9, 8)).unwrap(),
            ControlObservation::Accepted
        );
    }
    #[test]
    fn control_rejects_target_substitution_and_submission_before_complete_binding() {
        assert!(state().authorize_submission(snapshot(9, 8)).is_err());
        let prepared = prepared();
        assert!(prepared.authorize_submission(snapshot(11, 8)).is_err());
        assert!(prepared.authorize_submission(snapshot(9, 7)).is_err());
        assert!(prepared.authorize_submission(snapshot(9, 9)).is_err());
        assert!(prepared.confirm_target(snapshot(9, 8)).is_err());
        assert!(prepared
            .prepare(ControlOperation::Save, [1; 16], [9; 32], [2; 32])
            .is_err());
        assert_eq!(
            prepared.abandon_unsubmitted().unwrap().accepted(),
            state().accepted()
        );
    }
    #[test]
    fn control_codec_rejects_truncation_extensions_reserved_flags_and_overflow() {
        for state in [
            state(),
            prepared(),
            prepared().authorize_submission(snapshot(9, 8)).unwrap(),
        ] {
            let bytes = state.encode();
            assert_eq!(bytes.len(), CONTROL_STATE_BYTES);
            assert_eq!(ControlState::parse(&bytes).unwrap(), state);
            for length in 0..bytes.len() {
                assert!(ControlState::parse(&bytes[..length]).is_err());
            }
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(ControlState::parse(&extended).is_err());
        }
        let mut bytes = state().encode();
        bytes[274] = 1;
        assert!(ControlState::parse(&bytes).is_err());
        let mut bytes = state().encode();
        bytes[120] = 2;
        assert!(ControlState::parse(&bytes).is_err());
        let mut maximum = state();
        maximum.revision = u64::MAX;
        assert!(maximum
            .prepare(ControlOperation::Save, [0; 16], [0; 32], [0; 32])
            .is_err());
    }

    #[test]
    fn ordinary_owner_canonical_vectors_and_strict_decoder() {
        // Independently calculated with Python hashlib SHA-256 over the exact
        // fixed bytes, not captured from this implementation at test runtime.
        let expected = [
            (
                ControlOperation::Save,
                "dc864afeab0ab48032510cc48dab43030568710aebec544dfd47c85f40921ad2",
            ),
            (
                ControlOperation::Delete,
                "929e3f2114c5a08893c3bfa055224db5719ee332c98ce0dba2cb036843300e00",
            ),
            (
                ControlOperation::Credentials,
                "8c80fa20539254216181e6c22258e93fa2f24fc3fb42e8f69b0706e0a1b3df0b",
            ),
        ];
        let expected_save_bytes = concat!(
            "4647564f574e3031",
            "01010101010101010101010101010101",
            "02020202020202020202020202020202",
            "01",
            "06060606060606060606060606060606",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "0000000000000007",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "0505050505050505050505050505050505050505050505050505050505050505",
            "0000000000000008"
        );
        for (kind, digest) in expected {
            let operation = owner(kind);
            let bytes = operation.canonical_bytes();
            assert_eq!(bytes.len(), CONTROL_OWNER_BYTES);
            assert_eq!(hex(&operation.owner_commitment()), digest);
            assert_eq!(PreparedControlOperation::parse(&bytes).unwrap(), operation);
            for length in 0..bytes.len() {
                assert!(PreparedControlOperation::parse(&bytes[..length]).is_err());
            }
            let mut extended = bytes.to_vec();
            extended.push(0);
            assert!(PreparedControlOperation::parse(&extended).is_err());
            if kind == ControlOperation::Save {
                assert_eq!(hex(&bytes), expected_save_bytes);
            }
        }
        for tag in [0, 4, 5, 6, 255] {
            let mut bytes = owner(ControlOperation::Save).canonical_bytes();
            bytes[40] = tag;
            assert!(PreparedControlOperation::parse(&bytes).is_err());
        }
    }

    #[test]
    fn ordinary_control_rejects_each_owner_field_substitution() {
        for kind in [
            ControlOperation::Save,
            ControlOperation::Delete,
            ControlOperation::Credentials,
        ] {
            let operation = owner(kind);
            let prepared = state().prepare_ordinary(&operation).unwrap();
            prepared.validate_ordinary(&operation).unwrap();
            let submitted = prepared.authorize_ordinary_submission(&operation).unwrap();
            submitted.validate_ordinary(&operation).unwrap();
            assert_eq!(
                submitted.pending().unwrap().submission(),
                Some(operation.target())
            );
            assert!(submitted.authorize_ordinary_submission(&operation).is_err());
            for offset in 0..CONTROL_OWNER_BYTES {
                let mut bytes = operation.canonical_bytes();
                bytes[offset] ^= 1;
                if let Ok(changed) = PreparedControlOperation::parse(&bytes) {
                    assert!(prepared.authorize_ordinary_submission(&changed).is_err());
                    assert!(submitted.validate_ordinary(&changed).is_err());
                }
            }
            // The generic protective/diagnostic API remains available, but its
            // target cannot be mistaken for a correctly bound ordinary target.
            let mut other_target = operation.target();
            other_target.head_digest[0] ^= 1;
            let mismatched = prepared.authorize_submission(other_target).unwrap();
            assert!(mismatched.validate_ordinary(&operation).is_err());
            assert!(submitted.abandon_unsubmitted().is_err());
        }
    }

    #[test]
    fn ordinary_control_rejects_foreign_source_and_unsupported_roles() {
        let operation = owner(ControlOperation::Save);
        for foreign in [
            ControlState::register([9; 16], [2; 16], snapshot(3, 7)),
            ControlState::register([1; 16], [9; 16], snapshot(3, 7)),
            ControlState::register([1; 16], [2; 16], snapshot(3, 6)),
            ControlState::register([1; 16], [2; 16], snapshot(8, 7)),
        ] {
            assert!(foreign.prepare_ordinary(&operation).is_err());
        }
        for unsupported in [
            ControlOperation::ProtectiveTransition,
            ControlOperation::Import,
        ] {
            assert!(PreparedControlOperation::new(
                [1; 16],
                [2; 16],
                unsupported,
                [6; 16],
                snapshot(3, 7),
                snapshot(3, 8),
            )
            .is_err());
        }
        assert!(PreparedControlOperation::new(
            [1; 16],
            [2; 16],
            ControlOperation::Save,
            [6; 16],
            snapshot(3, 7),
            snapshot(8, 8),
        )
        .is_err());
        assert!(PreparedControlOperation::new(
            [1; 16],
            [2; 16],
            ControlOperation::Save,
            [6; 16],
            snapshot(3, u64::MAX),
            snapshot(3, 0),
        )
        .is_err());
    }
}
