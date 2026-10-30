//! Credential updates rewrap one root; they never rewrite record or index objects.
use super::*;

/// No passwords, root keys or unwrapped content keys survive in a draft.
/// An opaque draft can only be staged against its original session and snapshot.
pub struct CredentialDraft {
    pub(super) session: SessionToken,
    pub(super) descriptor_digest: [u8; 32],
    pub(super) head_digest: [u8; 32],
    pub(super) request: [u8; 16],
    pub(super) operation_digest: [u8; 32],
    pub(super) descriptor: Option<Descriptor>,
    pub(super) replacement_session: Option<SessionToken>,
    pub(super) recovery: bool,
    pub(super) access_admission: Option<crate::AccessAdmission>,
}

/// The adapter atomically compares/replaces BOTH header objects. No node or
/// record write is part of this plan. Confirmation follows storage completion.
pub struct CredentialPlan {
    pub replay: bool,
    pub receipt: CommitReceipt,
    pub prior_descriptor: Vec<u8>,
    pub descriptor_bytes: Vec<u8>,
    pub prior_head: Vec<u8>,
    pub head_bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialReceipt {
    pub receipt: CommitReceipt,
    pub session: SessionToken,
    pub key_effect: crate::KeyEffect,
}

impl CredentialDraft {
    /// Credential maintenance preserves the root and record-content keys.
    pub fn key_effect(&self) -> crate::KeyEffect {
        crate::KeyEffect::Preserved
    }
}
impl CredentialPlan {
    pub fn key_effect(&self) -> crate::KeyEffect {
        crate::KeyEffect::Preserved
    }
}
impl CredentialReceipt {
    pub fn key_effect(&self) -> crate::KeyEffect {
        self.key_effect
    }
}

impl Engine {
    /// Requires the current password again; the root is not retained in an
    /// unlocked Engine. The password bytes are used exactly as supplied.
    pub fn draft_password_change(
        &self,
        current_password: &[u8],
        new_password: &[u8],
        request: [u8; 16],
    ) -> Result<CredentialDraft> {
        self.draft_credential_change(
            current_password,
            new_password,
            self.kdf_profile(),
            request,
            false,
        )
    }
    /// A trusted host must admit the exact target before any KDF work. Only a
    /// component-wise increase is an upgrade; constraints never trigger fallback.
    pub fn draft_kdf_upgrade(
        &self,
        password: &[u8],
        target: KdfProfile,
        request: [u8; 16],
    ) -> Result<CredentialDraft> {
        self.draft_credential_change(password, password, target, request, true)
    }
    fn draft_credential_change(
        &self,
        current_password: &[u8],
        new_password: &[u8],
        target: KdfProfile,
        request: [u8; 16],
        upgrade: bool,
    ) -> Result<CredentialDraft> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        // The host admits the exact target before any password/KDF work.
        self.kdf_policy.admit(target)?;
        let replay = self.head.request_id == request;
        if !replay && upgrade && !target.is_strict_upgrade_from(self.kdf_profile()) {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        self.head
            .generation
            .checked_add(u64::from(!replay))
            .ok_or(Error::ResourceLimit)?;
        let (descriptor, replacement_session, digest) = if replay {
            let digest = self.credential_identity(&self.descriptor, target, upgrade)?;
            if !crypto::tags_match(&self.head.operation_digest, &digest) {
                return Err(Error::OperationIdReuse);
            }
            // Never make a cheap password verifier from a root-derived key:
            // retained old wrappers can disclose that root. The current wrapper
            // provides password equivalence only at its admitted Argon2 cost.
            match self
                .descriptor
                .unlock_with_policy(new_password, &self.kdf_policy)
            {
                Ok(root) => drop(root),
                Err(Error::Crypto(crypto::CryptoError::AuthenticationFailed)) => {
                    return Err(Error::OperationIdReuse)
                }
                Err(error) => return Err(error),
            }
            (None, None, digest)
        } else {
            let root = self
                .descriptor
                .unlock_with_policy(current_password, &self.kdf_policy)?;
            let next = self
                .descriptor
                .rewrap(&root, new_password, target, &self.kdf_policy)?;
            drop(root);
            let digest = self.credential_identity(&next, target, upgrade)?;
            let session = SessionToken {
                vault_id: self.vault_id(),
                nonce: crypto::random()?,
            };
            (Some(next), Some(session), digest)
        };
        Ok(CredentialDraft {
            recovery: false,
            access_admission: None,
            session: self.current_session()?,
            descriptor_digest: self.descriptor.hash(),
            head_digest: crypto::digest(&self.head_bytes),
            request,
            operation_digest: digest,
            descriptor,
            replacement_session,
        })
    }
    fn credential_identity(
        &self,
        descriptor: &Descriptor,
        target: KdfProfile,
        upgrade: bool,
    ) -> Result<[u8; 32]> {
        let mut input = format::frame(b"fogvault/prototype/credential-change/v1");
        input.push(u8::from(upgrade));
        input.extend_from_slice(&descriptor.context_hash());
        input.extend_from_slice(&target.memory_kib().to_be_bytes());
        input.extend_from_slice(&target.passes().to_be_bytes());
        input.extend_from_slice(&target.lanes().to_be_bytes());
        input.extend_from_slice(&descriptor.hash());
        Ok(crypto::mac(&self.raw_keys()?.operation, &input))
    }
    /// Staging is storage-blind. The adapter checks a coherent snapshot and
    /// atomically CASes prior_descriptor AND prior_head before publication.
    pub fn stage_credential_change(&mut self, draft: &CredentialDraft) -> Result<CredentialPlan> {
        if draft.recovery {
            self.raw_keys()?;
            self.ensure_known_outcome()?;
            if !self.recovery_candidate || self.audit.is_some() {
                return Err(Error::Conflict);
            }
        } else {
            self.operation_keys()?;
        }
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        if draft.recovery {
            if self.session != Some(draft.session) {
                return Err(Error::StaleSession);
            }
        } else {
            self.check_session(&draft.session)?;
        }
        if self.descriptor.hash() != draft.descriptor_digest
            || crypto::digest(&self.head_bytes) != draft.head_digest
        {
            return Err(Error::Conflict);
        }
        if self.head.request_id == draft.request {
            if !crypto::tags_match(&self.head.operation_digest, &draft.operation_digest) {
                return Err(Error::OperationIdReuse);
            }
            if draft.descriptor.is_some() {
                return Err(Error::Conflict);
            }
            return Ok(CredentialPlan {
                replay: true,
                receipt: Self::receipt(&self.head, &self.head_bytes),
                prior_descriptor: self.descriptor_bytes().to_vec(),
                descriptor_bytes: self.descriptor_bytes().to_vec(),
                prior_head: self.head_bytes.clone(),
                head_bytes: self.head_bytes.clone(),
            });
        }
        let descriptor = draft.descriptor.as_ref().ok_or(Error::Conflict)?;
        let replacement_session = draft.replacement_session.ok_or(Error::Conflict)?;
        let mut head = self.head.clone();
        head.generation = head.generation.checked_add(1).ok_or(Error::ResourceLimit)?;
        head.request_id = draft.request;
        head.operation_digest = draft.operation_digest;
        let bytes = head.encode(descriptor, &self.raw_keys()?.head);
        let plan = CredentialPlan {
            replay: false,
            receipt: Self::receipt(&head, &bytes),
            prior_descriptor: self.descriptor_bytes().to_vec(),
            descriptor_bytes: descriptor.bytes().to_vec(),
            prior_head: self.head_bytes.clone(),
            head_bytes: bytes.clone(),
        };
        self.pending = Some(Pending {
            head,
            bytes,
            unknown: false,
            descriptor: Some(descriptor.clone()),
            replacement_session: Some(replacement_session),
            access_admission: draft.access_admission.clone(),
            protective: false,
            ordinary_binding: Some(control::bind_credentials(&plan)?),
        });
        Ok(plan)
    }
    /// No entropy, password derivation or fallible allocation is needed after a
    /// storage commit. A mismatching confirmation keeps the pending plan intact.
    pub fn confirm_credential_commit(
        &mut self,
        descriptor: &[u8],
        head: &[u8],
    ) -> Result<CredentialReceipt> {
        if self.recovery_candidate {
            self.raw_keys()?;
        } else {
            self.operation_keys()?;
        }
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if pending.unknown {
            return Err(Error::OutcomeUnknown {
                request_id: pending.head.request_id,
            });
        }
        let next = pending.descriptor.as_ref().ok_or(Error::Conflict)?;
        if next.bytes() != descriptor || pending.bytes != head {
            return Err(Error::Integrity);
        }
        let session = pending.replacement_session.ok_or(Error::Conflict)?;
        let pending = self.pending.take().ok_or(Error::Conflict)?;
        self.descriptor = pending.descriptor.ok_or(Error::Conflict)?;
        if let Some(admission) = pending.access_admission {
            self.access_admission = Some(admission);
        }
        self.head = pending.head;
        self.head_bytes = pending.bytes;
        self.session = Some(session);
        self.recovery_candidate = false;
        Ok(CredentialReceipt {
            receipt: Self::receipt(&self.head, &self.head_bytes),
            session,
            key_effect: crate::KeyEffect::Preserved,
        })
    }
}
