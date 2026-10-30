//! Bind host control authority to the Engine's privately retained exact plan.
use super::*;
use crate::{ControlOperation, PreparedControlOperation, SnapshotIdentity};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OrdinaryPlanBinding {
    Save([u8; 32]),
    Delete([u8; 32]),
    Credentials([u8; 32]),
}

// This fingerprint is private, in-memory plan validation, not a saved format.
// Hash incrementally so binding a record does not copy its entire envelope.
fn start(operation: ControlOperation, receipt: &CommitReceipt) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"fogvault/private-ordinary-plan/v1\0");
    hash.update([operation as u8]);
    hash.update(receipt.generation.to_be_bytes());
    hash.update(receipt.request_id);
    hash.update(receipt.head_digest);
    hash
}
fn bytes(hash: &mut Sha256, value: &[u8]) -> Result<()> {
    hash.update(
        u64::try_from(value.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_be_bytes(),
    );
    hash.update(value);
    Ok(())
}
fn obsolete(hash: &mut Sha256, nodes: &[[u8; 32]]) -> Result<()> {
    hash.update(
        u64::try_from(nodes.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_be_bytes(),
    );
    for node in nodes {
        hash.update(node);
    }
    Ok(())
}

pub(super) fn bind_save(plan: &CommitPlan) -> Result<OrdinaryPlanBinding> {
    let mut hash = start(ControlOperation::Save, &plan.receipt);
    bytes(&mut hash, &plan.prior_head)?;
    bytes(&mut hash, &plan.head_bytes)?;
    hash.update(plan.id);
    hash.update(plan.revision.to_be_bytes());
    bytes(&mut hash, &plan.envelope)?;
    obsolete(&mut hash, &plan.obsolete)?;
    Ok(OrdinaryPlanBinding::Save(hash.finalize().into()))
}
pub(super) fn bind_delete(plan: &DeletePlan) -> Result<OrdinaryPlanBinding> {
    let mut hash = start(ControlOperation::Delete, &plan.receipt);
    bytes(&mut hash, &plan.prior_descriptor)?;
    bytes(&mut hash, &plan.prior_head)?;
    bytes(&mut hash, &plan.head_bytes)?;
    hash.update(plan.id);
    hash.update(plan.deleted_revision.to_be_bytes());
    obsolete(&mut hash, &plan.obsolete)?;
    Ok(OrdinaryPlanBinding::Delete(hash.finalize().into()))
}
pub(super) fn bind_credentials(plan: &CredentialPlan) -> Result<OrdinaryPlanBinding> {
    let mut hash = start(ControlOperation::Credentials, &plan.receipt);
    bytes(&mut hash, &plan.prior_descriptor)?;
    bytes(&mut hash, &plan.descriptor_bytes)?;
    bytes(&mut hash, &plan.prior_head)?;
    bytes(&mut hash, &plan.head_bytes)?;
    Ok(OrdinaryPlanBinding::Credentials(hash.finalize().into()))
}

impl Engine {
    /// Rebind a registered adapter to an exactly selected descriptor after
    /// durable reconciliation. This always revokes the old Engine first and
    /// leaves the replacement locked: it does no KDF/provider work and accepts
    /// no head, plaintext or session. The host must independently validate its
    /// selected control target; parsing a descriptor is not freshness evidence.
    /// Existing trusted policy is retained, never widened from saved bytes.
    pub fn reopen_locked(&mut self, descriptor: &[u8]) -> Result<()> {
        let vault_id = self.vault_id();
        let limits = self.limits;
        let policy = self.kdf_policy.clone();
        let admission = self.reopen_admission(descriptor);
        let allow_legacy = self.content_format() != format::EPOCH_FORMAT_ID;
        self.lock();
        *self = Self::open_rebound_descriptor(
            descriptor,
            vault_id,
            limits,
            policy,
            admission,
            allow_legacy,
        )?;
        Ok(())
    }

    /// Preflight the exact selected target before registered publication. The
    /// returned Engine is locked and carries no accepted head or live keys.
    /// Neither success nor failure changes/revokes this source Engine. Adapters
    /// explicitly revoke it before submission and install the prepared locked
    /// replacement only after trusted completion, without a fallible reparse.
    pub fn prepare_reopen_locked(&self, descriptor: &[u8]) -> Result<Self> {
        Self::open_rebound_descriptor(
            descriptor,
            self.vault_id(),
            self.limits,
            self.kdf_policy.clone(),
            self.reopen_admission(descriptor),
            self.content_format() != format::EPOCH_FORMAT_ID,
        )
    }

    fn reopen_admission(&self, descriptor: &[u8]) -> Option<crate::AccessAdmission> {
        // An already prepared target can carry a host-authorized admission
        // change. Do not install it for any other presented descriptor.
        self.pending
            .as_ref()
            .filter(|pending| {
                pending
                    .descriptor
                    .as_ref()
                    .is_some_and(|target| target.bytes() == descriptor)
            })
            .and_then(|pending| pending.access_admission.clone())
            .or_else(|| self.access_admission.clone())
    }

    fn open_rebound_descriptor(
        descriptor: &[u8],
        vault_id: [u8; 16],
        limits: Limits,
        policy: KdfPolicy,
        admission: Option<crate::AccessAdmission>,
        allow_legacy: bool,
    ) -> Result<Self> {
        // A maintained engine never obtains a legacy writable parser through
        // restart preflight. Explicit diagnostic sources retain compatibility.
        if !allow_legacy
            && (descriptor.get(..8) != Some(b"FGVP0003".as_slice())
                || descriptor.get(12..14) != Some(format::EPOCH_FORMAT_ID.to_be_bytes().as_slice()))
        {
            return Err(Error::UnsupportedCapability);
        }
        let replacement = if descriptor.get(..8) == Some(b"FGVP0003".as_slice()) {
            let admission = admission.ok_or(Error::UnsupportedCapability)?;
            if descriptor.get(12..14) == Some(format::EPOCH_FORMAT_ID.to_be_bytes().as_slice()) {
                Self::open_epoch_access(descriptor, limits, policy, admission)?
            } else {
                Self::diagnostic_open_with_access(descriptor, limits, policy, admission)?
            }
        } else {
            let mut replacement =
                Self::diagnostic_open_with_kdf_policy(descriptor, limits, policy)?;
            // Preserve a host's explicitly configured P3 allowance even while
            // the selected source remains P2. It is not activated by the file.
            replacement.access_admission = admission;
            replacement
        };
        if replacement.vault_id() != vault_id {
            return Err(Error::Integrity);
        }
        Ok(replacement)
    }

    /// Select control ownership from this exact non-replay staged save. Public
    /// plan fields are checked against a private retained fingerprint first.
    pub fn control_save(
        &self,
        registration_id: [u8; 16],
        plan: &CommitPlan,
    ) -> Result<PreparedControlOperation> {
        if plan.replay {
            return Err(Error::Conflict);
        }
        self.control_ordinary(
            registration_id,
            ControlOperation::Save,
            bind_save(plan)?,
            &plan.receipt,
            &plan.prior_head,
            &plan.head_bytes,
        )
    }

    pub fn control_delete(
        &self,
        registration_id: [u8; 16],
        plan: &DeletePlan,
    ) -> Result<PreparedControlOperation> {
        if plan.replay || plan.prior_descriptor != self.descriptor_bytes() {
            return Err(Error::Conflict);
        }
        self.control_ordinary(
            registration_id,
            ControlOperation::Delete,
            bind_delete(plan)?,
            &plan.receipt,
            &plan.prior_head,
            &plan.head_bytes,
        )
    }

    pub fn control_credentials(
        &self,
        registration_id: [u8; 16],
        plan: &CredentialPlan,
    ) -> Result<PreparedControlOperation> {
        if plan.replay || plan.prior_descriptor != self.descriptor_bytes() {
            return Err(Error::Conflict);
        }
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if pending
            .descriptor
            .as_ref()
            .is_none_or(|descriptor| descriptor.bytes() != plan.descriptor_bytes)
        {
            return Err(Error::Conflict);
        }
        self.control_ordinary(
            registration_id,
            ControlOperation::Credentials,
            bind_credentials(plan)?,
            &plan.receipt,
            &plan.prior_head,
            &plan.head_bytes,
        )
    }

    fn control_ordinary(
        &self,
        registration_id: [u8; 16],
        operation: ControlOperation,
        binding: OrdinaryPlanBinding,
        receipt: &CommitReceipt,
        prior_head: &[u8],
        head: &[u8],
    ) -> Result<PreparedControlOperation> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        if !self.recovery_candidate {
            self.current_session()?;
        } else if operation != ControlOperation::Credentials {
            return Err(Error::Locked);
        }
        let pending = self.pending.as_ref().ok_or(Error::Conflict)?;
        if self.audit.is_some()
            || pending.protective
            || pending.ordinary_binding != Some(binding)
            || prior_head != self.head_bytes
            || head != pending.bytes
            || *receipt != Self::receipt(&pending.head, &pending.bytes)
            || (operation == ControlOperation::Credentials) != pending.descriptor.is_some()
        {
            return Err(Error::Conflict);
        }
        PreparedControlOperation::new(
            self.vault_id(),
            registration_id,
            operation,
            pending.head.request_id,
            SnapshotIdentity {
                descriptor_digest: self.descriptor.hash(),
                head_digest: crypto::digest(&self.head_bytes),
                generation: self.head.generation,
            },
            SnapshotIdentity {
                descriptor_digest: pending
                    .descriptor
                    .as_ref()
                    .unwrap_or(&self.descriptor)
                    .hash(),
                head_digest: crypto::digest(&pending.bytes),
                generation: pending.head.generation,
            },
        )
    }
}
