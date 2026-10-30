//! The only owner of key/session/accepted-head/pending-receipt decisions.
//! Adapters supply a coherent snapshot and confirm only after their I/O completes.
use crate::{
    crypto,
    format::{self, Descriptor, Entry, IndexHead},
    index, Error, IndexStats, KdfPolicy, KdfProfile, Limits, NodeStore, RecordId, Result,
};
use std::fmt;
use zeroize::Zeroizing;
mod access;
mod async_provider;
pub use async_provider::{
    AsyncAccessSetup, AsyncCreation, AsyncProtectiveAccess, AsyncUnlock, ProviderCancellation,
    ProviderReply, ProviderRequest,
};
mod control;
mod credentials;
mod protective;
mod records;
mod revocation;
pub use credentials::{CredentialDraft, CredentialPlan, CredentialReceipt};
pub use protective::{
    ProtectivePlan, ProtectiveSource, ProtectiveTransition, TransitionStore,
    UnanchoredProtectiveControl,
};
pub use records::{DeleteDraft, DeletePlan, RecordCursor, RecordPage};
use revocation::PublicationAuthority;
pub use revocation::{RevocationHandle, RevocationReceipt, ScopedRevocationHandle, WorkGuard};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken {
    vault_id: [u8; 16],
    nonce: [u8; 16],
}
impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([redacted capability])")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub generation: u64,
    pub request_id: [u8; 16],
    pub head_digest: [u8; 32],
}
pub struct SecretRecord {
    pub revision: u64,
    pub metadata: Zeroizing<Vec<u8>>,
    pub payload: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRecord")
            .field("revision", &self.revision)
            .field("metadata", &"[redacted]")
            .field("payload", &"[redacted]")
            .finish()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Initializing,
    Locked,
    Unlocking,
    Auditing,
    Ready,
    Prepared,
    Uncertain,
    Recovery,
}
struct Keys {
    wrapping: Zeroizing<[u8; 32]>,
    head: Zeroizing<[u8; 32]>,
    operation: Zeroizing<[u8; 32]>,
}
struct Pending {
    head: IndexHead,
    bytes: Vec<u8>,
    unknown: bool,
    descriptor: Option<Descriptor>,
    replacement_session: Option<SessionToken>,
    access_admission: Option<crate::AccessAdmission>,
    protective: bool,
    ordinary_binding: Option<control::OrdinaryPlanBinding>,
}
#[derive(Clone, Copy)]
enum Purpose {
    Unlock,
    Current,
    Reconcile,
}
struct Audit {
    head: IndexHead,
    bytes: Vec<u8>,
    cursor: index::AuditCursor,
    record: Option<(RecordId, Entry)>,
    checked: u64,
    finished: bool,
    purpose: Purpose,
    descriptor: Descriptor,
    replacement_session: Option<SessionToken>,
}
#[derive(Clone, Debug)]
pub enum AuditRequest {
    Node([u8; 32]),
    Record { id: RecordId, entry: Entry },
    Done,
}
#[derive(Clone, Copy, Debug)]
pub struct AuditMetrics {
    pub nodes_read: u64,
    pub records_checked: u64,
    pub node_bytes: u64,
    pub peak_buffered_nodes: usize,
    pub peak_path_nodes: usize,
}
#[derive(Clone, Copy)]
pub struct StoredRecord<'a> {
    pub revision: u64,
    pub envelope: &'a [u8],
}
/// Opaque proof; an adapter cannot forge an old record entry and ask to decrypt it.
pub struct VerifiedRecord {
    id: RecordId,
    entry: Entry,
    session: SessionToken,
    head_digest: [u8; 32],
}
impl VerifiedRecord {
    pub fn revision(&self) -> u64 {
        self.entry.revision
    }
    pub fn id(&self) -> RecordId {
        self.id
    }
}
pub struct VerifiedLookup {
    id: RecordId,
    session: SessionToken,
    head_digest: [u8; 32],
    entry: Option<VerifiedRecord>,
    pub stats: IndexStats,
}
impl VerifiedLookup {
    pub fn entry(&self) -> Option<&VerifiedRecord> {
        self.entry.as_ref()
    }
}
/// Encrypted preparation, tied to one session and accepted head; contains no raw keys.
pub struct SaveDraft {
    id: RecordId,
    expected: Option<u64>,
    revision: u64,
    request: [u8; 16],
    operation_digest: [u8; 32],
    envelope: Vec<u8>,
    session: SessionToken,
    head_digest: [u8; 32],
}
pub struct CommitPlan {
    pub replay: bool,
    pub receipt: CommitReceipt,
    pub prior_head: Vec<u8>,
    pub head_bytes: Vec<u8>,
    pub envelope: Vec<u8>,
    pub id: RecordId,
    pub revision: u64,
    pub obsolete: Vec<[u8; 32]>,
    pub stats: IndexStats,
}

pub struct Engine {
    descriptor: Descriptor,
    head: IndexHead,
    head_bytes: Vec<u8>,
    limits: Limits,
    kdf_policy: KdfPolicy,
    keys: Option<Keys>,
    session: Option<SessionToken>,
    initializing: bool,
    pending: Option<Pending>,
    audit: Option<Audit>,
    authority: PublicationAuthority,
    access_admission: Option<crate::access::AccessAdmission>,
    recovery_candidate: bool,
}
struct PasswordOnlyProvider;
impl crate::KeyProvider for PasswordOnlyProvider {
    fn capability_kind(&self, _: &crate::ProviderIdentity) -> crate::ProviderCapabilityKind {
        crate::ProviderCapabilityKind::ConvenienceCache
    }
    fn wrap_seed(
        &mut self,
        _: &crate::ProviderContext,
        _: &[u8; 32],
    ) -> crate::ProviderResult<Vec<u8>> {
        Err(crate::ProviderError::Unsupported)
    }
    fn unwrap_seed(
        &mut self,
        _: &crate::ProviderContext,
        _: &[u8],
    ) -> crate::ProviderResult<Zeroizing<[u8; 32]>> {
        Err(crate::ProviderError::Unsupported)
    }
}

impl Engine {
    fn derive(root: &[u8; 32], descriptor: &Descriptor) -> Result<Keys> {
        Ok(Keys {
            wrapping: crypto::derive(root, &descriptor.vault_id, b"record-key-wrapping")?,
            head: crypto::derive(root, &descriptor.vault_id, b"head-authentication")?,
            operation: crypto::derive(root, &descriptor.vault_id, b"operation-identity")?,
        })
    }
    fn empty_head() -> Result<IndexHead> {
        Ok(IndexHead {
            generation: 0,
            request_id: crypto::random()?,
            operation_digest: [0; 32],
            count: 0,
            root: None,
        })
    }
    /// Password-only creation uses the same credential/content grammar as
    /// explicit device profiles: P3/content three at wrapping epoch zero.
    pub fn create(password: &[u8], limits: Limits) -> Result<Self> {
        Self::create_with_kdf_policy(password, limits, KdfPolicy::baseline())
    }
    pub fn create_with_kdf_policy(
        password: &[u8],
        limits: Limits,
        policy: KdfPolicy,
    ) -> Result<Self> {
        let (engine, recovery) = Self::create_with_access(
            password,
            limits,
            policy,
            Self::portable_admission(),
            crate::AccessProfile::Portable,
            &[],
            false,
            &mut PasswordOnlyProvider,
        )?;
        debug_assert!(recovery.is_none());
        Ok(engine)
    }
    /// Default opening admits only the maintained password-only profile. Device
    /// or recovery descriptors require explicit trusted access admission.
    pub fn open(descriptor: &[u8], limits: Limits) -> Result<Self> {
        Self::open_with_kdf_policy(descriptor, limits, KdfPolicy::baseline())
    }
    pub fn open_with_kdf_policy(
        descriptor: &[u8],
        limits: Limits,
        policy: KdfPolicy,
    ) -> Result<Self> {
        Self::open_with_access(descriptor, limits, policy, Self::portable_admission())
    }
    fn portable_admission() -> crate::AccessAdmission {
        format::current_portable_admission()
    }

    /// Explicit legacy P2 fixture/diagnostic constructor. Ordinary creation
    /// never selects this writable compatibility format.
    pub fn diagnostic_create(password: &[u8], limits: Limits) -> Result<Self> {
        Self::diagnostic_create_with_kdf_policy(password, limits, KdfPolicy::baseline())
    }
    pub fn diagnostic_create_with_kdf_policy(
        password: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
    ) -> Result<Self> {
        crate::validate_policy(limits)?;
        kdf_policy.admit(KdfProfile::baseline())?;
        let (descriptor, root) = Descriptor::create_with_policy(password, &kdf_policy)?;
        let keys = Self::derive(&root, &descriptor)?;
        let head = Self::empty_head()?;
        let head_bytes = head.encode(&descriptor, &keys.head);
        Ok(Self {
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
            authority: PublicationAuthority::new(true),
            access_admission: None,
            recovery_candidate: false,
        })
    }
    pub fn diagnostic_open(descriptor: &[u8], limits: Limits) -> Result<Self> {
        Self::diagnostic_open_with_kdf_policy(descriptor, limits, KdfPolicy::baseline())
    }
    pub fn diagnostic_open_with_kdf_policy(
        descriptor: &[u8],
        limits: Limits,
        kdf_policy: KdfPolicy,
    ) -> Result<Self> {
        crate::validate_policy(limits)?;
        let descriptor = Descriptor::parse_with_policy(descriptor, &kdf_policy)?;
        if descriptor.format_id() != 2 {
            return Err(Error::Malformed(
                "P1 experiment requires explicit migration",
            ));
        }
        // This placeholder carries no accepted authority until unlock/audit.
        let head = IndexHead {
            generation: 0,
            request_id: [0; 16],
            operation_digest: [0; 32],
            count: 0,
            root: None,
        };
        Ok(Self {
            descriptor,
            head,
            head_bytes: Vec::new(),
            limits,
            kdf_policy,
            keys: None,
            session: None,
            initializing: false,
            pending: None,
            audit: None,
            authority: PublicationAuthority::new(false),
            access_admission: None,
            recovery_candidate: false,
        })
    }
    pub fn activate_created(&mut self) -> Result<SessionToken> {
        let work = self.authority.work()?;
        if !self.initializing || self.keys.is_none() || self.session.is_some() {
            return Err(Error::Conflict);
        }
        let token = SessionToken {
            vault_id: self.descriptor.vault_id,
            nonce: crypto::random()?,
        };
        self.initializing = false;
        work.check()?;
        self.session = Some(token);
        Ok(token)
    }
    pub fn begin_unlock(&mut self, password: &[u8]) -> Result<()> {
        if self.initializing {
            return Err(Error::Conflict);
        }
        self.lock();
        let work = self.authority.begin_attempt()?;
        let root = self
            .descriptor
            .unlock_with_policy(password, &self.kdf_policy)?;
        let keys = Self::derive(&root, &self.descriptor)?;
        self.authority.retain_keys(&work)?;
        self.keys = Some(keys);
        Ok(())
    }
    pub fn lock(&mut self) {
        self.authority.handle().revoke();
        self.audit = None;
        self.pending = None;
        self.session = None;
        self.keys = None;
        self.authority.clear_keys();
        self.recovery_candidate = false;
        self.initializing = false;
    }
    pub fn revocation_handle(&self) -> RevocationHandle {
        self.authority.handle()
    }
    pub fn lock_with_receipt(&mut self) -> RevocationReceipt {
        let receipt = self.authority.handle().revoke();
        self.lock();
        receipt
    }
    /// Register externally pending work without granting read/unlock authority.
    pub fn begin_host_work(&self) -> Result<WorkGuard> {
        self.raw_keys()?;
        self.authority.work()
    }
    pub fn phase(&self) -> Phase {
        if self.keys.is_none() || self.authority.is_revoked() {
            Phase::Locked
        } else if self.initializing {
            Phase::Initializing
        } else if self.audit.is_some() {
            Phase::Auditing
        } else if self.recovery_candidate {
            Phase::Recovery
        } else if self.session.is_none() {
            Phase::Unlocking
        } else if self.is_uncertain() {
            Phase::Uncertain
        } else if self.pending.is_some() {
            Phase::Prepared
        } else {
            Phase::Ready
        }
    }
    /// Trusted host admission policy; contains no derived keys or credentials.
    pub fn kdf_policy(&self) -> &KdfPolicy {
        &self.kdf_policy
    }
    pub fn kdf_profile(&self) -> KdfProfile {
        self.descriptor.kdf_profile()
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
            && self.keys.is_some()
            && !self.authority.is_revoked()
            && !self.recovery_candidate
    }
    pub fn is_uncertain(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| p.unknown)
    }
    pub fn is_recovery_candidate(&self) -> bool {
        self.recovery_candidate && self.keys.is_some() && !self.authority.is_revoked()
    }
    pub fn generation(&self) -> Option<u64> {
        self.session.map(|_| self.head.generation)
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.descriptor.vault_id
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        self.descriptor.bytes()
    }
    pub fn envelope_byte_limit(&self) -> Result<usize> {
        self.descriptor.envelope_limit(self.limits)
    }
    pub fn content_format(&self) -> u16 {
        self.descriptor.format_id()
    }
    pub fn descriptor_byte_limit(&self) -> usize {
        let accepted = self
            .access_admission
            .as_ref()
            .map_or(format::DESCRIPTOR_LEN, |policy| policy.max_descriptor_bytes);
        // A staged target may require a larger header read for exact outcome
        // reconciliation. This admits only its known width, not its proposed
        // profiles/providers, and disappears on a known abort.
        self.pending
            .as_ref()
            .and_then(|pending| pending.descriptor.as_ref())
            .map_or(accepted, |descriptor| {
                accepted.max(descriptor.bytes().len())
            })
    }
    pub fn head_bytes(&self) -> &[u8] {
        &self.head_bytes
    }
    pub fn latest_request(&self) -> [u8; 16] {
        self.head.request_id
    }
    pub fn pending_request(&self) -> Option<[u8; 16]> {
        self.pending.as_ref().map(|p| p.head.request_id)
    }
    pub fn current_session(&self) -> Result<SessionToken> {
        if self.authority.is_revoked() || self.recovery_candidate {
            return Err(Error::Locked);
        }
        self.session.ok_or(Error::Locked)
    }
    pub fn check_session(&self, token: &SessionToken) -> Result<()> {
        if self.current_session()? != *token {
            Err(Error::StaleSession)
        } else {
            Ok(())
        }
    }
    pub fn token_bytes(&self, token: &SessionToken) -> Result<[u8; 16]> {
        self.check_session(token)?;
        Ok(token.nonce)
    }
    pub fn session_from_bytes(&self, nonce: [u8; 16]) -> Result<SessionToken> {
        let token = SessionToken {
            vault_id: self.vault_id(),
            nonce,
        };
        self.check_session(&token)?;
        Ok(token)
    }
    fn raw_keys(&self) -> Result<&Keys> {
        if self.authority.is_revoked() {
            return Err(Error::Locked);
        }
        self.keys.as_ref().ok_or(Error::Locked)
    }
    fn ensure_known_outcome(&self) -> Result<()> {
        if let Some(pending) = &self.pending {
            if pending.unknown {
                return Err(Error::OutcomeUnknown {
                    request_id: pending.head.request_id,
                });
            }
        }
        Ok(())
    }
    fn operation_keys(&self) -> Result<&Keys> {
        let keys = self.raw_keys()?;
        self.current_session()?;
        self.ensure_known_outcome()?;
        if self.audit.is_some() {
            return Err(Error::Conflict);
        }
        Ok(keys)
    }
    fn receipt(head: &IndexHead, bytes: &[u8]) -> CommitReceipt {
        CommitReceipt {
            generation: head.generation,
            request_id: head.request_id,
            head_digest: crypto::digest(bytes),
        }
    }
    pub fn current_receipt(&self) -> Result<CommitReceipt> {
        self.operation_keys()?;
        Ok(Self::receipt(&self.head, &self.head_bytes))
    }
    pub fn check_snapshot(&self, descriptor: &[u8], head: &[u8]) -> Result<()> {
        let keys = self.operation_keys()?;
        if descriptor != self.descriptor_bytes() {
            return Err(Error::Integrity);
        }
        IndexHead::parse(head, &self.descriptor, &keys.head, self.limits)?;
        if head != self.head_bytes() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Validate the audited source for a credential-only recovery repair. This
    /// grants no record-read or normal-session authority.
    pub fn check_credential_snapshot(&self, descriptor: &[u8], head: &[u8]) -> Result<()> {
        if !self.recovery_candidate {
            return self.check_snapshot(descriptor, head);
        }
        let keys = self.raw_keys()?;
        if self.session.is_none() || self.audit.is_some() {
            return Err(Error::Conflict);
        }
        if let Some(pending) = &self.pending {
            if pending.unknown {
                return Err(Error::OutcomeUnknown {
                    request_id: pending.head.request_id,
                });
            }
        }
        if descriptor != self.descriptor_bytes() {
            return Err(Error::Integrity);
        }
        IndexHead::parse(head, &self.descriptor, &keys.head, self.limits)?;
        if head != self.head_bytes() {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn start_audit(&mut self, bytes: &[u8], purpose: Purpose) -> Result<()> {
        self.start_audit_with_descriptor(bytes, self.descriptor.clone(), purpose, None)
    }
    fn start_audit_with_descriptor(
        &mut self,
        bytes: &[u8],
        descriptor: Descriptor,
        purpose: Purpose,
        replacement_session: Option<SessionToken>,
    ) -> Result<()> {
        if self.audit.is_some() || self.initializing {
            return Err(Error::Conflict);
        }
        let head = IndexHead::parse(bytes, &descriptor, &self.raw_keys()?.head, self.limits)?;
        let maximum = head
            .count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        self.audit = Some(Audit {
            cursor: index::AuditCursor::new(head.root, maximum),
            head,
            bytes: bytes.to_vec(),
            record: None,
            checked: 0,
            finished: false,
            purpose,
            descriptor,
            replacement_session,
        });
        Ok(())
    }
    pub fn begin_audit(&mut self, head: &[u8]) -> Result<()> {
        self.raw_keys()?;
        self.ensure_known_outcome()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let purpose = if self.session.is_some() {
            if head != self.head_bytes() {
                return Err(Error::Conflict);
            }
            Purpose::Current
        } else {
            Purpose::Unlock
        };
        self.start_audit(head, purpose)
    }
    pub fn begin_reconcile(&mut self, head: &[u8], request: [u8; 16]) -> Result<()> {
        let descriptor = self.descriptor_bytes().to_vec();
        self.begin_reconcile_snapshot(&descriptor, head, request)
    }
    pub fn begin_reconcile_snapshot(
        &mut self,
        descriptor_bytes: &[u8],
        head: &[u8],
        request: [u8; 16],
    ) -> Result<()> {
        self.raw_keys()?;
        if self.recovery_candidate {
            if self.session.is_none()
                || self
                    .pending
                    .as_ref()
                    .is_none_or(|pending| pending.replacement_session.is_none())
            {
                return Err(Error::Locked);
            }
        } else {
            self.current_session()?;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.head.request_id != request)
        {
            return Err(Error::Conflict);
        }
        // A valid source snapshot is not corruption, but hostile storage may
        // replay it after a real commit. It cannot prove NotCommitted or clear
        // uncertainty. Keep both the pending plan and publication barrier.
        if let Some(pending) = &self.pending {
            if pending.unknown
                && pending.head.request_id == request
                && self.descriptor_bytes() == descriptor_bytes
                && self.head_bytes() == head
            {
                IndexHead::parse(head, &self.descriptor, &self.raw_keys()?.head, self.limits)?;
                return Err(Error::OutcomeUnknown {
                    request_id: request,
                });
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.protective)
        {
            // The target uses fresh keys. Reconcile it through a separately
            // authenticated target Engine and the durable control-state protocol.
            return Err(Error::UnsupportedCapability);
        }
        let (descriptor, replacement_session) = if let Some(p) = &self.pending {
            let expected = p.descriptor.as_ref().unwrap_or(&self.descriptor);
            if expected.bytes() != descriptor_bytes {
                return Err(Error::Integrity);
            }
            (expected.clone(), p.replacement_session)
        } else {
            if self.descriptor_bytes() != descriptor_bytes {
                return Err(Error::Integrity);
            }
            (self.descriptor.clone(), None)
        };
        let parsed = IndexHead::parse(head, &descriptor, &self.raw_keys()?.head, self.limits)?;
        if parsed.request_id != request {
            return Err(Error::NotFound);
        }
        if let Some(p) = &self.pending {
            if !p.unknown || p.head.request_id != request || p.bytes != head {
                return Err(Error::Conflict);
            }
        }
        if self.pending.is_none() && self.head_bytes() != head {
            return Err(Error::Conflict);
        }
        self.start_audit_with_descriptor(head, descriptor, Purpose::Reconcile, replacement_session)
    }
    pub fn audit_next(&self) -> Result<AuditRequest> {
        self.raw_keys()?;
        let audit = self.audit.as_ref().ok_or(Error::Conflict)?;
        if let Some((id, entry)) = &audit.record {
            Ok(AuditRequest::Record {
                id: *id,
                entry: entry.clone(),
            })
        } else if let Some(hash) = audit.cursor.next_hash()? {
            Ok(AuditRequest::Node(hash))
        } else {
            Ok(AuditRequest::Done)
        }
    }
    pub fn supply_node(&mut self, bytes: &[u8]) -> Result<()> {
        self.raw_keys()?;
        let audit = self.audit.as_mut().ok_or(Error::Conflict)?;
        if audit.finished || audit.record.is_some() {
            return Err(Error::Conflict);
        }
        audit.record = audit.cursor.supply(bytes)?;
        Ok(())
    }
    pub fn supply_record(
        &mut self,
        revision: u64,
        length: u64,
        envelope: Option<&[u8]>,
    ) -> Result<()> {
        self.raw_keys()?;
        let maximum = self
            .audit
            .as_ref()
            .ok_or(Error::Conflict)?
            .descriptor
            .envelope_limit(self.limits)? as u64;
        let audit = self.audit.as_mut().ok_or(Error::Conflict)?;
        let (_, entry) = audit.record.as_ref().ok_or(Error::Conflict)?;
        if audit.finished
            || entry.revision != revision
            || length < audit.descriptor.envelope_minimum() as u64
            || length > maximum
        {
            return Err(Error::Integrity);
        }
        if let Some(body) = envelope {
            if body.len() as u64 != length || crypto::digest(body) != entry.digest {
                return Err(Error::Integrity);
            }
        }
        audit.checked = audit.checked.checked_add(1).ok_or(Error::ResourceLimit)?;
        if audit.checked > audit.head.count {
            return Err(Error::Integrity);
        }
        audit.record = None;
        Ok(())
    }
    pub fn finish_audit(&mut self, record_count: u64, node_count: u64) -> Result<AuditMetrics> {
        self.raw_keys()?;
        let audit = self.audit.as_mut().ok_or(Error::Conflict)?;
        let stats = audit.cursor.finish()?;
        let expected = audit
            .head
            .count
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .unwrap_or(0);
        if audit.record.is_some()
            || audit.checked != audit.head.count
            || record_count != audit.head.count
            || node_count != expected
            || stats.nodes_read != expected
        {
            return Err(Error::Integrity);
        }
        audit.finished = true;
        Ok(AuditMetrics {
            nodes_read: stats.nodes_read,
            records_checked: audit.checked,
            node_bytes: stats.bytes_read,
            peak_buffered_nodes: audit.cursor.peak_buffered_nodes(),
            peak_path_nodes: stats.peak_path_nodes,
        })
    }
    pub fn activate_audit(&mut self) -> Result<CommitReceipt> {
        self.raw_keys()?;
        let audit = self.audit.as_ref().ok_or(Error::Conflict)?;
        if !audit.finished {
            return Err(Error::Conflict);
        }
        let token = if let Some(replacement) = audit.replacement_session {
            Some(replacement)
        } else if self.session.is_none() {
            Some(SessionToken {
                vault_id: self.vault_id(),
                nonce: crypto::random()?,
            })
        } else {
            self.session
        };
        let audit = self.audit.take().ok_or(Error::Conflict)?;
        if matches!(audit.purpose, Purpose::Reconcile) {
            if let Some(admission) = self
                .pending
                .as_mut()
                .and_then(|p| p.access_admission.take())
            {
                self.access_admission = Some(admission);
            }
            self.pending = None;
            if audit.replacement_session.is_some() {
                self.recovery_candidate = false;
            }
        }
        self.descriptor = audit.descriptor;
        self.head = audit.head;
        self.head_bytes = audit.bytes;
        self.session = token;
        Ok(Self::receipt(&self.head, &self.head_bytes))
    }
    pub fn abort_audit(&mut self) {
        self.audit = None;
    }
    pub fn lookup<S: NodeStore + ?Sized>(
        &self,
        store: &mut S,
        id: &RecordId,
    ) -> Result<VerifiedLookup> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        let session = self.current_session()?;
        let head_digest = crypto::digest(&self.head_bytes);
        let found = index::lookup(store, self.head.root, id)?;
        Ok(VerifiedLookup {
            id: *id,
            session,
            head_digest,
            entry: found.entry.map(|entry| VerifiedRecord {
                id: *id,
                entry,
                session,
                head_digest,
            }),
            stats: found.stats,
        })
    }
    fn check_proof(&self, proof: &VerifiedRecord) -> Result<()> {
        self.operation_keys()?;
        self.check_session(&proof.session)?;
        if proof.head_digest != crypto::digest(&self.head_bytes) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn verify_record(
        &self,
        proof: &VerifiedRecord,
        stored_revision: u64,
        envelope: &[u8],
    ) -> Result<u64> {
        self.check_proof(proof)?;
        if stored_revision != proof.entry.revision
            || envelope.len() < self.descriptor.envelope_minimum()
            || envelope.len() > self.descriptor.envelope_limit(self.limits)?
            || crypto::digest(envelope) != proof.entry.digest
        {
            return Err(Error::Integrity);
        }
        Ok(stored_revision)
    }
    pub fn read_verified(
        &self,
        proof: &VerifiedRecord,
        stored_revision: u64,
        envelope: &[u8],
    ) -> Result<SecretRecord> {
        let keys = self.operation_keys()?;
        let work = self.authority.work()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.verify_record(proof, stored_revision, envelope)?;
        let decoded = format::decrypt_record(
            &self.descriptor,
            &keys.wrapping,
            &proof.id,
            proof.entry.revision,
            envelope,
            self.limits,
        )?;
        work.check()?;
        Ok(SecretRecord {
            revision: proof.entry.revision,
            metadata: decoded.metadata,
            payload: decoded.payload,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn draft_save(
        &self,
        id: RecordId,
        expected: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request: [u8; 16],
    ) -> Result<SaveDraft> {
        let keys = self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.limits.validate_record(metadata, payload)?;
        if expected.is_some_and(|revision| revision == 0 || revision >= i64::MAX as u64) {
            return Err(Error::ResourceLimit);
        }
        let revision = expected
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        let input = format::operation_input(&id, expected, metadata, payload)?;
        let operation_digest = crypto::mac(&keys.operation, &input);
        let envelope = format::encrypt_record(
            &self.descriptor,
            &keys.wrapping,
            &id,
            revision,
            metadata,
            payload,
            self.limits,
        )?;
        Ok(SaveDraft {
            id,
            expected,
            revision,
            request,
            operation_digest,
            envelope,
            session: self.current_session()?,
            head_digest: crypto::digest(&self.head_bytes),
        })
    }
    pub fn stage_save<S: NodeStore + ?Sized>(
        &mut self,
        draft: &SaveDraft,
        lookup: VerifiedLookup,
        previous: Option<StoredRecord<'_>>,
        store: &mut S,
    ) -> Result<CommitPlan> {
        self.operation_keys()?;
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.check_session(&draft.session)?;
        let digest = crypto::digest(&self.head_bytes);
        if draft.head_digest != digest
            || lookup.head_digest != digest
            || lookup.session != draft.session
            || lookup.id != draft.id
        {
            return Err(Error::Conflict);
        }
        let found = lookup.entry.as_ref();
        if self.head.request_id == draft.request {
            if !crypto::tags_match(&self.head.operation_digest, &draft.operation_digest) {
                return Err(Error::OperationIdReuse);
            }
            let proof = found.ok_or(Error::Integrity)?;
            let old = previous.ok_or(Error::Integrity)?;
            if proof.revision() != draft.revision {
                return Err(Error::Integrity);
            }
            self.verify_record(proof, old.revision, old.envelope)?;
            return Ok(CommitPlan {
                replay: true,
                receipt: Self::receipt(&self.head, &self.head_bytes),
                prior_head: self.head_bytes.clone(),
                head_bytes: self.head_bytes.clone(),
                envelope: Vec::new(),
                id: draft.id,
                revision: draft.revision,
                obsolete: Vec::new(),
                stats: IndexStats::default(),
            });
        }
        if found.map(|proof| proof.revision()) != draft.expected {
            return Err(Error::Conflict);
        }
        match (found, previous) {
            (Some(proof), Some(old)) => {
                self.verify_record(proof, old.revision, old.envelope)?;
            }
            (None, None) => {}
            _ => return Err(Error::Integrity),
        }
        let mut head = self.head.clone();
        if found.is_none() {
            if head.count >= self.limits.max_records as u64 {
                return Err(Error::ResourceLimit);
            }
            head.count = head.count.checked_add(1).ok_or(Error::ResourceLimit)?;
        }
        let change = index::upsert(
            store,
            self.head.root,
            draft.id,
            Entry {
                revision: draft.revision,
                digest: crypto::digest(&draft.envelope),
            },
        )?;
        if change.previous != found.map(|proof| proof.entry.clone()) {
            return Err(Error::Integrity);
        }
        head.generation = head.generation.checked_add(1).ok_or(Error::ResourceLimit)?;
        head.request_id = draft.request;
        head.operation_digest = draft.operation_digest;
        head.root = Some(change.root);
        let bytes = head.encode(&self.descriptor, &self.raw_keys()?.head);
        let receipt = Self::receipt(&head, &bytes);
        let plan = CommitPlan {
            replay: false,
            receipt,
            prior_head: self.head_bytes.clone(),
            head_bytes: bytes.clone(),
            envelope: draft.envelope.clone(),
            id: draft.id,
            revision: draft.revision,
            obsolete: change.obsolete,
            stats: change.stats,
        };
        self.pending = Some(Pending {
            head,
            bytes,
            unknown: false,
            descriptor: None,
            replacement_session: None,
            access_admission: None,
            protective: false,
            ordinary_binding: Some(control::bind_save(&plan)?),
        });
        Ok(plan)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_save<S: NodeStore + ?Sized>(
        &mut self,
        store: &mut S,
        id: RecordId,
        expected: Option<u64>,
        metadata: &[u8],
        payload: &[u8],
        request: [u8; 16],
        previous: Option<StoredRecord<'_>>,
    ) -> Result<CommitPlan> {
        let draft = self.draft_save(id, expected, metadata, payload, request)?;
        let lookup = self.lookup(store, &id)?;
        self.stage_save(&draft, lookup, previous, store)
    }
    pub fn confirm_commit(&mut self, head: &[u8]) -> Result<CommitReceipt> {
        self.operation_keys()?;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.descriptor.is_some())
        {
            return Err(Error::Conflict);
        }
        let pending = self.pending.take().ok_or(Error::Conflict)?;
        if pending.bytes != head {
            self.pending = Some(pending);
            return Err(Error::Integrity);
        }
        self.head = pending.head;
        self.head_bytes = pending.bytes;
        Ok(Self::receipt(&self.head, &self.head_bytes))
    }
    pub fn mark_unknown(&mut self) -> Result<()> {
        let pending = self.pending.as_mut().ok_or(Error::Conflict)?;
        pending.unknown = true;
        Ok(())
    }
    pub fn abort_prepared(&mut self) -> Result<()> {
        if self.recovery_candidate {
            self.raw_keys()?;
            self.ensure_known_outcome()?;
        } else {
            self.operation_keys()?;
        }
        self.pending = None;
        Ok(())
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.lock();
    }
}
