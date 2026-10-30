//! Provisional, reversible workspace API for the synthetic browser workflow.
//!
//! Callers supply findings and fresh public random IDs. The host owns credentials,
//! encryption, approval and durable storage; activating a candidate trusts that host.
mod codec;
mod conversation;
pub use conversation::{
    Conversation, ConversationInput, ConversationState, SendIntentId, SendStatus,
};
mod operations;
pub use operations::{
    MAX_OPERATION_TIME_MS, MAX_OPERATIONS, MAX_ORDINARY_OPERATIONS, OperationContext,
    OperationCounts, OperationHistoryCoverage, OperationKind, OperationOutcome, OperationPage,
    OperationRecord, OutcomeKind, PreUpgradeHistory, RESERVED_RECOVERY_OPERATIONS,
};
mod policy;
pub use policy::{
    ChoiceDisposition, ChoiceEditPreview, ChoiceView, MAX_POLICY_EDITS, MAX_POLICY_ITEMS,
    PolicyEdits, PolicyPreview, PolicyView, RuleEditPreview, RuleView, TypeRule, TypeRuleEdit,
    ValueChoiceEdit, protected_type,
};
mod buffered_restore;
pub use buffered_restore::{BufferedRestore, RestoreEncoding};
mod private_bytes;
mod progressive_restore;
pub use progressive_restore::{ProgressiveRestore, RestoreChunk, RestoreProgress, StreamFailure};
mod recall;
mod review;
pub use review::{
    ReviewCandidate, ReviewConflict, ReviewConflictKind, ReviewCorrection, ReviewInput,
    ReviewResult,
};

pub use recall::{RecallFinding, RecallResult};

use crate::{Finding, TextIndex, TextRange, TransformationConfig, TransformationStrategy};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_FINDINGS: usize = 10_000;
pub const MAX_INPUTS: usize = 32;
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
/// Entity type labels are uppercase ASCII and appear verbatim inside markers.
pub const MAX_LABEL_BYTES: usize = 32;
/// Markers are `[[LABEL_CODE]]` with a random Crockford base32 code of this length.
pub const MARKER_CODE_LENGTH: usize = 6;
pub type PublicId = [u8; 16];

/// Complete optimistic-concurrency identity, not an authorization credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub revision: u64,
    pub commit_id: PublicId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    ClosedWorkspace,
    InactivePlan,
    WorkspaceConflict,
    InvalidFinding,
    InvalidEncoding,
    InactiveStream,
    ReviewConflict,
    InvalidBatch,
    InvalidMarker,
    InvalidSnapshot,
    InvalidId,
    InvalidPolicy,
    ResourceLimit,
    InvalidOperation,
    OperationReused,
    InvalidConversation,
    ConversationUnknown,
    ConversationPending,
    InvalidSendIntent,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClosedWorkspace => "closed_workspace",
            Self::InactivePlan => "inactive_plan",
            Self::WorkspaceConflict => "workspace_conflict",
            Self::InvalidFinding => "invalid_finding",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InactiveStream => "inactive_stream",
            Self::ReviewConflict => "review_conflict",
            Self::InvalidBatch => "invalid_batch",
            Self::InvalidMarker => "invalid_marker",
            Self::InvalidSnapshot => "invalid_snapshot",
            Self::InvalidId => "invalid_operation_id",
            Self::InvalidPolicy => "invalid_policy",
            Self::ResourceLimit => "resource_limit",
            Self::InvalidOperation => "invalid_operation",
            Self::OperationReused => "operation_reused",
            Self::InvalidConversation => "invalid_conversation",
            Self::ConversationUnknown => "conversation_unknown",
            Self::ConversationPending => "conversation_pending",
            Self::InvalidSendIntent => "invalid_send_intent",
        }
    }
}

/// Content-free failure. Input indexes identify batch members; finding indexes are input-local.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceError {
    pub code: ErrorCode,
    pub finding_index: Option<usize>,
    pub input_index: Option<usize>,
    /// Content-free source spans that block preparation.
    pub marker_issues: Vec<MarkerIssue>,
    pub review_conflicts: Vec<ReviewConflict>,
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code.as_str())
    }
}
impl std::error::Error for WorkspaceError {}
fn error(code: ErrorCode) -> WorkspaceError {
    WorkspaceError {
        code,
        finding_index: None,
        input_index: None,
        marker_issues: Vec::new(),
        review_conflicts: Vec::new(),
    }
}
type Result<T> = std::result::Result<T, WorkspaceError>;

/// Caller-declared origin for review display, not authorization or proof of detection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    #[default]
    Scanner,
    Recall,
    User,
}

impl FindingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::Recall => "recall",
            Self::User => "user",
        }
    }
}

/// Omitted review metadata conservatively requests review; approval is always host-owned.
pub const DEFAULT_NEEDS_REVIEW: bool = true;

/// Exact source span in UTF-8 bytes. Review metadata is never persisted.
#[derive(Clone)]
pub struct WorkspaceFinding {
    pub entity_type: String,
    pub matched_text: String,
    pub byte_range: TextRange,
    pub confidence: Option<f32>,
    pub detector_name: Option<String>,
    pub detector_version: Option<String>,
    pub source: FindingSource,
    pub needs_review: bool,
}

impl WorkspaceFinding {
    pub fn new(
        entity_type: impl Into<String>,
        matched_text: impl Into<String>,
        byte_range: TextRange,
    ) -> Self {
        Self {
            entity_type: entity_type.into(),
            matched_text: matched_text.into(),
            byte_range,
            confidence: None,
            detector_name: None,
            detector_version: None,
            source: FindingSource::default(),
            needs_review: DEFAULT_NEEDS_REVIEW,
        }
    }
}

/// One batch member. Ranges are local to this input; order is preserved in previews.
#[derive(Clone, Copy)]
pub struct WorkspaceInput<'a> {
    pub text: &'a str,
    pub findings: &'a [WorkspaceFinding],
}

/// A transformed span, with explicit zero-based, end-exclusive coordinate systems.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transformation {
    pub source: FindingSource,
    pub needs_review: bool,
    pub source_byte_range: TextRange,
    pub source_codepoint_range: TextRange,
    pub source_utf16_range: TextRange,
    pub output_byte_range: TextRange,
    pub output_codepoint_range: TextRange,
    pub output_utf16_range: TextRange,
}

pub struct Preview {
    pub text: String,
    pub transformations: Vec<Transformation>,
}
impl Drop for Preview {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// Why a span in model output did not restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerIssueKind {
    /// Well-formed marker that this workspace never committed: a wrong label, a code
    /// the model made up, one from another workspace, or one lost since a backup.
    Unknown,
    /// `[[...]]` span shaped like a marker that does not parse, e.g. a shortened code.
    Damaged,
    /// A committed `LABEL_CODE` whose surrounding brackets were dropped.
    Unbracketed,
    NotIssuedInConversation,
}
impl MarkerIssueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Damaged => "damaged",
            Self::Unbracketed => "unbracketed",
            Self::NotIssuedInConversation => "not_issued_in_conversation",
        }
    }
}

/// Content-free offsets of a source or output marker issue; no source or restored value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkerIssue {
    pub kind: MarkerIssueKind,
    pub byte_range: TextRange,
    pub codepoint_range: TextRange,
    pub utf16_range: TextRange,
}

/// `text` is present only when every marker resolved and no issue was found.
pub struct RestoreReport {
    pub text: Option<String>,
    pub restored_markers: usize,
    pub issues: Vec<MarkerIssue>,
}
impl Drop for RestoreReport {
    fn drop(&mut self) {
        if let Some(text) = self.text.as_mut() {
            text.zeroize();
        }
    }
}

/// Values of one type that differ only in letter case or spacing share an identity,
/// so `JOHN SMITH` in one paste and `John  Smith` in the next get one marker.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    entity_type: String,
    key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
/// `display` is the first spelling seen and is what restoration returns.
/// `code` is canonical uppercase Crockford base32 and unique within the workspace.
/// `issuance` records the operation that created the entry; it never leaves the vault.
#[derive(Clone)]
struct Entry {
    display: String,
    code: String,
    issuance: PublicId,
    counter: u64,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.display.zeroize();
    }
}

/// Derive the normalized identity key for workspace lookup.
///
/// Uses [`str::split_whitespace`], which recognizes Unicode whitespace including
/// NBSP (U+00A0) and tabs, so leading/trailing spaces, NBSP and multiple interior
/// spaces all collapse. Uses [`char::to_lowercase`] for Unicode-aware lowercasing:
/// `ß` stays `ß` (not `ss`), and Turkish `İ` maps to `i` + combining dot.
///
/// This means values that differ only in case, spacing type or whitespace amount
/// share one entry. The stored `display` is the first spelling seen (ADR 004
/// lines 73–74: "the first spelling seen is stored and restored"), untrimmed.
fn identity_key(value: &str) -> String {
    let mut key = String::with_capacity(value.len());
    for word in value.split_whitespace() {
        if !key.is_empty() {
            key.push(' ');
        }
        key.extend(word.chars().flat_map(char::to_lowercase));
    }
    key
}
#[derive(Clone)]
struct State {
    conversations: conversation::Conversations,
    snapshot_version: u8,
    operations: Vec<OperationRecord>,
    operation_counts: OperationCounts,
    rules: BTreeMap<String, policy::RuleRecord>,
    choices: BTreeMap<Identity, policy::ChoiceRecord>,
    namespace: PublicId,
    head: Head,
    entries: BTreeMap<Identity, Entry>,
    counters: BTreeMap<String, u64>,
}

struct Pending {
    lifetime: Arc<AtomicBool>,
    parent: Head,
    parent_snapshot_version: u8,
    candidate: State,
    bundle: Zeroizing<Vec<u8>>,
    previews: Vec<Preview>,
    policy_preview: Option<PolicyPreview>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotFormat {
    pub current_version: u8,
    pub candidate_version: u8,
}

/// An immutable pending change. Preview/export do not consume it; activation or discard do.
pub struct PreparedChange {
    pending: Option<Pending>,
}
impl PreparedChange {
    fn pending(&self) -> Result<&Pending> {
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InactivePlan))?;
        if !pending.lifetime.load(Ordering::Acquire) {
            return Err(error(ErrorCode::ClosedWorkspace));
        }
        Ok(pending)
    }
    /// Single-input convenience; use `previews` for a multi-input plan.
    pub fn preview(&self) -> Result<&Preview> {
        match self.previews()? {
            [preview] => Ok(preview),
            _ => Err(error(ErrorCode::InvalidBatch)),
        }
    }
    pub fn snapshot_format(&self) -> Result<SnapshotFormat> {
        let pending = self.pending()?;
        Ok(SnapshotFormat {
            current_version: pending.parent_snapshot_version,
            candidate_version: pending.candidate.snapshot_version,
        })
    }
    pub fn policy_preview(&self) -> Result<Option<&PolicyPreview>> {
        Ok(self.pending()?.policy_preview.as_ref())
    }
    pub fn previews(&self) -> Result<&[Preview]> {
        Ok(&self.pending()?.previews)
    }
    pub fn expected_head(&self) -> Result<Head> {
        Ok(self.pending()?.parent)
    }
    pub fn candidate_head(&self) -> Result<Head> {
        Ok(self.pending()?.candidate.head)
    }
    /// Sensitive plaintext bytes for the trusted encrypting host only.
    pub fn export_candidate_bundle(&self) -> Result<&[u8]> {
        Ok(&self.pending()?.bundle)
    }
    pub fn discard(&mut self) {
        self.pending = None;
    }
}

/// One runtime workspace. Closing it never deletes its saved bundle.
pub struct Workspace {
    state: Option<Arc<State>>,
    lifetime: Arc<AtomicBool>,
    read_epoch: Arc<AtomicBool>,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.close();
    }
}
impl Workspace {
    fn from_state(state: State) -> Result<Self> {
        Ok(Self {
            state: Some(Arc::new(state)),
            lifetime: Arc::new(AtomicBool::new(true)),
            read_epoch: Arc::new(AtomicBool::new(true)),
        })
    }
    fn state(&self) -> Result<&State> {
        self.state
            .as_deref()
            .ok_or_else(|| error(ErrorCode::ClosedWorkspace))
    }
    /// IDs must come from the host OS CSPRNG. Shape checks cannot prove entropy.
    pub fn create(namespace: PublicId, operation_id: PublicId) -> Result<Self> {
        let operations = vec![OperationRecord {
            id: operation_id,
            kind: OperationKind::Create,
            occurred_at_ms: None,
            prepared_inputs: 0,
            transformed_spans: 0,
        }];
        Self::from_state(State {
            conversations: conversation::Conversations::default(),
            snapshot_version: 3,
            operation_counts: operations::summarize(&operations)?,
            operations,
            rules: BTreeMap::new(),
            choices: BTreeMap::new(),
            namespace,
            head: Head {
                revision: 0,
                commit_id: operation_id,
            },
            entries: BTreeMap::new(),
            counters: BTreeMap::new(),
        })
    }
    pub fn open_bundle(bytes: &[u8]) -> Result<Self> {
        Self::from_state(codec::decode(bytes)?)
    }
    pub fn export_bundle(&self) -> Result<Vec<u8>> {
        codec::encode(self.state()?)
    }
    pub fn head(&self) -> Result<Head> {
        Ok(self.state()?.head)
    }
    pub fn namespace(&self) -> Result<PublicId> {
        Ok(self.state()?.namespace)
    }
    pub fn close(&mut self) {
        self.lifetime.store(false, Ordering::Release);
        self.state = None;
    }

    /// Buffer chunks against this committed head, returning no text before finalization.
    /// This atomic adapter is not a progressive live-restoration API.
    pub fn buffered_restore(&self, encoding: RestoreEncoding) -> Result<BufferedRestore> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| error(ErrorCode::ClosedWorkspace))?;
        Ok(BufferedRestore::new(
            Arc::clone(state),
            Arc::clone(&self.lifetime),
            Arc::clone(&self.read_epoch),
            encoding,
            None,
        ))
    }

    /// Opt in to irreversible chunk delivery. A later error marks the response
    /// incomplete; text returned by earlier calls cannot be retracted.
    pub fn progressive_restore(&self, encoding: RestoreEncoding) -> Result<ProgressiveRestore> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| error(ErrorCode::ClosedWorkspace))?;
        ProgressiveRestore::new(
            Arc::clone(state),
            Arc::clone(&self.lifetime),
            Arc::clone(&self.read_epoch),
            encoding,
            None,
        )
    }

    /// Find committed values without allocating aliases or changing the saved head.
    /// Returns all overlapping matches in original-input coordinates, not a clean-text verdict.
    pub fn recall(&self, text: &str) -> Result<RecallResult> {
        recall::find(self.state()?, text)
    }

    /// Combine caller scanner/manual findings with committed recall. This read-only
    /// result grants no handoff permission and never creates a plan or saved alias.
    pub fn review(&self, input: ReviewInput<'_>) -> Result<ReviewResult> {
        review::build(self.state()?, input)
    }

    /// Recompute combined review, then stage one atomic batch only if every input
    /// preserves protected coverage. Approval and durable save are still required.
    pub fn prepare_review(
        &self,
        inputs: &[ReviewInput<'_>],
        operation_id: PublicId,
    ) -> Result<PreparedChange> {
        self.prepare_review_internal(inputs, operation_id, None, false)
    }
    fn prepare_review_internal(
        &self,
        inputs: &[ReviewInput<'_>],
        operation_id: PublicId,
        occurred_at_ms: Option<u64>,
        explicit: bool,
    ) -> Result<PreparedChange> {
        if inputs.is_empty() {
            return Err(error(ErrorCode::InvalidBatch));
        }
        if inputs.len() > MAX_INPUTS {
            return Err(error(ErrorCode::ResourceLimit));
        }
        let mut total_bytes = 0usize;
        let mut total_findings = 0usize;
        let mut finding_bytes = 0usize;
        let mut reviewed = Vec::with_capacity(inputs.len());
        for (input_index, input) in inputs.iter().enumerate() {
            let result = (|| {
                total_bytes = total_bytes.saturating_add(input.text.len());
                total_findings = total_findings
                    .saturating_add(input.scanner_findings.len())
                    .saturating_add(input.user_selections.len())
                    .saturating_add(input.corrections.len());
                if total_bytes > MAX_SOURCE_BYTES || total_findings > MAX_FINDINGS {
                    return Err(error(ErrorCode::ResourceLimit));
                }
                let result = self.review(*input)?;
                total_findings =
                    total_findings.saturating_add(result.finding_count.saturating_sub(
                        input.scanner_findings.len()
                            + input.user_selections.len()
                            + input.corrections.len(),
                    ));
                finding_bytes = finding_bytes.saturating_add(result.finding_bytes);
                if total_findings > MAX_FINDINGS || finding_bytes > MAX_BUNDLE_BYTES {
                    return Err(error(ErrorCode::ResourceLimit));
                }
                if !result.conflicts.is_empty() {
                    let mut failure = error(ErrorCode::ReviewConflict);
                    failure.finding_index = result
                        .conflicts
                        .first()
                        .map(|conflict| conflict.finding_index);
                    failure.review_conflicts = result.conflicts;
                    return Err(failure);
                }
                Ok(result
                    .candidates
                    .into_iter()
                    .filter(|candidate| candidate.selected)
                    .map(|candidate| candidate.finding)
                    .collect::<Vec<_>>())
            })()
            .map_err(|mut failure| {
                failure.input_index = Some(input_index);
                failure
            })?;
            reviewed.push(result);
        }
        let borrowed: Vec<_> = inputs
            .iter()
            .zip(&reviewed)
            .map(|(input, findings)| WorkspaceInput {
                text: input.text,
                findings,
            })
            .collect();
        self.prepare_batch_internal(&borrowed, operation_id, occurred_at_ms, explicit)
    }

    /// Stage recovery of this validated bundle under a fresh commit head.
    /// Issued markers, counters and privacy configuration retain their saved meaning.
    /// The host must reject destination conflicts and durably save before activation.
    /// Recovery has no text previews and grants no permission to release content.
    pub fn prepare_recovery(&self, operation_id: PublicId) -> Result<PreparedChange> {
        self.prepare_recovery_internal(operation_id, None, true)
    }
    fn prepare_recovery_internal(
        &self,
        operation_id: PublicId,
        occurred_at_ms: Option<u64>,
        legacy: bool,
    ) -> Result<PreparedChange> {
        let state = self.state()?;
        state.validate_operation_id(operation_id, legacy)?;
        state.admit_record(true)?;
        let mut candidate = state.clone();
        candidate.head = Head {
            revision: state
                .head
                .revision
                .checked_add(1)
                .ok_or_else(|| error(ErrorCode::ResourceLimit))?,
            commit_id: operation_id,
        };
        candidate.record_operation(OperationRecord {
            id: operation_id,
            kind: OperationKind::Recovery,
            occurred_at_ms,
            prepared_inputs: 0,
            transformed_spans: 0,
        })?;
        let bundle = Zeroizing::new(codec::encode_for_record(&candidate, true)?);
        Ok(PreparedChange {
            pending: Some(Pending {
                lifetime: Arc::clone(&self.lifetime),
                parent: state.head,
                parent_snapshot_version: state.snapshot_version,
                candidate,
                bundle,
                previews: Vec::new(),
                policy_preview: None,
            }),
        })
    }

    /// Preserve exact committed markers and transform supplied findings outside them.
    pub fn prepare(
        &self,
        text: &str,
        findings: &[WorkspaceFinding],
        operation_id: PublicId,
    ) -> Result<PreparedChange> {
        self.prepare_batch(&[WorkspaceInput { text, findings }], operation_id)
    }

    /// Prepare all inputs as one immutable change. A failure returns no partial plan.
    /// Size and finding limits apply to the aggregate batch; no inputs are omitted.
    /// Marker references must already be committed before this batch begins.
    pub fn prepare_batch(
        &self,
        inputs: &[WorkspaceInput<'_>],
        operation_id: PublicId,
    ) -> Result<PreparedChange> {
        self.prepare_batch_internal(inputs, operation_id, None, false)
    }
    fn prepare_batch_internal(
        &self,
        inputs: &[WorkspaceInput<'_>],
        operation_id: PublicId,
        occurred_at_ms: Option<u64>,
        explicit: bool,
    ) -> Result<PreparedChange> {
        let state = self.state()?;
        if inputs.is_empty() {
            return Err(error(ErrorCode::InvalidBatch));
        }
        if inputs.len() > MAX_INPUTS {
            return Err(error(ErrorCode::ResourceLimit));
        }
        let mut source_bytes = 0usize;
        let mut finding_count = 0usize;
        for (input_index, input) in inputs.iter().enumerate() {
            source_bytes = source_bytes.saturating_add(input.text.len());
            finding_count = finding_count.saturating_add(input.findings.len());
            if source_bytes > MAX_SOURCE_BYTES || finding_count > MAX_FINDINGS {
                return Err(WorkspaceError {
                    code: ErrorCode::ResourceLimit,
                    input_index: Some(input_index),
                    marker_issues: Vec::new(),
                    review_conflicts: Vec::new(),
                    finding_index: None,
                });
            }
        }
        state.validate_operation_id(operation_id, !explicit)?;
        if explicit {
            state.admit_record(false)?;
        }
        let committed = marker_lookup(state);
        let mut codes: BTreeSet<String> = state.entries.values().map(|e| e.code.clone()).collect();
        let mut candidate = state.clone();
        let mut previews = Vec::with_capacity(inputs.len());
        let mut output_bytes = 0usize;
        for (input_index, input) in inputs.iter().enumerate() {
            let preview = self
                .prepare_input(
                    input.text,
                    input.findings,
                    operation_id,
                    &committed,
                    &mut codes,
                    &mut candidate,
                )
                .map_err(|mut failure| {
                    failure.input_index = Some(input_index);
                    failure
                })?;
            output_bytes = output_bytes.saturating_add(preview.text.len());
            if output_bytes > MAX_BUNDLE_BYTES {
                return Err(WorkspaceError {
                    code: ErrorCode::ResourceLimit,
                    input_index: Some(input_index),
                    marker_issues: Vec::new(),
                    review_conflicts: Vec::new(),
                    finding_index: None,
                });
            }
            previews.push(preview);
        }
        if explicit || candidate.entries.len() != state.entries.len() {
            candidate.head = Head {
                revision: state
                    .head
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error(ErrorCode::ResourceLimit))?,
                commit_id: operation_id,
            };
            candidate.record_operation(OperationRecord {
                id: operation_id,
                kind: OperationKind::Prepare,
                occurred_at_ms,
                prepared_inputs: inputs.len() as u64,
                transformed_spans: previews
                    .iter()
                    .map(|p| p.transformations.len() as u64)
                    .sum(),
            })?;
        }
        let bundle = Zeroizing::new(if candidate.head != state.head {
            codec::encode_for_record(&candidate, false)?
        } else {
            codec::encode(&candidate)?
        });
        Ok(PreparedChange {
            pending: Some(Pending {
                lifetime: Arc::clone(&self.lifetime),
                parent: state.head,
                parent_snapshot_version: state.snapshot_version,
                candidate,
                bundle,
                previews,
                policy_preview: None,
            }),
        })
    }

    fn prepare_input(
        &self,
        text: &str,
        findings: &[WorkspaceFinding],
        operation_id: PublicId,
        committed: &BTreeMap<String, &str>,
        codes: &mut BTreeSet<String>,
        candidate: &mut State,
    ) -> Result<Preview> {
        let (adapted, mut index) = adapt_findings(text, findings, committed)?;
        let (selected, conflicts) = review::select(text, &adapted, candidate, &[], &[])?;
        if !conflicts.is_empty() {
            let mut failure = error(ErrorCode::ReviewConflict);
            failure.finding_index = conflicts.first().map(|conflict| conflict.finding_index);
            failure.review_conflicts = conflicts;
            return Err(failure);
        }
        // Selection keeps one finding per type/range. Recover its original metadata
        // using exact selected fields; equal duplicates retain the first input.
        let mut input_groups: BTreeMap<(&str, usize, usize), Vec<usize>> = BTreeMap::new();
        for (input_index, finding) in adapted.iter().enumerate() {
            input_groups
                .entry((
                    finding.entity_type.as_str(),
                    finding.byte_range.start,
                    finding.byte_range.end,
                ))
                .or_default()
                .push(input_index);
        }
        let mut output = String::new();
        let mut transformations = Vec::with_capacity(selected.len());
        let mut cursor = 0;
        for finding in selected {
            let input_index = input_groups
                .get(&(
                    finding.entity_type.as_str(),
                    finding.byte_range.start,
                    finding.byte_range.end,
                ))
                .and_then(|group| {
                    group.iter().copied().find(|&input_index| {
                        adapted[input_index] == finding
                            && adapted[input_index].confidence.map(f32::to_bits)
                                == finding.confidence.map(f32::to_bits)
                    })
                })
                .ok_or_else(|| error(ErrorCode::InvalidFinding))?;
            let metadata = &findings[input_index];
            let identity = Identity {
                entity_type: finding.entity_type.clone(),
                key: identity_key(&finding.matched_text),
            };
            if !candidate.entries.contains_key(&identity) {
                if candidate.entries.len() >= MAX_ENTRIES {
                    return Err(error(ErrorCode::ResourceLimit));
                }
                let counter = candidate
                    .counters
                    .get(&finding.entity_type)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| error(ErrorCode::ResourceLimit))?;
                let code = issue_code(
                    candidate.namespace,
                    operation_id,
                    &finding.entity_type,
                    counter,
                    codes,
                )?;
                let entry = Entry {
                    display: finding.matched_text.clone(),
                    code,
                    issuance: operation_id,
                    counter,
                };
                candidate
                    .counters
                    .insert(finding.entity_type.clone(), counter);
                candidate.entries.insert(identity.clone(), entry);
            }
            let entry = candidate
                .entries
                .get(&identity)
                .ok_or_else(|| error(ErrorCode::InvalidSnapshot))?;
            append(&mut output, &text[cursor..finding.byte_range.start])?;
            let output_start = output.len();
            append(&mut output, &marker(&identity.entity_type, &entry.code))?;
            transformations.push(Transformation {
                source: metadata.source,
                needs_review: metadata.needs_review,
                source_byte_range: finding.byte_range,
                source_codepoint_range: finding.codepoint_range,
                source_utf16_range: index
                    .utf16_range(finding.byte_range)
                    .map_err(|_| error(ErrorCode::InvalidFinding))?,
                output_byte_range: TextRange {
                    start: output_start,
                    end: output.len(),
                },
                output_codepoint_range: TextRange { start: 0, end: 0 },
                output_utf16_range: TextRange { start: 0, end: 0 },
            });
            cursor = finding.byte_range.end;
        }
        append(&mut output, &text[cursor..])?;
        let mut output_index = TextIndex::new(&output);
        for transformation in &mut transformations {
            let range = transformation.output_byte_range;
            transformation.output_codepoint_range = TextRange {
                start: output_index.codepoint_offset(range.start),
                end: output_index.codepoint_offset(range.end),
            };
            transformation.output_utf16_range = output_index
                .utf16_range(range)
                .map_err(|_| error(ErrorCode::InvalidFinding))?;
        }
        Ok(Preview {
            text: output,
            transformations,
        })
    }

    /// Adopt an exact saved candidate. The host must first confirm atomic persistence.
    pub fn activate_saved(
        &mut self,
        plan: &mut PreparedChange,
        expected_parent: Head,
        saved_head: Head,
    ) -> Result<()> {
        let state = self.state()?;
        let pending = plan.pending()?;
        if !Arc::ptr_eq(&pending.lifetime, &self.lifetime)
            || state.head != expected_parent
            || pending.parent != expected_parent
            || pending.candidate.head != saved_head
        {
            return Err(error(ErrorCode::WorkspaceConflict));
        }
        let head_changed = state.head != pending.candidate.head;
        let pending = plan
            .pending
            .take()
            .ok_or_else(|| error(ErrorCode::InactivePlan))?;
        if head_changed {
            self.read_epoch.store(false, Ordering::Release);
            self.read_epoch = Arc::new(AtomicBool::new(true));
        }
        self.state = Some(Arc::new(pending.candidate));
        Ok(())
    }

    /// Restore committed markers; any issue fails the whole call so no partially
    /// restored text is exposed. Marker matching ignores case and accepts Crockford's
    /// `I`/`L` → `1` and `O` → `0` substitutions in the code. Use `restore_report`
    /// to locate the issues.
    ///
    /// Any `[[LABEL_CODE]]`-shaped span that does not resolve to a committed entry
    /// blocks restoration, including accidental patterns such as `[[my_note]]` or
    /// `[[TODO_ABC123]]`. These are considered damaged markers; the caller should
    /// remove or escape them before retrying. `restore` maps any issue to `InvalidMarker`.
    pub fn restore(&self, text: &str) -> Result<String> {
        let mut report = self.restore_report(text)?;
        report
            .text
            .take()
            .ok_or_else(|| error(ErrorCode::InvalidMarker))
    }

    /// Restore all-or-nothing and report every span that blocked restoration.
    /// Marker matching ignores case and accepts Crockford's `I`/`L` → `1` and
    /// `O` → `0` substitutions in the code.
    pub fn restore_report(&self, text: &str) -> Result<RestoreReport> {
        restore_report(self.state()?, text)
    }
}

fn restore_report(state: &State, text: &str) -> Result<RestoreReport> {
    restore_report_scoped(state, text, None)
}
fn restore_report_scoped(
    state: &State,
    text: &str,
    context: Option<usize>,
) -> Result<RestoreReport> {
    if text.len() > MAX_BUNDLE_BYTES {
        return Err(error(ErrorCode::ResourceLimit));
    }
    let lookup = marker_lookup(state);
    let spans = marker_spans(text)?;
    let mut issues = marker_issues(text, &spans, &lookup)?;
    if let Some(context) = context {
        let mut index = TextIndex::new(text);
        for span in &spans {
            if span.canonical.as_ref().is_some_and(|canonical| {
                lookup.contains_key(canonical) && !conversation::eligible(state, context, canonical)
            }) {
                issues.push(MarkerIssue {
                    kind: MarkerIssueKind::NotIssuedInConversation,
                    byte_range: span.range,
                    codepoint_range: TextRange {
                        start: index.codepoint_offset(span.range.start),
                        end: index.codepoint_offset(span.range.end),
                    },
                    utf16_range: index
                        .utf16_range(span.range)
                        .map_err(|_| error(ErrorCode::InvalidEncoding))?,
                });
            }
        }
        issues.sort_by_key(|issue| issue.byte_range.start);
    }
    let restored_markers = spans
        .iter()
        .filter(|span| {
            span.canonical.as_ref().is_some_and(|canonical| {
                lookup.contains_key(canonical)
                    && context
                        .is_none_or(|context| conversation::eligible(state, context, canonical))
            })
        })
        .count();
    if !issues.is_empty() {
        return Ok(RestoreReport {
            text: None,
            restored_markers,
            issues,
        });
    }
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        let display = span
            .canonical
            .as_ref()
            .and_then(|canonical| lookup.get(canonical))
            .ok_or_else(|| error(ErrorCode::InvalidMarker))?;
        append(&mut output, &text[cursor..span.range.start])?;
        append(&mut output, display)?;
        cursor = span.range.end;
    }
    append(&mut output, &text[cursor..])?;
    Ok(RestoreReport {
        text: Some(output),
        restored_markers,
        issues,
    })
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Longest `[[...]]` interior inspected as a possible marker: label, separator and code,
/// with slack so moderately damaged markers are still recognized and rejected.
const MAX_MARKER_INTERIOR: usize = 2 * (MAX_LABEL_BYTES + 1 + MARKER_CODE_LENGTH);
const MAX_CODE_ATTEMPTS: u32 = 32;

/// Committed `LABEL_CODE` words outside any `[[...]]` span. Uncommitted look-alikes,
/// such as order numbers, are ordinary text.
fn unbracketed_markers(
    segment: &str,
    offset: usize,
    lookup: &BTreeMap<String, &str>,
    push: &mut impl FnMut(MarkerIssueKind, TextRange) -> Result<()>,
) -> Result<()> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = segment.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !word(bytes[start]) {
            start += 1;
            continue;
        }
        let end = bytes[start..]
            .iter()
            .position(|b| !word(*b))
            .map_or(bytes.len(), |length| start + length);
        if end - start <= MAX_MARKER_INTERIOR
            && canonical_marker(&segment[start..end])
                .is_some_and(|canonical| lookup.contains_key(&canonical))
        {
            push(
                MarkerIssueKind::Unbracketed,
                TextRange {
                    start: offset + start,
                    end: offset + end,
                },
            )?;
        }
        start = end;
    }
    Ok(())
}

/// Canonical marker text → display value, for every committed entry.
fn marker_lookup(state: &State) -> BTreeMap<String, &str> {
    state
        .entries
        .iter()
        .map(|(identity, entry)| {
            (
                marker(&identity.entity_type, &entry.code),
                entry.display.as_str(),
            )
        })
        .collect()
}

/// A `[[...]]` span whose interior looks like `LABEL_CODE`. `canonical` is the
/// normalized marker when the interior is well formed, and `None` for a damaged one.
struct MarkerSpan {
    range: TextRange,
    canonical: Option<String>,
}

fn marker_spans(text: &str) -> Result<Vec<MarkerSpan>> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = text[cursor..].find("[[") {
        let start = cursor + relative;
        let interior_start = start + 2;
        let interior_end = bytes[interior_start..]
            .iter()
            .take(MAX_MARKER_INTERIOR + 1)
            .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
            .map(|offset| interior_start + offset);
        let Some(interior_end) = interior_end else {
            cursor = start + 1;
            continue;
        };
        let interior = &text[interior_start..interior_end];
        let marker_like = interior_end - interior_start <= MAX_MARKER_INTERIOR
            && interior
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && interior.contains('_')
            && text[interior_end..].starts_with("]]");
        if !marker_like {
            cursor = start + 1;
            continue;
        }
        spans
            .try_reserve(1)
            .map_err(|_| error(ErrorCode::ResourceLimit))?;
        spans.push(MarkerSpan {
            range: TextRange {
                start,
                end: interior_end + 2,
            },
            canonical: canonical_marker(interior),
        });
        cursor = interior_end + 2;
    }
    Ok(spans)
}

/// Classify spans identically for source validation and strict restoration.
fn marker_issues(
    text: &str,
    spans: &[MarkerSpan],
    lookup: &BTreeMap<String, &str>,
) -> Result<Vec<MarkerIssue>> {
    let mut problems = Vec::new();
    let mut push = |kind, range| {
        problems
            .try_reserve(1)
            .map_err(|_| error(ErrorCode::ResourceLimit))?;
        problems.push((kind, range));
        Ok(())
    };
    let mut cursor = 0;
    for span in spans {
        unbracketed_markers(&text[cursor..span.range.start], cursor, lookup, &mut push)?;
        match span.canonical.as_ref() {
            Some(canonical) if lookup.contains_key(canonical) => {}
            Some(_) => push(MarkerIssueKind::Unknown, span.range)?,
            None => push(MarkerIssueKind::Damaged, span.range)?,
        }
        cursor = span.range.end;
    }
    unbracketed_markers(&text[cursor..], cursor, lookup, &mut push)?;
    let mut index = TextIndex::new(text);
    problems
        .into_iter()
        .map(|(kind, byte_range)| {
            Ok(MarkerIssue {
                kind,
                byte_range,
                codepoint_range: TextRange {
                    start: index.codepoint_offset(byte_range.start),
                    end: index.codepoint_offset(byte_range.end),
                },
                utf16_range: index
                    .utf16_range(byte_range)
                    .map_err(|_| error(ErrorCode::InvalidMarker))?,
            })
        })
        .collect()
}

/// Full committed markers pass through; every unrestorable source span blocks preparation.
fn committed_marker_ranges(
    text: &str,
    committed: &BTreeMap<String, &str>,
) -> Result<Vec<TextRange>> {
    let spans = marker_spans(text)?;
    let issues = marker_issues(text, &spans, committed)?;
    if issues.len() > MAX_FINDINGS {
        return Err(error(ErrorCode::ResourceLimit));
    }
    if !issues.is_empty() {
        let mut failure = error(ErrorCode::InvalidMarker);
        failure.marker_issues = issues;
        return Err(failure);
    }
    Ok(spans.into_iter().map(|span| span.range).collect())
}

fn canonical_marker(interior: &str) -> Option<String> {
    let separator = interior.len().checked_sub(MARKER_CODE_LENGTH + 1)?;
    let (label, code) = interior.split_at(separator);
    let code = code.strip_prefix('_')?;
    let label = label.to_ascii_uppercase();
    if !valid_type(&label) {
        return None;
    }
    let code = code
        .bytes()
        .map(|b| match b.to_ascii_uppercase() {
            b'I' | b'L' => Some(b'1'),
            b'O' => Some(b'0'),
            upper if CROCKFORD.contains(&upper) => Some(upper),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()?;
    Some(marker(&label, std::str::from_utf8(&code).ok()?))
}

fn valid_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_code(code: &str) -> bool {
    code.len() == MARKER_CODE_LENGTH && code.bytes().all(|b| CROCKFORD.contains(&b))
}

fn marker(label: &str, code: &str) -> String {
    format!("[[{label}_{code}]]")
}

/// Derive a fresh code from the host-random operation ID. Codes carry no information
/// about the value; they are unpredictable to a model guessing markers, and are
/// re-drawn on collision so each code is unique within the workspace.
fn issue_code(
    namespace: PublicId,
    operation: PublicId,
    label: &str,
    counter: u64,
    codes: &mut BTreeSet<String>,
) -> Result<String> {
    for attempt in 0..MAX_CODE_ATTEMPTS {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&operation).map_err(|_| error(ErrorCode::InvalidId))?;
        mac.update(b"datafog-workspace-marker-code\0");
        mac.update(&namespace);
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(&counter.to_be_bytes());
        mac.update(&attempt.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let bits = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) >> 2;
        let code: String = (0..MARKER_CODE_LENGTH)
            .map(|index| {
                let shift = 5 * (MARKER_CODE_LENGTH - 1 - index);
                char::from(CROCKFORD[((bits >> shift) & 31) as usize])
            })
            .collect();
        if codes.insert(code.clone()) {
            return Ok(code);
        }
    }
    Err(error(ErrorCode::ResourceLimit))
}
fn source_limit(text: &str) -> Result<()> {
    if text.len() > MAX_SOURCE_BYTES {
        Err(error(ErrorCode::ResourceLimit))
    } else {
        Ok(())
    }
}
fn append(output: &mut String, value: &str) -> Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > MAX_BUNDLE_BYTES)
    {
        return Err(error(ErrorCode::ResourceLimit));
    }
    output
        .try_reserve(value.len())
        .map_err(|_| error(ErrorCode::ResourceLimit))?;
    output.push_str(value);
    Ok(())
}

/// Convert a browser selection through Core, rejecting split surrogate-pair boundaries.
pub fn byte_range_from_utf16(text: &str, range: TextRange) -> Result<TextRange> {
    source_limit(text)?;
    if range.start > range.end {
        return Err(error(ErrorCode::InvalidFinding));
    }
    let mut index = TextIndex::new(text);
    index
        .byte_range_from_utf16(range)
        .map_err(|_| error(ErrorCode::InvalidFinding))
}

fn ensure_fresh_operation(state: &State, operation: PublicId) -> Result<()> {
    state.validate_operation_id(operation, true)
}

fn adapt_findings<'a>(
    text: &'a str,
    findings: &[WorkspaceFinding],
    committed: &BTreeMap<String, &str>,
) -> Result<(Vec<Finding>, TextIndex<'a>)> {
    source_limit(text)?;
    let markers = committed_marker_ranges(text, committed)?;
    let mut index = TextIndex::new(text);
    let mut adapted = Vec::with_capacity(findings.len());
    let mut total_bytes = 0usize;
    for (finding_index, finding) in findings.iter().enumerate() {
        let invalid = || WorkspaceError {
            code: ErrorCode::InvalidFinding,
            finding_index: Some(finding_index),
            input_index: None,
            marker_issues: Vec::new(),
            review_conflicts: Vec::new(),
        };
        if !valid_type(&finding.entity_type)
            || finding.byte_range.start >= finding.byte_range.end
            || finding.matched_text.trim().is_empty()
            || crate::validate_utf8_range(text, finding.byte_range).is_err()
            || markers
                .get(markers.partition_point(|marker| marker.end <= finding.byte_range.start))
                .is_some_and(|marker| marker.start < finding.byte_range.end)
            || finding
                .detector_name
                .as_ref()
                .is_some_and(|v| v.len() > 128)
            || finding
                .detector_version
                .as_ref()
                .is_some_and(|v| v.len() > 128)
        {
            return Err(invalid());
        }
        total_bytes = total_bytes
            .checked_add(finding.matched_text.len())
            .ok_or_else(|| error(ErrorCode::ResourceLimit))?;
        if total_bytes > MAX_BUNDLE_BYTES {
            return Err(error(ErrorCode::ResourceLimit));
        }
        adapted.push(Finding {
            entity_type: finding.entity_type.clone(),
            matched_text: finding.matched_text.clone(),
            byte_range: finding.byte_range,
            codepoint_range: TextRange {
                start: index.codepoint_offset(finding.byte_range.start),
                end: index.codepoint_offset(finding.byte_range.end),
            },
            confidence: finding.confidence,
            detector_name: finding.detector_name.clone().unwrap_or_default(),
            detector_version: finding.detector_version.clone(),
        });
    }
    // Every finding must validate before any remembered choice can waive it.
    for (finding_index, finding) in adapted.iter().enumerate() {
        crate::validate_finding_with_index(text, finding, &mut index).map_err(|_| {
            WorkspaceError {
                code: ErrorCode::InvalidFinding,
                finding_index: Some(finding_index),
                input_index: None,
                marker_issues: Vec::new(),
                review_conflicts: Vec::new(),
            }
        })?;
    }
    Ok((adapted, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_attempt_codes(
        namespace: PublicId,
        operation: PublicId,
        label: &str,
        counter: u64,
    ) -> Vec<String> {
        (0..MAX_CODE_ATTEMPTS)
            .map(|attempt| {
                let mut mac = Hmac::<Sha256>::new_from_slice(&operation).unwrap();
                mac.update(b"datafog-workspace-marker-code\0");
                mac.update(&namespace);
                mac.update(label.as_bytes());
                mac.update(&[0]);
                mac.update(&counter.to_be_bytes());
                mac.update(&attempt.to_be_bytes());
                let digest = mac.finalize().into_bytes();
                let bits = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) >> 2;
                (0..MARKER_CODE_LENGTH)
                    .map(|index| {
                        let shift = 5 * (MARKER_CODE_LENGTH - 1 - index);
                        char::from(CROCKFORD[((bits >> shift) & 31) as usize])
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn issue_code_redraws_on_collision_and_exhausts_after_max_attempts() {
        let namespace = [1u8; 16];
        let operation = [0u8; 16];
        let mut codes = BTreeSet::new();

        let first = issue_code(namespace, operation, "PERSON", 0, &mut codes).unwrap();
        assert!(valid_code(&first));
        assert!(codes.contains(&first));

        let second = issue_code(namespace, operation, "PERSON", 1, &mut codes).unwrap();
        assert!(valid_code(&second));
        assert_ne!(first, second);
        assert!(codes.contains(&second));

        let all_codes: BTreeSet<String> = all_attempt_codes(namespace, operation, "PERSON", 2)
            .into_iter()
            .collect();
        let mut blocking = all_codes.clone();
        let result = issue_code(namespace, operation, "PERSON", 2, &mut blocking);
        assert_eq!(result.err().unwrap().code, ErrorCode::ResourceLimit);

        let mut partial = all_codes.iter().skip(1).cloned().collect();
        let fallback = issue_code(namespace, operation, "PERSON", 2, &mut partial).unwrap();
        assert_eq!(fallback, all_codes.iter().next().unwrap().clone());
    }
}
