//! Native persistence for FogVault. The host protects a control namespace
//! independently of the untrusted vault files; a different pathname is not
//! isolation. The supported facade does not expose fault injection or legacy
//! writable constructors. Diagnostic compatibility is an explicit feature.
mod crypto {
    #[cfg(test)]
    pub(crate) use fogvault::experimental::crypto::{derive, open, seal};
    pub(crate) use fogvault::storage::digest;
}
mod format {
    #[cfg(test)]
    pub(crate) use fogvault::experimental::format::{encrypt_record, Descriptor, IndexHead};
    pub(crate) use fogvault::storage::Entry;
}
mod index {
    pub(crate) use fogvault::storage::{lookup, node_hash, remove, upsert, AuditCursor};
}
pub use fogvault::{
    AccessAdmission, AccessInfo, AccessPath, AccessProfile, CommitReceipt, CredentialReceipt,
    Error, KdfPolicy, KdfProfile, KeyEffect, KeyProvider, Limits, RecordCursor, RecordId,
    RecordPage, RecoveryKey, Result, SecretRecord, SessionToken,
};
mod facade;
#[cfg(feature = "backup")]
mod facade_backup;
#[cfg(feature = "backup")]
pub use facade_backup::{RestoreOptions, RestoreTicket};
mod native;
pub use facade::{AccessOptions, Host, Vault};
pub use native::{AuditReport, OperationMetrics, PreparedProtection, ProtectionTicket};
#[cfg(any(test, feature = "diagnostics"))]
pub use native::{
    CommitFault, ControlPublicationGuard, CreationReceipt, NativeHost as DiagnosticHost,
    PreparedCreation, ProtectedControlSqliteStore, Vault as DiagnosticVault,
};
