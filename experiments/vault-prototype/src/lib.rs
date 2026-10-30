//! Compatibility harness for the maintained portable core and native adapter.
pub use fogvault::experimental::{crypto, format, index};
pub use fogvault::{CommitReceipt, Error, Limits, RecordId, Result, SecretRecord, SessionToken};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use fogvault_native::{
    AuditReport, CommitFault, ControlPublicationGuard, CreationReceipt,
    DiagnosticHost as NativeHost, DiagnosticVault as Vault, OperationMetrics, PreparedCreation,
    ProtectedControlSqliteStore,
};
