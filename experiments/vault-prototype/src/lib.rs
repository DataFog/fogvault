//! Disposable native adapter and compatibility fixtures for the shared portable core.
pub use fogvault::experimental::{crypto, format, index};
pub use fogvault::{CommitReceipt, Error, Limits, RecordId, Result, SecretRecord, SessionToken};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod native;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use native::NativeHost;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use native::{
    AuditReport, CommitFault, CreationReceipt, OperationMetrics, PreparedCreation, Vault,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use native::{ControlPublicationGuard, ProtectedControlSqliteStore};
