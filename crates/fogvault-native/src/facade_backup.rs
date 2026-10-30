//! Supported backup entry points. Restores create a new password-protected vault;
//! they never replace an existing identity or preserve historical CAS revisions.
use crate::*;
use fogvault_backup::{ExportReceipt, Identity, Policy, Recipient, SourceSnapshot};
use std::{
    io::{Read, Write},
    path::Path,
};

pub use crate::native::RestoreTicket;

/// Finite host-selected backup/restore and native resource policy.
#[derive(Clone)]
pub struct RestoreOptions {
    pub limits: Limits,
    pub kdf: KdfPolicy,
    pub backup: Policy,
    pub request_id: [u8; 16],
}
impl Vault {
    /// The caller must durably complete its sink before retaining the receipt as
    /// a durable backup. Keep that receipt outside untrusted backup storage.
    pub fn export_backup(
        &mut self,
        session: &SessionToken,
        recipient: &Recipient,
        output: impl Write,
        policy: Policy,
    ) -> Result<(SourceSnapshot, ExportReceipt)> {
        self.0.export_backup(session, recipient, output, policy)
    }
}
impl Host {
    /// Prepare an origin-checked restore into a fresh password-protected target.
    /// The digest must come from independently trusted completed-export storage.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_password_restore(
        &self,
        path: impl AsRef<Path>,
        input: impl Read,
        identity: &Identity,
        source: SourceSnapshot,
        trusted_ciphertext: [u8; 32],
        new_password: &[u8],
        options: RestoreOptions,
    ) -> Result<RestoreTicket> {
        self.0.prepare_password_restore(
            path,
            input,
            identity,
            source,
            Some(trusted_ciphertext),
            new_password,
            options.limits,
            options.kdf,
            options.backup,
            options.request_id,
        )
    }
    /// Explicit owner-accepted data import with no original-sender claim.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_unverified_password_import(
        &self,
        path: impl AsRef<Path>,
        input: impl Read,
        identity: &Identity,
        source: SourceSnapshot,
        new_password: &[u8],
        options: RestoreOptions,
    ) -> Result<RestoreTicket> {
        self.0.prepare_password_restore(
            path,
            input,
            identity,
            source,
            None,
            new_password,
            options.limits,
            options.kdf,
            options.backup,
            options.request_id,
        )
    }
    /// Publish or restart an exact retained restore. Missing control state is
    /// never recreated. A later ordinary write makes an old ticket conflict.
    pub fn publish_password_restore(
        &self,
        path: impl AsRef<Path>,
        request: [u8; 16],
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<(Vault, RestoreTicket)> {
        self.0
            .publish_password_restore(path, request, password, limits, kdf)
            .map(|(vault, ticket)| (Vault(vault), ticket))
    }
    /// Explicit cancellation is allowed only before a durable submission marker.
    pub fn discard_prepared_restore(
        &self,
        path: impl AsRef<Path>,
        request: [u8; 16],
    ) -> Result<()> {
        self.0.discard_prepared_restore(path, request)
    }
}
