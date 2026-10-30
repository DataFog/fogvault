//! Source-pinned streaming exports and fresh-password restore publication.
//! A fixed protected intent survives restart; old registrations are never reset.
use super::*;
use fogvault::{SnapshotIdentity, TrustedControlStore, WorkGuard};
use fogvault_backup::{
    CompletedImport, ExportReceipt, FreshImportPermit, Identity, Observation, Policy, RecordData,
    SourceSnapshot,
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"FGVRST01";
const PLAN_BYTES: usize = 282;

#[derive(Clone, Debug)]
pub struct RestoreTicket {
    request: [u8; 16],
    vault: [u8; 16],
    snapshot: SnapshotIdentity,
    path_digest: [u8; 32],
    source: SourceSnapshot,
    ciphertext: [u8; 32],
    origin_verified: bool,
    submitted: bool,
}
impl RestoreTicket {
    pub fn request_id(&self) -> [u8; 16] {
        self.request
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault
    }
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }
    pub fn origin_verified(&self) -> bool {
        self.origin_verified
    }
    pub fn backup_sha256(&self) -> [u8; 32] {
        self.ciphertext
    }
    fn encode(&self) -> [u8; PLAN_BYTES] {
        let mut out = [0; PLAN_BYTES];
        out[..8].copy_from_slice(MAGIC);
        out[8..24].copy_from_slice(&self.request);
        out[24..40].copy_from_slice(&self.vault);
        out[40..72].copy_from_slice(&self.snapshot.descriptor_digest);
        out[72..104].copy_from_slice(&self.snapshot.head_digest);
        out[104..112].copy_from_slice(&self.snapshot.generation.to_be_bytes());
        out[112..144].copy_from_slice(&self.path_digest);
        out[144..248].copy_from_slice(self.source.header());
        out[248..280].copy_from_slice(&self.ciphertext);
        out[280] = u8::from(self.origin_verified);
        out[281] = u8::from(self.submitted);
        out
    }
    fn decode(bytes: [u8; PLAN_BYTES]) -> Result<Self> {
        if &bytes[..8] != MAGIC || bytes[280] > 1 || bytes[281] > 1 {
            return Err(Error::Integrity);
        }
        Ok(Self {
            request: bytes[8..24].try_into().expect("fixed field"),
            vault: bytes[24..40].try_into().expect("fixed field"),
            snapshot: SnapshotIdentity {
                descriptor_digest: bytes[40..72].try_into().expect("fixed field"),
                head_digest: bytes[72..104].try_into().expect("fixed field"),
                generation: u64::from_be_bytes(bytes[104..112].try_into().expect("fixed field")),
            },
            path_digest: bytes[112..144].try_into().expect("fixed field"),
            source: SourceSnapshot::from_header(bytes[144..248].try_into().expect("fixed field"))
                .map_err(transport_error)?,
            ciphertext: bytes[248..280].try_into().expect("fixed field"),
            origin_verified: bytes[280] != 0,
            submitted: bytes[281] != 0,
        })
    }
}

fn transport_error(error: io::Error) -> Error {
    let kind = error.kind();
    if let Some(inner) = error.into_inner() {
        if let Ok(error) = inner.downcast::<Error>() {
            return *error;
        }
    }
    match kind {
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => Error::Integrity,
        io::ErrorKind::OutOfMemory => Error::ResourceLimit,
        _ => Error::Storage,
    }
}
fn export_error(error: Error) -> io::Error {
    io::Error::other(error)
}
fn canonical_destination(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or(Error::Malformed("fresh restore destination"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)
        .map_err(|_| Error::Storage)?
        .join(name))
}
fn path_digest(path: &Path) -> Result<[u8; 32]> {
    Ok(crate::crypto::digest(
        path.to_str()
            .ok_or(Error::UnsupportedCapability)?
            .as_bytes(),
    ))
}
fn operation_name(request: [u8; 16]) -> String {
    request.iter().map(|v| format!("{v:02x}")).collect()
}
fn reserve(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::Exists
        } else {
            Error::Storage
        }
    })
}
fn required(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| Error::Integrity)
}
struct Cleanup {
    paths: Vec<PathBuf>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

struct Records<'a> {
    engine: &'a Engine,
    transaction: &'a Connection,
    cursor: fogvault::RecordCursor,
    work: &'a WorkGuard,
    complete: bool,
    metrics: OperationMetrics,
}
impl Iterator for Records<'_> {
    type Item = io::Result<RecordData>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.complete {
            return None;
        }
        let result = (|| {
            self.work.check()?;
            let mut nodes = SqliteNodes::new(self.transaction, u64::MAX);
            let page = self.engine.record_page(&mut self.cursor, &mut nodes, 1)?;
            if page.complete {
                let rows: i64 = self
                    .transaction
                    .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
                    .storage()?;
                let nodes: i64 = self
                    .transaction
                    .query_row("SELECT count(*) FROM index_nodes", [], |r| r.get(0))
                    .storage()?;
                let count = self.cursor.record_count();
                let expected_nodes = if count == 0 {
                    0
                } else {
                    count
                        .checked_mul(2)
                        .and_then(|n| n.checked_sub(1))
                        .ok_or(Error::ResourceLimit)?
                };
                if u64::try_from(rows).map_err(|_| Error::Integrity)? != count
                    || u64::try_from(nodes).map_err(|_| Error::Integrity)? != expected_nodes
                {
                    return Err(Error::Integrity);
                }
                self.complete = true;
            }
            let Some(proof) = page.records.into_iter().next() else {
                return Ok(None);
            };
            let row = load_record_admitted(
                self.transaction,
                &proof.id(),
                true,
                self.engine.envelope_byte_limit()?,
                &mut self.metrics,
            )?;
            let clear = self.engine.read_verified(
                &proof,
                row.revision,
                row.envelope.as_deref().ok_or(Error::Integrity)?,
            )?;
            self.work.check()?;
            Ok(Some(RecordData {
                id: proof.id(),
                revision: clear.revision,
                schema: Zeroizing::new(Vec::new()),
                metadata: clear.metadata,
                payload: clear.payload,
            }))
        })();
        match result {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(error) => {
                self.complete = true;
                Some(Err(export_error(error)))
            }
        }
    }
}
impl Vault {
    pub fn export_backup(
        &mut self,
        token: &SessionToken,
        recipient: &fogvault_backup::Recipient,
        output: impl Write,
        policy: Policy,
    ) -> Result<(SourceSnapshot, ExportReceipt)> {
        self.engine.check_session(token)?;
        let work = self.engine.begin_host_work()?;
        self.engine.current_receipt()?;
        let mut registration = self.registered.clone();
        let guard = transactions::read_guard(&mut registration)?;
        let transaction = self.connection.transaction().storage()?;
        let mut metrics = OperationMetrics::default();
        let (descriptor, head) = load_header(
            &transaction,
            self.engine.limits(),
            &mut metrics,
            self.engine.descriptor_byte_limit(),
        )?;
        self.engine.check_snapshot(&descriptor, &head)?;
        transactions::check_guard_snapshot(guard.as_ref(), &descriptor, &head)?;
        let cursor = self.engine.begin_records()?;
        let source = SourceSnapshot::new(
            self.engine.vault_id(),
            crate::crypto::digest(&descriptor),
            crate::crypto::digest(&head),
            self.engine.generation().ok_or(Error::Locked)?,
            cursor.record_count(),
        );
        let records = Records {
            engine: &self.engine,
            transaction: &transaction,
            cursor,
            work: &work,
            complete: false,
            metrics: OperationMetrics::default(),
        };
        let receipt = fogvault_backup::export_snapshot(
            source.clone(),
            records,
            output,
            recipient,
            policy,
            &mut Observation::default(),
        )
        .map_err(transport_error)?;
        transaction.commit().storage()?;
        work.check()?;
        Ok((source, receipt))
    }
}
impl NativeHost {
    fn restore_paths(
        &self,
        destination: &Path,
        request: [u8; 16],
    ) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let name = operation_name(request);
        let parent = destination.parent().expect("canonical destination parent");
        (
            self.namespace.join(format!("restore-{name}.intent")),
            self.namespace.join(format!("restore-{name}.lock")),
            parent.join(format!(".fogvault-restore-{name}.sqlite")),
            parent.join(format!(".fogvault-restore-{name}.age")),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_password_restore(
        &self,
        destination: impl AsRef<Path>,
        input: impl Read,
        identity: &Identity,
        source: SourceSnapshot,
        trusted_digest: Option<[u8; 32]>,
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
        policy: Policy,
        request: [u8; 16],
    ) -> Result<RestoreTicket> {
        let destination = canonical_destination(destination.as_ref())?;
        if destination.exists() {
            return Err(Error::Exists);
        }
        if source.records() > limits.max_records as u64 {
            return Err(Error::ResourceLimit);
        }
        let (intent, coordinator, stage, cipherstage) = self.restore_paths(&destination, request);
        if intent.exists() {
            return Err(Error::OperationIdReuse);
        }
        let lock = reserve(&coordinator)?;
        lock.lock().map_err(|_| Error::Storage)?;
        let mut cleanup = Cleanup { paths: Vec::new() };
        let mut vault =
            Vault::diagnostic_create_current_with_kdf_policy(&stage, password, limits, kdf)?;
        cleanup.paths.push(stage.clone());
        let permit = match trusted_digest {
            Some(digest) => {
                FreshImportPermit::origin_checked(source.clone(), digest, vault.vault_id())
            }
            None => FreshImportPermit::owner_accepted_unverified(source.clone(), vault.vault_id()),
        }
        .map_err(transport_error)?;
        let stage_key = Identity::generate();
        let mut cipher = reserve(&cipherstage)?;
        cleanup.paths.push(cipherstage.clone());
        let completed: CompletedImport = fogvault_backup::stage_import(
            input,
            identity,
            &stage_key.to_public(),
            &mut cipher,
            &permit,
            policy,
            &mut Observation::default(),
        )
        .map_err(transport_error)?;
        cipher.sync_all().map_err(|_| Error::Storage)?;
        drop(cipher);
        let records = fogvault_backup::read_staged_records(
            File::open(&cipherstage).map_err(|_| Error::Storage)?,
            &stage_key,
            &completed,
            vault.vault_id(),
            policy,
        )
        .map_err(transport_error)?;
        let session = vault.unlock(password)?;
        for record in records {
            // Schema is informational, but native records have only metadata and
            // payload fields. Reject nonempty schema rather than silently lose it.
            if !record.schema.is_empty() {
                return Err(Error::UnsupportedCapability);
            }
            vault.save(
                &session,
                record.id,
                None,
                &record.metadata,
                &record.payload,
                fogvault::storage::random_identifier()?,
            )?;
        }
        vault.audit(&session)?;
        let snapshot =
            transactions::identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())?;
        let ticket = RestoreTicket {
            request,
            vault: vault.vault_id(),
            snapshot,
            path_digest: path_digest(&destination)?,
            source,
            ciphertext: completed.source_ciphertext_sha256(),
            origin_verified: completed.origin_verified(),
            submitted: false,
        };
        vault.lock();
        drop(vault);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&stage)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::Storage)?;
        let temporary = self.namespace.join(format!(
            "restore-{}.intent-prepared",
            operation_name(request)
        ));
        let mut file = reserve(&temporary)?;
        cleanup.paths.push(temporary.clone());
        file.write_all(&ticket.encode())
            .map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)?;
        drop(file);
        fs::hard_link(&temporary, &intent).map_err(|_| Error::Storage)?;
        // Retain the exact target immediately once the intent exists, even if a
        // later directory barrier fails and persistence becomes uncertain.
        cleanup.paths.retain(|p| p != &stage);
        super::durability::directory_sync(&self.namespace).map_err(|_| Error::OutcomeUnknown {
            request_id: request,
        })?;
        Ok(ticket)
    }
    fn load_restore(
        &self,
        path: &Path,
        request: [u8; 16],
    ) -> Result<(File, RestoreTicket, PathBuf, PathBuf)> {
        let destination = canonical_destination(path)?;
        let (intent, lock, stage, _) = self.restore_paths(&destination, request);
        let file = required(&lock)?;
        file.lock().map_err(|_| Error::Storage)?;
        let mut input = File::open(&intent).map_err(|_| Error::NotFound)?;
        if input.metadata().map_err(|_| Error::Storage)?.len() != PLAN_BYTES as u64 {
            return Err(Error::Integrity);
        }
        let mut bytes = [0; PLAN_BYTES];
        input.read_exact(&mut bytes).map_err(|_| Error::Integrity)?;
        let ticket = RestoreTicket::decode(bytes)?;
        if ticket.request != request || ticket.path_digest != path_digest(&destination)? {
            return Err(Error::Conflict);
        }
        Ok((file, ticket, destination, stage))
    }
    pub fn publish_password_restore(
        &self,
        path: impl AsRef<Path>,
        request: [u8; 16],
        password: &[u8],
        limits: Limits,
        kdf: KdfPolicy,
    ) -> Result<(Vault, RestoreTicket)> {
        let (_guard, mut ticket, destination, stage) = self.load_restore(path.as_ref(), request)?;
        let existing = destination.exists();
        let source = if existing { &destination } else { &stage };
        let mut vault =
            Vault::diagnostic_open_current_with_kdf_policy(source, limits, kdf.clone())?;
        let token = vault.unlock(password)?;
        if vault.vault_id() != ticket.vault
            || transactions::identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())?
                != ticket.snapshot
        {
            return Err(Error::Conflict);
        }
        vault.audit(&token)?;
        vault.lock();
        drop(vault);
        let outcome_unknown = || Error::OutcomeUnknown {
            request_id: request,
        };
        if !ticket.submitted {
            ticket.submitted = true;
            let (intent, _, _, _) = self.restore_paths(&destination, request);
            let next = self
                .namespace
                .join(format!("restore-{}.submitted", operation_name(request)));
            let mut file = reserve(&next)?;
            file.write_all(&ticket.encode())
                .map_err(|_| Error::Storage)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            drop(file);
            fs::rename(&next, &intent).map_err(|_| outcome_unknown())?;
            super::durability::directory_sync(&self.namespace).map_err(|_| outcome_unknown())?;
        }
        if !existing {
            fs::hard_link(&stage, &destination).map_err(|_| outcome_unknown())?;
        }
        super::durability::directory_sync(destination.parent().expect("canonical parent"))
            .map_err(|_| outcome_unknown())?;
        let mut vault =
            Vault::diagnostic_open_current_with_kdf_policy(&destination, limits, kdf.clone())
                .map_err(|_| outcome_unknown())?;
        // Untrusted staging paths can change after preparation. Authenticate
        // and compare the actual published object again before registration.
        let token = vault.unlock(password).map_err(|_| outcome_unknown())?;
        if vault.vault_id() != ticket.vault
            || transactions::identity(vault.engine.descriptor_bytes(), vault.engine.head_bytes())
                .map_err(|_| outcome_unknown())?
                != ticket.snapshot
        {
            return Err(outcome_unknown());
        }
        vault.audit(&token).map_err(|_| outcome_unknown())?;
        vault.lock();
        match self.open_registration(&destination) {
            Ok(mut context) => {
                let state = context
                    .store
                    .load()
                    .map_err(|_| outcome_unknown())?
                    .ok_or_else(outcome_unknown)?;
                if state.pending().is_some()
                    || state.accepted() != ticket.snapshot
                    || state.vault_id() != ticket.vault
                {
                    return Err(Error::Conflict);
                }
                vault.registered = Some(context);
            }
            Err(Error::NotFound) => {
                vault.registered = Some(
                    self.register_authenticated(&destination, ticket.vault, ticket.snapshot)
                        .map_err(|_| outcome_unknown())?,
                );
            }
            Err(_) => return Err(outcome_unknown()),
        }
        // Keep the small immutable intent/coordinator as an exact latest restore
        // receipt. A later ordinary write correctly makes this restore conflict.
        let _ = fs::remove_file(&stage);
        Ok((vault, ticket))
    }
    pub fn discard_prepared_restore(
        &self,
        path: impl AsRef<Path>,
        request: [u8; 16],
    ) -> Result<()> {
        let (_guard, ticket, destination, stage) = self.load_restore(path.as_ref(), request)?;
        if ticket.submitted {
            return Err(Error::OutcomeUnknown {
                request_id: request,
            });
        }
        if destination.exists() {
            return Err(Error::Conflict);
        }
        fs::remove_file(&stage).map_err(|_| Error::Integrity)?;
        let (intent, _, _, _) = self.restore_paths(&destination, request);
        fs::remove_file(intent).map_err(|_| Error::Storage)?;
        super::durability::directory_sync(&self.namespace)
    }
}
