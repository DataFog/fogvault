//! Host-selected registration and encrypted point-operation retention.
//! The caller must protect this entire namespace from the vault-file attacker.
//! These files supply no protection against an authorized malicious host or
//! rollback of both the vault and the independently retained control namespace.
use super::*;
use fogvault::{
    ControlOperation, ControlState, PreparedControlOperation, SnapshotIdentity,
    TrustedControlStore, CONTROL_OWNER_BYTES,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

const REGISTRY_DDL: &str = "CREATE TABLE registrations(location TEXT PRIMARY KEY NOT NULL,vault BLOB NOT NULL UNIQUE CHECK(length(vault)=16),registration BLOB NOT NULL UNIQUE CHECK(length(registration)=16))";
const TARGET_MAGIC: &[u8; 8] = b"FGVNAT01";
// A point operation performs bounded lookup and mutation traces. This bound
// comes from those two index paths, not a product memory/capacity default.
const POINT_NODES: usize = 2 * MAX_PATH_NODES + 1;

/// An explicitly selected independently protected native host namespace.
/// Registered create/open is the normal host boundary. A raw diagnostic Vault
/// constructor outside this boundary cannot discover an unrelated registry.
#[derive(Clone)]
pub struct NativeHost {
    pub(super) namespace: PathBuf,
}

#[derive(Clone)]
pub(super) struct RegisteredContext {
    pub(super) store: ProtectedControlSqliteStore,
    pub(super) vault_path: PathBuf,
    target_path: PathBuf,
    vault_id: [u8; 16],
    registration_id: [u8; 16],
}

#[derive(Clone, Copy)]
pub(super) struct StageLimits {
    pub(super) descriptor_bytes: usize,
    pub(super) envelope_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceRecord {
    pub(super) revision: u64,
    pub(super) envelope_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PersistedRecordMutation {
    None,
    Save {
        id: RecordId,
        revision: u64,
        envelope: Vec<u8>,
        expected: Option<SourceRecord>,
    },
    Delete {
        id: RecordId,
        expected: SourceRecord,
    },
}

/// Ciphertext and nonsecret exact SQL instructions, never password/root/CEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PersistedNativeTarget {
    pub(super) owner_bytes: Vec<u8>,
    pub(super) operation: ControlOperation,
    pub(super) request_id: [u8; 16],
    pub(super) source_descriptor: Vec<u8>,
    pub(super) source_head: Vec<u8>,
    pub(super) target_descriptor: Vec<u8>,
    pub(super) target_head: Vec<u8>,
    pub(super) source_nodes: Vec<(NodeHash, Vec<u8>)>,
    pub(super) nodes: Vec<(NodeHash, Vec<u8>)>,
    pub(super) obsolete: Vec<NodeHash>,
    pub(super) record: PersistedRecordMutation,
}

fn directory_sync(path: &Path) -> Result<()> {
    super::durability::directory_sync(path)
}

fn reserve(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Exists
        } else {
            Error::Storage
        }
    })
}

fn location(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|_| Error::Storage)
}

impl NativeHost {
    /// Explicit creation; an occupied namespace is never reset or adopted.
    /// The host must establish OS protection independently of this call.
    pub fn create_new(namespace: impl AsRef<Path>) -> Result<Self> {
        let namespace = namespace.as_ref();
        if !namespace.is_absolute() {
            return Err(Error::Malformed("host namespace"));
        }
        std::fs::create_dir(namespace).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Storage
            }
        })?;
        let host = Self {
            namespace: std::fs::canonicalize(namespace).map_err(|_| Error::Storage)?,
        };
        drop(reserve(&host.namespace.join("registry.sqlite"))?);
        let coordinator = reserve(&host.namespace.join("registry.lock"))?;
        coordinator.lock().map_err(|_| Error::Storage)?;
        let mut connection = host.registry(false)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        transaction.execute_batch(REGISTRY_DDL).storage()?;
        transaction.commit().storage()?;
        directory_sync(&host.namespace)?;
        directory_sync(host.namespace.parent().ok_or(Error::Storage)?)?;
        Ok(host)
    }

    pub fn open_required(namespace: impl AsRef<Path>) -> Result<Self> {
        if !namespace.as_ref().is_absolute() {
            return Err(Error::Malformed("host namespace"));
        }
        let host = Self {
            namespace: std::fs::canonicalize(namespace.as_ref()).map_err(|_| Error::Integrity)?,
        };
        let _guard = host.registry_lock()?;
        host.registry(true)?;
        Ok(host)
    }

    fn registry_lock(&self) -> Result<File> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.namespace.join("registry.lock"))
            .map_err(|_| Error::Integrity)?;
        lock.lock().map_err(|_| Error::Storage)?;
        Ok(lock)
    }

    fn registry(&self, admit: bool) -> Result<Connection> {
        let connection = Connection::open_with_flags(
            self.namespace.join("registry.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| Error::Integrity)?;
        for (setting, value) in [
            (
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                false,
            ),
            (
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW,
                false,
            ),
            (
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
                false,
            ),
            (rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
        ] {
            if connection.set_db_config(setting, value).storage()? != value {
                return Err(Error::UnsupportedCapability);
            }
        }
        if !admit {
            connection
                .execute_batch("PRAGMA journal_mode=DELETE;")
                .storage()?;
        }
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA mmap_size=0; PRAGMA cell_size_check=ON;",
            )
            .storage()?;
        if admit {
            let mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .storage()?;
            let tables: i64 = connection
                .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                .storage()?;
            let ddl: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name='registrations'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| Error::Integrity)?;
            // Three UNIQUE constraints contribute three SQLite auto-indexes.
            if mode != "delete" || tables != 4 || ddl != REGISTRY_DDL {
                return Err(Error::Integrity);
            }
        }
        Ok(connection)
    }

    pub(super) fn register_authenticated(
        &self,
        path: &Path,
        vault_id: [u8; 16],
        accepted: SnapshotIdentity,
    ) -> Result<RegisteredContext> {
        let path = location(path)?;
        let location = path.to_str().ok_or(Error::UnsupportedCapability)?;
        let registration_id = fogvault::storage::random_identifier().map_err(Error::Crypto)?;
        let _guard = self.registry_lock()?;
        let mut connection = self.registry(true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        let occupied: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM registrations WHERE location=?1 OR vault=?2)",
                params![location, vault_id.as_slice()],
                |row| row.get(0),
            )
            .storage()?;
        if occupied {
            return Err(Error::Exists);
        }
        let prefix = self.namespace.join(hex(&registration_id));
        let store = ProtectedControlSqliteStore::create_new(
            prefix.with_extension("control.sqlite"),
            prefix.with_extension("control.lock"),
            ControlState::register(vault_id, registration_id, accepted),
        )?;
        transaction
            .execute(
                "INSERT INTO registrations VALUES(?1,?2,?3)",
                params![location, vault_id.as_slice(), registration_id.as_slice()],
            )
            .storage()?;
        transaction.commit().storage()?;
        directory_sync(&self.namespace)?;
        Ok(RegisteredContext {
            store,
            vault_path: path,
            target_path: prefix.with_extension("target"),
            vault_id,
            registration_id,
        })
    }

    pub(super) fn open_registration(&self, path: &Path) -> Result<RegisteredContext> {
        let path = location(path)?;
        let _guard = self.registry_lock()?;
        let mut connection = self.registry(true)?;
        let transaction = connection.transaction().storage()?;
        let pair: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT vault,registration FROM registrations WHERE location=?1",
                [path.to_str().ok_or(Error::UnsupportedCapability)?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .storage()?;
        let (vault_id, registration_id) = pair.ok_or(Error::NotFound)?;
        let vault_id: [u8; 16] = vault_id.try_into().map_err(|_| Error::Integrity)?;
        let registration_id: [u8; 16] = registration_id.try_into().map_err(|_| Error::Integrity)?;
        transaction.commit().storage()?;
        let prefix = self.namespace.join(hex(&registration_id));
        let store = ProtectedControlSqliteStore::open_required(
            prefix.with_extension("control.sqlite"),
            prefix.with_extension("control.lock"),
            vault_id,
            registration_id,
        )?;
        Ok(RegisteredContext {
            store,
            vault_path: path,
            target_path: prefix.with_extension("target"),
            vault_id,
            registration_id,
        })
    }

    #[cfg(any(test, feature = "diagnostics"))]
    pub(super) fn refuse_registered_diagnostic(
        &self,
        path: &Path,
        presented_vault_id: [u8; 16],
    ) -> Result<()> {
        let path = location(path)?;
        let _guard = self.registry_lock()?;
        let connection = self.registry(true)?;
        let registered: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM registrations WHERE location=?1 OR vault=?2)",
                params![
                    path.to_str().ok_or(Error::UnsupportedCapability)?,
                    presented_vault_id.as_slice()
                ],
                |row| row.get(0),
            )
            .storage()?;
        if registered {
            Err(Error::UnsupportedCapability)
        } else {
            Ok(())
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl RegisteredContext {
    pub(super) fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }
    pub(super) fn registration_id(&self) -> [u8; 16] {
        self.registration_id
    }

    pub(super) fn persist_target(
        &mut self,
        target: &PersistedNativeTarget,
        limits: StageLimits,
    ) -> Result<[u8; 32]> {
        let bytes = target.encode(limits)?;
        let digest = crate::crypto::digest(&bytes);
        let owner = PreparedControlOperation::parse(&target.owner_bytes)?;
        if owner.vault_id() != self.vault_id || owner.registration_id() != self.registration_id {
            return Err(Error::Integrity);
        }
        let state = self.store.load()?.ok_or(Error::Integrity)?;
        let guard = self.store.publication_guard(&state)?;
        guard.current().validate_ordinary(&owner)?;
        let pending = guard.current().pending().ok_or(Error::Conflict)?;
        if pending.submission().is_some() {
            return Err(Error::Conflict);
        }
        match reserve(&self.target_path) {
            Ok(mut file) => {
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|_| Error::Storage)?;
                directory_sync(self.target_path.parent().ok_or(Error::Storage)?)?;
            }
            Err(Error::Exists) => {
                let previous_bytes = Self::read_target_bytes_at(&self.target_path, limits)?;
                if previous_bytes != bytes {
                    let previous = PersistedNativeTarget::decode(&previous_bytes, limits)?;
                    let previous_owner = PreparedControlOperation::parse(&previous.owner_bytes)?;
                    if previous_owner.vault_id() != self.vault_id
                        || previous_owner.registration_id() != self.registration_id
                        || previous.target_identity()? != guard.current().accepted()
                    {
                        return Err(Error::Integrity);
                    }
                    // A prior completed operation may have left cleanup pending.
                    // The current live Prepared guard proves its target is now
                    // accepted; deleting it cannot erase a Submitted operation.
                    std::fs::remove_file(&self.target_path).map_err(|_| Error::Storage)?;
                    directory_sync(self.target_path.parent().ok_or(Error::Storage)?)?;
                    let mut file = reserve(&self.target_path)?;
                    file.write_all(&bytes)
                        .and_then(|_| file.sync_all())
                        .map_err(|_| Error::Storage)?;
                    directory_sync(self.target_path.parent().ok_or(Error::Storage)?)?;
                }
            }
            Err(error) => return Err(error),
        }
        Ok(digest)
    }

    fn read_target_bytes_at(path: &Path, limits: StageLimits) -> Result<Vec<u8>> {
        let max = PersistedNativeTarget::maximum_bytes(limits)?;
        let mut file = File::open(path).map_err(|_| Error::Integrity)?;
        let len = usize::try_from(file.metadata().map_err(|_| Error::Storage)?.len())
            .map_err(|_| Error::ResourceLimit)?;
        if len > max {
            return Err(Error::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(len);
        Read::by_ref(&mut file)
            .take(
                u64::try_from(max)
                    .map_err(|_| Error::ResourceLimit)?
                    .checked_add(1)
                    .ok_or(Error::ResourceLimit)?,
            )
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.len() != len || bytes.len() > max {
            return Err(Error::Integrity);
        }
        Ok(bytes)
    }

    pub(super) fn load_target(&self, limits: StageLimits) -> Result<PersistedNativeTarget> {
        let target = PersistedNativeTarget::decode(
            &Self::read_target_bytes_at(&self.target_path, limits)?,
            limits,
        )?;
        let owner = PreparedControlOperation::parse(&target.owner_bytes)?;
        if owner.vault_id() != self.vault_id || owner.registration_id() != self.registration_id {
            return Err(Error::Integrity);
        }
        Ok(target)
    }

    /// Only accepted, no-pending control authorizes removal. Never clean a
    /// Submitted target merely because a vault transaction returned an error.
    pub(super) fn clear_target(&mut self) -> Result<()> {
        let state = self.store.load()?.ok_or(Error::Integrity)?;
        let guard = self.store.publication_guard(&state)?;
        if guard.current().pending().is_some() {
            return Err(Error::Conflict);
        }
        match std::fs::remove_file(&self.target_path) {
            Ok(()) => directory_sync(self.target_path.parent().ok_or(Error::Storage)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Storage),
        }
    }

    /// Remove only the exact completed target while its live coordinator is
    /// still held. Dropping the guard before cleanup could delete a newer
    /// writer's retained target. Failure is cleanup pending, never rollback.
    pub(super) fn clear_completed_target(
        &self,
        guard: &ControlPublicationGuard<'_>,
        limits: StageLimits,
    ) -> Result<()> {
        if !guard.belongs_to(&self.store)
            || guard.current().vault_id() != self.vault_id
            || guard.current().registration_id() != self.registration_id
            || guard.current().pending().is_some()
        {
            return Err(Error::Conflict);
        }
        match std::fs::metadata(&self.target_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Storage),
            Ok(_) => {}
        }
        let target = self.load_target(limits)?;
        if target.target_identity()? != guard.current().accepted() {
            return Err(Error::Conflict);
        }
        std::fs::remove_file(&self.target_path).map_err(|_| Error::Storage)?;
        directory_sync(self.target_path.parent().ok_or(Error::Storage)?)
    }
}

impl PersistedNativeTarget {
    pub(super) fn source_identity(&self) -> Result<SnapshotIdentity> {
        identity(&self.source_descriptor, &self.source_head)
    }
    pub(super) fn target_identity(&self) -> Result<SnapshotIdentity> {
        identity(&self.target_descriptor, &self.target_head)
    }

    fn maximum_bytes(limits: StageLimits) -> Result<usize> {
        // Both descriptors, both heads, two node collections, obsolete hashes,
        // one envelope, and exact framing/record expectation fields.
        8usize
            .checked_add(
                CONTROL_OWNER_BYTES
                    + 1
                    + 16
                    + 4 * 8
                    + 2 * fogvault::INDEX_HEAD_LEN
                    + 3 * 4
                    + 1
                    + 16
                    + 8
                    + 8
                    + 1
                    + 8
                    + 32,
            )
            .and_then(|n| n.checked_add(limits.descriptor_bytes.checked_mul(2)?))
            .and_then(|n| {
                n.checked_add(
                    (32 + 2 + MAX_NODE_BYTES)
                        .checked_mul(POINT_NODES)?
                        .checked_mul(2)?,
                )
            })
            .and_then(|n| n.checked_add(32usize.checked_mul(POINT_NODES)?))
            .and_then(|n| n.checked_add(limits.envelope_bytes))
            .ok_or(Error::ResourceLimit)
    }

    pub(super) fn canonicalize(&mut self) {
        self.source_nodes.sort_by_key(|entry| entry.0);
        self.nodes.sort_by_key(|entry| entry.0);
        self.obsolete.sort();
    }

    fn validate(&self, limits: StageLimits) -> Result<()> {
        if self.source_descriptor.len() > limits.descriptor_bytes
            || self.target_descriptor.len() > limits.descriptor_bytes
            || self.source_descriptor.is_empty()
            || self.target_descriptor.is_empty()
        {
            return Err(Error::ResourceLimit);
        }
        let source = self.source_identity()?;
        let target = self.target_identity()?;
        let owner = PreparedControlOperation::parse(&self.owner_bytes)?;
        if owner.operation() != self.operation
            || owner.request_id() != self.request_id
            || owner.source() != source
            || owner.target() != target
        {
            return Err(Error::Integrity);
        }
        if source.generation.checked_add(1) != Some(target.generation) {
            return Err(Error::Integrity);
        }
        if self.target_head.get(8..24) != Some(self.request_id.as_slice()) {
            return Err(Error::Integrity);
        }
        for nodes in [&self.source_nodes, &self.nodes] {
            if nodes.len() > POINT_NODES {
                return Err(Error::ResourceLimit);
            }
            for (position, (hash, bytes)) in nodes.iter().enumerate() {
                if bytes.is_empty()
                    || bytes.len() > MAX_NODE_BYTES
                    || crate::index::node_hash(bytes) != *hash
                    || (position > 0 && nodes[position - 1].0 >= *hash)
                {
                    return Err(Error::Integrity);
                }
            }
        }
        if self.obsolete.len() > POINT_NODES
            || self.obsolete.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Integrity);
        }
        match (&self.operation, &self.record) {
            (
                ControlOperation::Save,
                PersistedRecordMutation::Save {
                    revision,
                    envelope,
                    expected,
                    ..
                },
            ) if *revision > 0
                && envelope.len() <= limits.envelope_bytes
                && !envelope.is_empty()
                && expected.as_ref().map_or(*revision == 1, |old| {
                    old.revision > 0 && old.revision.checked_add(1) == Some(*revision)
                }) => {}
            (ControlOperation::Delete, PersistedRecordMutation::Delete { expected, .. })
                if expected.revision > 0 && self.nodes.len() <= POINT_NODES => {}
            (ControlOperation::Credentials, PersistedRecordMutation::None)
                if self.source_nodes.is_empty()
                    && self.nodes.is_empty()
                    && self.obsolete.is_empty() => {}
            _ => return Err(Error::Integrity),
        }
        if self.operation != ControlOperation::Credentials
            && self.source_descriptor != self.target_descriptor
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }

    pub(super) fn encode(&self, limits: StageLimits) -> Result<Vec<u8>> {
        self.validate(limits)?;
        let mut out = Vec::new();
        out.extend_from_slice(TARGET_MAGIC);
        out.extend_from_slice(&self.owner_bytes);
        out.push(self.operation as u8);
        out.extend_from_slice(&self.request_id);
        for bytes in [
            &self.source_descriptor,
            &self.source_head,
            &self.target_descriptor,
            &self.target_head,
        ] {
            blob(&mut out, bytes)?;
        }
        for nodes in [&self.source_nodes, &self.nodes] {
            out.extend_from_slice(
                &u32::try_from(nodes.len())
                    .map_err(|_| Error::ResourceLimit)?
                    .to_be_bytes(),
            );
            for (hash, bytes) in nodes {
                out.extend_from_slice(hash);
                out.extend_from_slice(
                    &u16::try_from(bytes.len())
                        .map_err(|_| Error::ResourceLimit)?
                        .to_be_bytes(),
                );
                out.extend_from_slice(bytes);
            }
        }
        out.extend_from_slice(
            &u32::try_from(self.obsolete.len())
                .map_err(|_| Error::ResourceLimit)?
                .to_be_bytes(),
        );
        for hash in &self.obsolete {
            out.extend_from_slice(hash);
        }
        match &self.record {
            PersistedRecordMutation::None => out.push(0),
            PersistedRecordMutation::Save {
                id,
                revision,
                envelope,
                expected,
            } => {
                out.push(1);
                out.extend_from_slice(id);
                out.extend_from_slice(&revision.to_be_bytes());
                blob(&mut out, envelope)?;
                out.push(u8::from(expected.is_some()));
                if let Some(old) = expected {
                    source_record(&mut out, old);
                }
            }
            PersistedRecordMutation::Delete { id, expected } => {
                out.push(2);
                out.extend_from_slice(id);
                source_record(&mut out, expected);
            }
        }
        if out.len() > Self::maximum_bytes(limits)? {
            return Err(Error::ResourceLimit);
        }
        Ok(out)
    }

    pub(super) fn decode(bytes: &[u8], limits: StageLimits) -> Result<Self> {
        if bytes.len() > Self::maximum_bytes(limits)? {
            return Err(Error::ResourceLimit);
        }
        let mut reader = TargetReader { bytes, at: 0 };
        if &reader.array::<8>()? != TARGET_MAGIC {
            return Err(Error::Malformed("native target"));
        }
        let owner_bytes = reader.take(CONTROL_OWNER_BYTES)?.to_vec();
        let operation = match reader.byte()? {
            1 => ControlOperation::Save,
            2 => ControlOperation::Delete,
            3 => ControlOperation::Credentials,
            _ => return Err(Error::UnsupportedCapability),
        };
        let request_id = reader.array()?;
        let source_descriptor = reader.blob(limits.descriptor_bytes)?;
        let source_head = reader.blob(fogvault::INDEX_HEAD_LEN)?;
        let target_descriptor = reader.blob(limits.descriptor_bytes)?;
        let target_head = reader.blob(fogvault::INDEX_HEAD_LEN)?;
        let source_nodes = reader.nodes()?;
        let nodes = reader.nodes()?;
        let count = reader.count()?;
        let mut obsolete = Vec::with_capacity(count);
        for _ in 0..count {
            obsolete.push(reader.array()?);
        }
        let record = match reader.byte()? {
            0 => PersistedRecordMutation::None,
            1 => {
                let id = reader.array()?;
                let revision = reader.u64()?;
                let envelope = reader.blob(limits.envelope_bytes)?;
                let expected = match reader.byte()? {
                    0 => None,
                    1 => Some(reader.source_record()?),
                    _ => return Err(Error::Malformed("native target record flag")),
                };
                PersistedRecordMutation::Save {
                    id,
                    revision,
                    envelope,
                    expected,
                }
            }
            2 => PersistedRecordMutation::Delete {
                id: reader.array()?,
                expected: reader.source_record()?,
            },
            _ => return Err(Error::Malformed("native target record")),
        };
        if reader.at != bytes.len() {
            return Err(Error::Malformed("native target trailing bytes"));
        }
        let target = Self {
            owner_bytes,
            operation,
            request_id,
            source_descriptor,
            source_head,
            target_descriptor,
            target_head,
            source_nodes,
            nodes,
            obsolete,
            record,
        };
        target.validate(limits)?;
        Ok(target)
    }
}

fn identity(descriptor: &[u8], head: &[u8]) -> Result<SnapshotIdentity> {
    if head.len() != fogvault::INDEX_HEAD_LEN {
        return Err(Error::Integrity);
    }
    Ok(SnapshotIdentity {
        descriptor_digest: crate::crypto::digest(descriptor),
        head_digest: crate::crypto::digest(head),
        generation: u64::from_be_bytes(head[..8].try_into().map_err(|_| Error::Integrity)?),
    })
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| Error::ResourceLimit)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
fn source_record(out: &mut Vec<u8>, record: &SourceRecord) {
    out.extend_from_slice(&record.revision.to_be_bytes());
    out.extend_from_slice(&record.envelope_digest);
}
struct TargetReader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl TargetReader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(len).ok_or(Error::ResourceLimit)?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or(Error::Malformed("native target truncation"))?;
        self.at = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Integrity)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = usize::try_from(self.u64()?).map_err(|_| Error::ResourceLimit)?;
        if len > max {
            return Err(Error::ResourceLimit);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn count(&mut self) -> Result<usize> {
        let count = u32::from_be_bytes(self.array()?) as usize;
        if count > POINT_NODES {
            return Err(Error::ResourceLimit);
        }
        Ok(count)
    }
    fn nodes(&mut self) -> Result<Vec<(NodeHash, Vec<u8>)>> {
        let count = self.count()?;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let hash = self.array()?;
            let len = u16::from_be_bytes(self.array()?) as usize;
            if len > MAX_NODE_BYTES {
                return Err(Error::ResourceLimit);
            }
            nodes.push((hash, self.take(len)?.to_vec()));
        }
        Ok(nodes)
    }
    fn source_record(&mut self) -> Result<SourceRecord> {
        Ok(SourceRecord {
            revision: self.u64()?,
            envelope_digest: self.array()?,
        })
    }
}

impl RegisteredContext {
    pub(super) fn vault_path_for_stage(&self) -> Result<&Path> {
        self.target_path.parent().ok_or(Error::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(vault: [u8; 16], registration: [u8; 16]) -> (PersistedNativeTarget, StageLimits) {
        // Synthetic public codec values, not authenticated vault records.
        let mut target = PersistedNativeTarget {
            owner_bytes: Vec::new(),
            operation: ControlOperation::Save,
            request_id: [7; 16],
            source_descriptor: vec![3],
            source_head: vec![0; fogvault::INDEX_HEAD_LEN],
            target_descriptor: vec![3],
            target_head: vec![0; fogvault::INDEX_HEAD_LEN],
            source_nodes: Vec::new(),
            nodes: Vec::new(),
            obsolete: Vec::new(),
            record: PersistedRecordMutation::Save {
                id: [9; 16],
                revision: 1,
                envelope: vec![8; 16],
                expected: None,
            },
        };
        target.target_head[..8].copy_from_slice(&1u64.to_be_bytes());
        target.target_head[8..24].copy_from_slice(&target.request_id);
        refresh_owner(&mut target, vault, registration);
        (
            target,
            StageLimits {
                descriptor_bytes: 1,
                envelope_bytes: 16,
            },
        )
    }

    fn refresh_owner(target: &mut PersistedNativeTarget, vault: [u8; 16], registration: [u8; 16]) {
        let source = target.source_identity().unwrap();
        let destination = target.target_identity().unwrap();
        let mut owner = Vec::from(*b"FGVOWN01");
        owner.extend_from_slice(&vault);
        owner.extend_from_slice(&registration);
        owner.push(ControlOperation::Save as u8);
        owner.extend_from_slice(&target.request_id);
        for snapshot in [source, destination] {
            owner.extend_from_slice(&snapshot.descriptor_digest);
            owner.extend_from_slice(&snapshot.head_digest);
            owner.extend_from_slice(&snapshot.generation.to_be_bytes());
        }
        target.owner_bytes = owner;
    }

    #[test]
    fn registered_host_pins_path_and_identity_and_never_recreates_missing_control() {
        let temporary = tempfile::tempdir().unwrap();
        let namespace = temporary.path().join("host");
        let host = NativeHost::create_new(&namespace).unwrap();
        assert!(matches!(
            NativeHost::create_new(&namespace),
            Err(Error::Exists)
        ));
        let vault = temporary.path().join("vault");
        std::fs::write(&vault, b"synthetic registration boundary").unwrap();
        let alias = temporary.path().join("alias");
        std::fs::copy(&vault, &alias).unwrap();
        let (target, _) = fixture([1; 16], [2; 16]);
        let context = host
            .register_authenticated(&vault, [1; 16], target.source_identity().unwrap())
            .unwrap();
        assert_eq!(context.vault_id(), [1; 16]);
        assert!(matches!(
            host.refuse_registered_diagnostic(&vault, [9; 16]),
            Err(Error::UnsupportedCapability)
        ));
        assert!(matches!(
            host.refuse_registered_diagnostic(&alias, [1; 16]),
            Err(Error::UnsupportedCapability)
        ));
        assert!(host.refuse_registered_diagnostic(&alias, [9; 16]).is_ok());
        let reopened = NativeHost::open_required(&namespace)
            .unwrap()
            .open_registration(&vault)
            .unwrap();
        assert_eq!(reopened.registration_id(), context.registration_id());
        let control = context.target_path.with_extension("control.sqlite");
        std::fs::remove_file(&control).unwrap();
        assert!(matches!(
            host.open_registration(&vault),
            Err(Error::Integrity)
        ));
        assert!(!control.exists());
    }

    #[test]
    fn registered_target_codec_rejects_partial_oversized_and_mismatched_targets() {
        let (target, limits) = fixture([1; 16], [2; 16]);
        let bytes = target.encode(limits).unwrap();
        assert_eq!(
            PersistedNativeTarget::decode(&bytes, limits).unwrap(),
            target
        );
        for end in 0..bytes.len() {
            assert!(PersistedNativeTarget::decode(&bytes[..end], limits).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PersistedNativeTarget::decode(&trailing, limits).is_err());
        let mut changed = target.clone();
        changed.target_head[25] ^= 1;
        assert!(changed.encode(limits).is_err());
        let mut changed = target.clone();
        if let PersistedRecordMutation::Save { envelope, .. } = &mut changed.record {
            envelope.push(0);
        }
        assert!(changed.encode(limits).is_err());
        let mut changed = target.clone();
        changed.operation = ControlOperation::Import;
        assert!(changed.encode(limits).is_err());
    }

    #[test]
    fn registered_submitted_target_survives_failed_cleanup_and_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let namespace = temporary.path().join("host");
        let host = NativeHost::create_new(&namespace).unwrap();
        let vault = temporary.path().join("vault");
        std::fs::write(&vault, b"synthetic registration boundary").unwrap();
        let (preliminary, _) = fixture([1; 16], [2; 16]);
        let mut context = host
            .register_authenticated(&vault, [1; 16], preliminary.source_identity().unwrap())
            .unwrap();
        let (target, limits) = fixture([1; 16], context.registration_id());
        let owner = PreparedControlOperation::parse(&target.owner_bytes).unwrap();
        let accepted = context.store.load().unwrap().unwrap();
        let prepared = accepted.prepare_ordinary(&owner).unwrap();
        assert_eq!(
            context
                .store
                .compare_exchange(Some(&accepted), &prepared)
                .unwrap(),
            fogvault::ControlWriteOutcome::Stored
        );
        context.persist_target(&target, limits).unwrap();
        assert_eq!(
            context.persist_target(&target, limits).unwrap(),
            crate::crypto::digest(&target.encode(limits).unwrap())
        );
        let submitted = prepared.authorize_ordinary_submission(&owner).unwrap();
        assert_eq!(
            context
                .store
                .compare_exchange(Some(&prepared), &submitted)
                .unwrap(),
            fogvault::ControlWriteOutcome::Stored
        );
        assert!(matches!(context.clear_target(), Err(Error::Conflict)));
        let mut reopened = host.open_registration(&vault).unwrap();
        assert_eq!(reopened.store.load().unwrap(), Some(submitted.clone()));
        assert_eq!(reopened.load_target(limits).unwrap(), target);
        std::fs::write(&reopened.target_path, b"broken retained target").unwrap();
        assert!(reopened.load_target(limits).is_err());
        assert_eq!(reopened.store.load().unwrap(), Some(submitted));
        assert!(reopened.target_path.exists());
    }

    #[test]
    fn registered_completed_stage_cleanup_is_fenced_and_next_prepared_target_is_retained() {
        let temporary = tempfile::tempdir().unwrap();
        let host = NativeHost::create_new(temporary.path().join("host")).unwrap();
        let vault = temporary.path().join("vault");
        std::fs::write(&vault, b"synthetic registration boundary").unwrap();
        let (preliminary, _) = fixture([1; 16], [2; 16]);
        let mut context = host
            .register_authenticated(&vault, [1; 16], preliminary.source_identity().unwrap())
            .unwrap();
        let (first, limits) = fixture([1; 16], context.registration_id());
        let first_owner = PreparedControlOperation::parse(&first.owner_bytes).unwrap();
        let accepted = context.store.load().unwrap().unwrap();
        let prepared = accepted.prepare_ordinary(&first_owner).unwrap();
        context
            .store
            .compare_exchange(Some(&accepted), &prepared)
            .unwrap();
        context.persist_target(&first, limits).unwrap();
        let submitted = prepared
            .authorize_ordinary_submission(&first_owner)
            .unwrap();
        context
            .store
            .compare_exchange(Some(&prepared), &submitted)
            .unwrap();
        {
            let mut guard = context.store.publication_guard(&submitted).unwrap();
            assert!(matches!(
                context.clear_completed_target(&guard, limits),
                Err(Error::Conflict)
            ));
            // This lower-layer fixture chooses a confirmed identity directly;
            // ordinary adapter tests separately prove actual vault publication.
            let completed = submitted
                .confirm_target(first.target_identity().unwrap())
                .unwrap();
            guard.compare_exchange(&completed).unwrap();
        }
        // Deliberately leave accepted-stage cleanup pending, then begin B->C.
        let mut second = first.clone();
        second.source_head = first.target_head.clone();
        second.target_head[..8].copy_from_slice(&2u64.to_be_bytes());
        second.request_id = [8; 16];
        second.target_head[8..24].copy_from_slice(&second.request_id);
        if let PersistedRecordMutation::Save {
            revision, expected, ..
        } = &mut second.record
        {
            *revision = 2;
            *expected = Some(SourceRecord {
                revision: 1,
                envelope_digest: [8; 32],
            });
        }
        refresh_owner(&mut second, [1; 16], context.registration_id());
        let second_owner = PreparedControlOperation::parse(&second.owner_bytes).unwrap();
        let accepted = context.store.load().unwrap().unwrap();
        let prepared = accepted.prepare_ordinary(&second_owner).unwrap();
        context
            .store
            .compare_exchange(Some(&accepted), &prepared)
            .unwrap();
        context.persist_target(&second, limits).unwrap();
        assert_eq!(context.load_target(limits).unwrap(), second);
        let guard = context.store.publication_guard(&prepared).unwrap();
        assert!(matches!(
            context.clear_completed_target(&guard, limits),
            Err(Error::Conflict)
        ));
        assert!(context.target_path.exists());
    }

    #[test]
    fn registered_delete_rejects_retained_recipe_that_reclaims_promoted_sibling() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("vault.sqlite");
        let host = NativeHost::create_new(temporary.path().join("host")).unwrap();
        let limits = Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 0,
            max_records: 2,
        };
        let mut vault = host
            .create(
                &path,
                b"SYNTHETIC-test-password",
                limits,
                KdfPolicy::baseline(),
            )
            .unwrap();
        let token = vault.unlock(b"SYNTHETIC-test-password").unwrap();
        vault
            .save(&token, [1; 16], None, b"", b"removed", [11; 16])
            .unwrap();
        vault
            .save(&token, [2; 16], None, b"", b"retained", [12; 16])
            .unwrap();
        let request = [13; 16];
        assert!(matches!(
            vault.delete_with_fault(&token, [1; 16], 1, request, CommitFault::BeforeCommit),
            Err(Error::OutcomeUnknown { .. })
        ));
        let context = vault.registered.clone().unwrap();
        let stage_limits = StageLimits {
            descriptor_bytes: vault.engine.descriptor_byte_limit(),
            envelope_bytes: vault.engine.envelope_byte_limit().unwrap(),
        };
        let target = context.load_target(stage_limits).unwrap();
        assert!(
            target.nodes.is_empty(),
            "two-leaf delete promotes an existing sibling"
        );
        let promoted: NodeHash = target.target_head[65..97].try_into().unwrap();
        assert!(target
            .source_nodes
            .iter()
            .any(|(hash, _)| *hash == promoted));
        assert!(!target.obsolete.contains(&promoted));
        let original_target = std::fs::read(&context.target_path).unwrap();
        let mut corrupted = target.clone();
        corrupted.obsolete.push(promoted);
        corrupted.canonicalize();
        // Simulate a corrupted recipe inside the protected namespace. This is
        // defense in depth, not a claim that the vault-file attacker owns it.
        std::fs::write(
            &context.target_path,
            corrupted.encode(stage_limits).unwrap(),
        )
        .unwrap();
        let source_bytes = std::fs::read(&path).unwrap();
        let control = vault.registered_control_state().unwrap();
        assert!(matches!(
            vault.reconcile_registered(request),
            Err(Error::Integrity)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), source_bytes);
        assert_eq!(vault.registered_control_state().unwrap(), control);
        assert!(context.target_path.exists());
        // Restoring the original retained exact plan still resolves safely.
        std::fs::write(&context.target_path, original_target).unwrap();
        vault.reconcile_registered(request).unwrap();
        let token = vault.unlock(b"SYNTHETIC-test-password").unwrap();
        assert_eq!(
            vault.read(&token, [2; 16]).unwrap().payload.as_slice(),
            b"retained"
        );
        assert!(matches!(vault.read(&token, [1; 16]), Err(Error::NotFound)));
    }

    #[test]
    fn registered_control_revision_ceiling_reserves_complete_publication_before_writes() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("vault.sqlite");
        let host = NativeHost::create_new(temporary.path().join("host")).unwrap();
        let limits = Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 0,
            max_records: 1,
        };
        let password = b"SYNTHETIC-control-ceiling-password";
        let mut vault = host
            .create(&path, password, limits, KdfPolicy::baseline())
            .unwrap();
        let token = vault.unlock(password).unwrap();
        let context = vault.registered.clone().unwrap();
        let control_path = context.target_path.with_extension("control.sqlite");

        // Fixture-only authority over protected control bytes. This directly
        // selects the fixed u64 codec boundary; it is not a product quota or
        // a claim that the vault-file attacker can modify control state.
        let set_revision = |revision: u64| {
            let mut bytes = vault.registered_control_state().unwrap().encode();
            bytes[40..48].copy_from_slice(&revision.to_be_bytes());
            let connection = Connection::open(&control_path).unwrap();
            assert_eq!(
                connection
                    .execute("UPDATE control_state SET state=?1 WHERE id=1", [bytes])
                    .unwrap(),
                1
            );
        };
        set_revision(u64::MAX - 2);
        let source_before = std::fs::read(&path).unwrap();
        let control_before = std::fs::read(&control_path).unwrap();
        assert!(matches!(
            vault.save(&token, [1; 16], None, b"", b"cannot finish", [21; 16]),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), source_before);
        assert_eq!(std::fs::read(&control_path).unwrap(), control_before);
        assert!(!context.target_path.exists());
        assert!(vault
            .registered_control_state()
            .unwrap()
            .pending()
            .is_none());
        assert!(matches!(vault.read(&token, [1; 16]), Err(Error::NotFound)));

        // Three remaining increments permit Prepare, Submitted and Accepted.
        let mut bytes = vault.registered_control_state().unwrap().encode();
        bytes[40..48].copy_from_slice(&(u64::MAX - 3).to_be_bytes());
        let connection = Connection::open(&control_path).unwrap();
        connection
            .execute("UPDATE control_state SET state=?1 WHERE id=1", [bytes])
            .unwrap();
        drop(connection);
        vault
            .save(
                &token,
                [1; 16],
                None,
                b"",
                b"last permitted publication",
                [22; 16],
            )
            .unwrap();
        let completed = vault.registered_control_state().unwrap();
        assert_eq!(completed.revision(), u64::MAX);
        assert!(completed.pending().is_none());
        assert_eq!(
            vault.read(&token, [1; 16]).unwrap().payload.as_slice(),
            b"last permitted publication"
        );
        let source_before = std::fs::read(&path).unwrap();
        let control_before = std::fs::read(&control_path).unwrap();
        assert!(matches!(
            vault.save(&token, [1; 16], Some(1), b"", b"must refuse", [23; 16]),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), source_before);
        assert_eq!(std::fs::read(&control_path).unwrap(), control_before);
        assert!(!context.target_path.exists());
        assert_eq!(
            vault.read(&token, [1; 16]).unwrap().payload.as_slice(),
            b"last permitted publication"
        );
    }

    #[test]
    fn registered_native_sql_revision_ceiling_preserves_last_readable_record() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("vault.sqlite");
        let host = NativeHost::create_new(temporary.path().join("host")).unwrap();
        let limits = Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 0,
            max_records: 1,
        };
        let password = b"SYNTHETIC-SQL-revision-ceiling-password";
        let id = [31; 16];
        let maximum = i64::MAX as u64;
        let diagnostic = Vault::diagnostic_create_current(&path, password, limits).unwrap();
        let descriptor = crate::format::Descriptor::diagnostic_parse_current_portable_with_policy(
            diagnostic.engine.descriptor_bytes(),
            &KdfPolicy::baseline(),
        )
        .unwrap();
        let root = descriptor.unlock(password).unwrap();
        let wrapping =
            crate::crypto::derive(&root, &descriptor.vault_id, b"record-key-wrapping").unwrap();
        let head_key =
            crate::crypto::derive(&root, &descriptor.vault_id, b"head-authentication").unwrap();
        let envelope = crate::format::encrypt_record(
            &descriptor,
            &wrapping,
            &id,
            maximum - 1,
            b"",
            b"authenticated high revision",
            limits,
        )
        .unwrap();
        drop(diagnostic);
        // Fixture generation uses public synthetic credentials and experimental
        // codecs to avoid billions of writes; the source is genuinely encrypted
        // and its complete head/index/record are authenticated before enrollment.
        let mut connection = Connection::open(&path).unwrap();
        let transaction = connection.transaction().unwrap();
        let entry = crate::format::Entry {
            revision: maximum - 1,
            digest: crate::crypto::digest(&envelope),
        };
        let change = crate::index::upsert(
            &mut SqliteNodes::new(&transaction, u64::MAX),
            None,
            id,
            entry,
        )
        .unwrap();
        let head = crate::format::IndexHead {
            generation: 1,
            request_id: [32; 16],
            operation_digest: [33; 32],
            count: 1,
            root: Some(change.root),
        }
        .encode(&descriptor, &head_key);
        transaction
            .execute(
                "INSERT INTO records VALUES(?1,?2,?3)",
                params![id.as_slice(), i64::MAX - 1, envelope],
            )
            .unwrap();
        transaction
            .execute("UPDATE vault_state SET head=?1 WHERE id=1", [head])
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);
        let mut vault =
            Vault::diagnostic_open_current_with_kdf_policy(&path, limits, KdfPolicy::baseline())
                .unwrap();
        let token = vault.unlock(password).unwrap();
        host.register_existing(&mut vault, &token).unwrap();
        assert_eq!(vault.read(&token, id).unwrap().revision, maximum - 1);
        vault
            .save(
                &token,
                id,
                Some(maximum - 1),
                b"",
                b"last valid SQL revision",
                [34; 16],
            )
            .unwrap();
        let record = vault.read(&token, id).unwrap();
        assert_eq!(record.revision, maximum);
        assert_eq!(record.payload.as_slice(), b"last valid SQL revision");
        let context = vault.registered.clone().unwrap();
        let control_path = context.target_path.with_extension("control.sqlite");
        let source = std::fs::read(&path).unwrap();
        let control = std::fs::read(&control_path).unwrap();
        assert!(matches!(
            vault.save(
                &token,
                id,
                Some(maximum),
                b"",
                b"unrepresentable SQL revision",
                [35; 16]
            ),
            Err(Error::ResourceLimit)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), source);
        assert_eq!(std::fs::read(&control_path).unwrap(), control);
        assert!(!context.target_path.exists());
        assert!(vault
            .registered_control_state()
            .unwrap()
            .pending()
            .is_none());
        let record = vault.read(&token, id).unwrap();
        assert_eq!(record.revision, maximum);
        assert_eq!(record.payload.as_slice(), b"last valid SQL revision");
    }
}
