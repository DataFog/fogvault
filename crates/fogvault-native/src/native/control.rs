//! Control store in an independently protected host namespace.
//! A separate pathname alone is not independent trust. Host registration must
//! protect this namespace and stable coordinator inode against the vault/staging
//! attacker. Control-store rollback, hostile host and power loss are unqualified.
use super::*;
use fogvault::{ControlState, ControlWriteOutcome, TrustedControlStore, CONTROL_STATE_BYTES};
use rusqlite::config::DbConfig;
use std::{fs::File, path::PathBuf};
const DDL:&str="CREATE TABLE control_state(id INTEGER PRIMARY KEY CHECK(id=1),state BLOB NOT NULL CHECK(length(state)=275))";
#[derive(Clone)]
pub struct ProtectedControlSqliteStore {
    database: PathBuf,
    lock_path: PathBuf,
    vault_id: [u8; 16],
    registration_id: [u8; 16],
}
/// All registered writers hold this coordinator through live control validation,
/// vault publication and control completion. No KDF/provider work while held.
pub struct ControlPublicationGuard<'a> {
    store: &'a ProtectedControlSqliteStore,
    _lock: File,
    current: ControlState,
    valid: bool,
}
impl ProtectedControlSqliteStore {
    fn configuration(
        database: PathBuf,
        lock_path: PathBuf,
        vault_id: [u8; 16],
        registration_id: [u8; 16],
    ) -> Result<Self> {
        if !database.is_absolute() || !lock_path.is_absolute() || database == lock_path {
            return Err(Error::Malformed("trusted control namespace"));
        }
        Ok(Self {
            database,
            lock_path,
            vault_id,
            registration_id,
        })
    }
    /// Explicit owner registration only. Never overwrites an occupied namespace.
    pub fn create_new(
        database: PathBuf,
        lock_path: PathBuf,
        initial: ControlState,
    ) -> Result<Self> {
        if initial.revision() != 0 || initial.pending().is_some() {
            return Err(Error::Conflict);
        }
        let store = Self::configuration(
            database,
            lock_path,
            initial.vault_id(),
            initial.registration_id(),
        )?;
        let reserve = |path: &Path| -> Result<File> {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Exists
                } else {
                    Error::Storage
                }
            })
        };
        drop(reserve(&store.database)?);
        let coordinator = reserve(&store.lock_path)?;
        coordinator.lock().map_err(|_| Error::Storage)?;
        let mut connection = store.connect(false)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        transaction.execute_batch(DDL).storage()?;
        transaction
            .execute("INSERT INTO control_state VALUES(1,?1)", [initial.encode()])
            .storage()?;
        transaction.commit().storage()?;
        super::durability::directory_sync(store.database.parent().ok_or(Error::Storage)?)?;
        Ok(store)
    }
    /// Required control state and coordinator are opened without CREATE.
    pub fn open_required(
        database: PathBuf,
        lock_path: PathBuf,
        vault_id: [u8; 16],
        registration_id: [u8; 16],
    ) -> Result<Self> {
        let store = Self::configuration(database, lock_path, vault_id, registration_id)?;
        {
            let _guard = store.lock()?;
            store.load_item()?;
        }
        Ok(store)
    }
    fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Error::Integrity
                } else {
                    Error::Storage
                }
            })?;
        file.lock().map_err(|_| Error::Storage)?;
        Ok(file)
    }
    fn connect(&self, admit: bool) -> Result<Connection> {
        let connection = Connection::open_with_flags(
            &self.database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| Error::Integrity)?;
        for (setting, value) in [
            (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
            (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
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
            let journal: String = connection
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .storage()?;
            let count: i64 = connection
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
                .storage()?;
            let sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name='control_state'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Integrity)?;
            if journal != "delete" || count != 1 || sql != DDL {
                return Err(Error::Integrity);
            }
        }
        Ok(connection)
    }
    fn identity(&self, state: &ControlState) -> Result<()> {
        if state.vault_id() != self.vault_id || state.registration_id() != self.registration_id {
            Err(Error::Integrity)
        } else {
            Ok(())
        }
    }
    fn read_state(&self, connection: &Connection) -> Result<ControlState> {
        let(length,count):(i64,i64)=connection.query_row("SELECT length(state),(SELECT count(*) FROM control_state) FROM control_state WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|Error::Integrity)?;
        if length != CONTROL_STATE_BYTES as i64 || count != 1 {
            return Err(Error::Integrity);
        }
        let bytes: Vec<u8> = connection
            .query_row("SELECT state FROM control_state WHERE id=1", [], |r| {
                r.get(0)
            })
            .storage()?;
        let state = ControlState::parse(&bytes)?;
        self.identity(&state)?;
        Ok(state)
    }
    fn load_item(&self) -> Result<ControlState> {
        let mut connection = self.connect(true)?;
        let transaction = connection.transaction().storage()?;
        let state = self.read_state(&transaction)?;
        transaction.commit().storage()?;
        Ok(state)
    }
    fn compare_exchange_item(
        &self,
        expected: Option<&ControlState>,
        replacement: &ControlState,
    ) -> Result<ControlWriteOutcome> {
        let expected = expected.ok_or(Error::Conflict)?;
        self.identity(expected)?;
        self.identity(replacement)?;
        if expected.revision().checked_add(1) != Some(replacement.revision()) {
            return Err(Error::Conflict);
        }
        let mut connection = self.connect(true)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        if self.read_state(&transaction)? != *expected {
            return Ok(ControlWriteOutcome::Conflict);
        }
        if transaction
            .execute(
                "UPDATE control_state SET state=?1 WHERE id=1 AND state=?2",
                params![replacement.encode(), expected.encode()],
            )
            .storage()?
            != 1
        {
            return Ok(ControlWriteOutcome::Conflict);
        }
        #[cfg(test)]
        if std::env::var("FOGVAULT_CONTROL_SQL_PAUSE").ok().as_deref() == Some("before-commit") {
            if let Some(marker) = std::env::var_os("FOGVAULT_CONTROL_SQL_MARKER") {
                std::fs::write(marker, b"control-update-executed-before-commit")
                    .map_err(|_| Error::Storage)?;
                loop {
                    std::thread::park();
                }
            }
        }
        match transaction.commit() {
            Ok(()) => {
                #[cfg(test)]
                if std::env::var("FOGVAULT_CONTROL_SQL_PAUSE").ok().as_deref()
                    == Some("after-commit")
                {
                    if let Some(marker) = std::env::var_os("FOGVAULT_CONTROL_SQL_MARKER") {
                        std::fs::write(marker, b"control-commit-completed-before-reply")
                            .map_err(|_| Error::Storage)?;
                        loop {
                            std::thread::park();
                        }
                    }
                }
                Ok(ControlWriteOutcome::Stored)
            }
            Err(_) => Ok(ControlWriteOutcome::Unknown),
        }
    }
    pub fn publication_guard(
        &self,
        expected: &ControlState,
    ) -> Result<ControlPublicationGuard<'_>> {
        self.identity(expected)?;
        let lock = self.lock()?;
        if self.load_item()? != *expected {
            return Err(Error::Conflict);
        }
        Ok(ControlPublicationGuard {
            store: self,
            _lock: lock,
            current: expected.clone(),
            valid: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> ControlState {
        ControlState::register(
            [1; 16],
            [2; 16],
            fogvault::SnapshotIdentity {
                descriptor_digest: [3; 32],
                head_digest: [4; 32],
                generation: 0,
            },
        )
    }
    #[test]
    fn protected_control_registration_and_cas_reject_reset_foreign_identity_and_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sqlite");
        let lock = temp.path().join("control.lock");
        let original = state();
        let mut store =
            ProtectedControlSqliteStore::create_new(path.clone(), lock.clone(), original.clone())
                .unwrap();
        assert_eq!(store.load().unwrap(), Some(original.clone()));
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            ProtectedControlSqliteStore::create_new(path.clone(), lock.clone(), original.clone()),
            Err(Error::Exists)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(matches!(
            ProtectedControlSqliteStore::open_required(
                path.clone(),
                lock.clone(),
                [9; 16],
                [2; 16]
            ),
            Err(Error::Integrity)
        ));
        assert!(matches!(
            store.compare_exchange(None, &original),
            Err(Error::Conflict)
        ));
        let next = original
            .prepare(fogvault::ControlOperation::Save, [5; 16], [3; 32], [6; 32])
            .unwrap();
        assert_eq!(
            store.compare_exchange(Some(&original), &next).unwrap(),
            ControlWriteOutcome::Stored
        );
        assert_eq!(
            store.compare_exchange(Some(&original), &next).unwrap(),
            ControlWriteOutcome::Conflict
        );
        assert!(matches!(
            store.compare_exchange(Some(&next), &original),
            Err(Error::Conflict)
        ));
        assert_eq!(store.load().unwrap(), Some(next));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(store.load(), Err(Error::Integrity)));
        assert!(matches!(
            ProtectedControlSqliteStore::open_required(path.clone(), lock, [1; 16], [2; 16]),
            Err(Error::Integrity)
        ));
        assert!(!path.exists());
    }
    #[test]
    fn protected_control_missing_coordinator_is_not_recreated() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.sqlite");
        let lock = temp.path().join("control.lock");
        drop(ProtectedControlSqliteStore::create_new(path.clone(), lock.clone(), state()).unwrap());
        let before = std::fs::read(&path).unwrap();
        std::fs::remove_file(&lock).unwrap();
        assert!(matches!(
            ProtectedControlSqliteStore::open_required(
                path.clone(),
                lock.clone(),
                [1; 16],
                [2; 16]
            ),
            Err(Error::Integrity)
        ));
        assert!(!lock.exists());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}
impl TrustedControlStore for ProtectedControlSqliteStore {
    fn load(&mut self) -> Result<Option<ControlState>> {
        let _lock = self.lock()?;
        self.load_item().map(Some)
    }
    fn compare_exchange(
        &mut self,
        expected: Option<&ControlState>,
        replacement: &ControlState,
    ) -> Result<ControlWriteOutcome> {
        let _lock = self.lock()?;
        self.compare_exchange_item(expected, replacement)
    }
}
impl ControlPublicationGuard<'_> {
    pub(super) fn belongs_to(&self, store: &ProtectedControlSqliteStore) -> bool {
        self.store.database == store.database
            && self.store.lock_path == store.lock_path
            && self.store.vault_id == store.vault_id
            && self.store.registration_id == store.registration_id
    }
    pub fn current(&self) -> &ControlState {
        &self.current
    }
    #[cfg(any(test, feature = "diagnostics"))]
    pub fn state(&self) -> &ControlState {
        &self.current
    }
    pub fn compare_exchange(&mut self, replacement: &ControlState) -> Result<ControlWriteOutcome> {
        if !self.valid {
            return Ok(ControlWriteOutcome::Unknown);
        }
        let outcome = self
            .store
            .compare_exchange_item(Some(&self.current), replacement)?;
        match outcome {
            ControlWriteOutcome::Stored => {
                self.current = replacement.clone();
                Ok(outcome)
            }
            ControlWriteOutcome::Unknown
                if self
                    .store
                    .load_item()
                    .is_ok_and(|actual| actual == *replacement) =>
            {
                self.current = replacement.clone();
                Ok(ControlWriteOutcome::Stored)
            }
            other => {
                self.valid = false;
                Ok(other)
            }
        }
    }
}
#[cfg(test)]
#[path = "control_proof.rs"]
mod proof;
