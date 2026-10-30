//! Admission for the adapter's deliberately small executable SQLite surface.
//!
//! A database file supplies SQL schema as well as encrypted rows. Admission is
//! repeated inside each operation's snapshot/IMMEDIATE writer transaction; a
//! successful open is not permission to trust a later schema. This does not
//! qualify arbitrary corrupt SQLite pages, concurrent raw-file writes or the VM.
use super::*;
use rusqlite::{
    config::DbConfig,
    hooks::{AuthAction, AuthContext, Authorization},
};

pub(super) const VAULT_STATE: &str = "CREATE TABLE vault_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                descriptor BLOB NOT NULL,
                head BLOB NOT NULL
             )";
pub(super) const RECORDS: &str = "CREATE TABLE records (
                id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
                revision INTEGER NOT NULL CHECK(revision > 0),
                envelope BLOB NOT NULL
             )";
pub(super) const INDEX_NODES: &str = "CREATE TABLE index_nodes (
                hash BLOB PRIMARY KEY NOT NULL CHECK(length(hash) = 32),
                bytes BLOB NOT NULL CHECK(length(bytes) <= 82)
             )";

pub(super) fn initialize(connection: &Connection) -> Result<()> {
    for statement in [VAULT_STATE, RECORDS, INDEX_NODES] {
        connection.execute_batch(statement).storage()?;
    }
    admit(connection)
}

/// Configure before the first schema-dependent statement, even for inspection.
pub(super) fn harden(connection: &Connection) -> Result<()> {
    for (setting, value) in [
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
    ] {
        if connection.set_db_config(setting, value).storage()? != value
            || connection.db_config(setting).storage()? != value
        {
            return Err(Error::UnsupportedCapability);
        }
    }
    connection
        .execute_batch("PRAGMA mmap_size=0; PRAGMA cell_size_check=ON;")
        .storage()?;
    Ok(())
}

/// The adapter has no SQL escape hatch. Keep future changes from accidentally
/// adding DDL, attached/temp state, schema callbacks or arbitrary functions.
pub(super) fn seal(connection: &Connection) -> Result<()> {
    connection
        .authorizer(Some(|context: AuthContext<'_>| {
            let allowed = context.accessor.is_none()
                && context
                    .database_name
                    .is_none_or(|database| database == "main")
                && match context.action {
                    AuthAction::Read { table_name, .. } => matches!(
                        table_name,
                        "vault_state"
                            | "records"
                            | "index_nodes"
                            | "sqlite_master"
                            | "sqlite_schema"
                    ),
                    AuthAction::Insert { table_name }
                    | AuthAction::Delete { table_name }
                    | AuthAction::Update { table_name, .. } => {
                        matches!(table_name, "vault_state" | "records" | "index_nodes")
                    }
                    AuthAction::Function { function_name } => {
                        matches!(function_name, "length" | "count")
                    }
                    AuthAction::Select
                    | AuthAction::Transaction { .. }
                    | AuthAction::Savepoint { .. } => true,
                    // Private adapter capacity experiments use these status/limit
                    // pragmas. None changes schema, journal or execution policy.
                    AuthAction::Pragma {
                        pragma_name: "journal_mode",
                        pragma_value: None,
                    } => true,
                    AuthAction::Pragma { pragma_name, .. } => {
                        matches!(pragma_name, "page_count" | "page_size" | "max_page_count")
                    }
                    _ => false,
                };
            if allowed {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }))
        .storage()
}

pub(super) fn inspect(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .storage()?;
    harden(&connection)?;
    seal(&connection)?;
    Ok(connection)
}

// Token comparison preserves word boundaries: removing all whitespace would
// incorrectly equate distinct identifiers/types. Quoting/comments are not part
// of either existing adapter DDL and therefore reject rather than normalize.
fn tokens(sql: &str) -> Result<Vec<String>> {
    let mut output = Vec::new();
    let mut word = String::new();
    for byte in sql.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            word.push(char::from(byte.to_ascii_lowercase()));
        } else {
            if !word.is_empty() {
                output.push(std::mem::take(&mut word));
            }
            if byte.is_ascii_whitespace() {
                continue;
            }
            if !matches!(byte, b'(' | b')' | b',' | b'=' | b'>' | b'<') {
                return Err(Error::Integrity);
            }
            output.push(char::from(byte).to_string());
        }
    }
    if !word.is_empty() {
        output.push(word);
    }
    Ok(output)
}

pub(super) fn admit(connection: &Connection) -> Result<()> {
    // This adapter has exercised only DELETE-journal transactions. Do not
    // silently inherit WAL/OFF/MEMORY completion semantics from a modified file
    // or change an unknown file's persistent journal mode while opening it.
    let journal: String = connection
        .query_row("PRAGMA main.journal_mode", [], |r| r.get(0))
        .map_err(|_| Error::Integrity)?;
    if journal != "delete" {
        return Err(Error::UnsupportedCapability);
    }
    // Three exact tables plus their two implicit primary-key indexes. Any
    // trigger, view, extra object or renamed/replaced definition is unsupported.
    const EXPECTED: [(&str, &str, &str, Option<&str>); 5] = [
        (
            "index",
            "sqlite_autoindex_index_nodes_1",
            "index_nodes",
            None,
        ),
        ("index", "sqlite_autoindex_records_1", "records", None),
        ("table", "index_nodes", "index_nodes", Some(INDEX_NODES)),
        ("table", "records", "records", Some(RECORDS)),
        ("table", "vault_state", "vault_state", Some(VAULT_STATE)),
    ];
    let count: i64 = connection
        .query_row("SELECT count(*) FROM main.sqlite_schema", [], |r| r.get(0))
        .map_err(|_| Error::Integrity)?;
    // Recognize only the exact historical two-table layout for a typed
    // unsupported-format rejection. It is never admitted for record I/O.
    let legacy = count == 3;
    if !legacy && count != EXPECTED.len() as i64 {
        return Err(Error::Integrity);
    }
    let mut roots = std::collections::BTreeSet::new();
    for (kind, name, table, expected_sql) in EXPECTED {
        if legacy && table == "index_nodes" {
            continue;
        }
        // Admit exact metadata lengths before copying attacker-controlled SQL.
        // The maximum is derived from the supported legacy CREATE spelling,
        // not a new product capacity. Both old creation styles fit this bound.
        let lengths: (i64, i64, i64, Option<i64>, i64) = connection.query_row(
            "SELECT length(type),length(name),length(tbl_name),length(CAST(sql AS BLOB)),rootpage FROM main.sqlite_schema WHERE name=?1",
            [name], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))
            .map_err(|_| Error::Integrity)?;
        if lengths.0 != kind.len() as i64
            || lengths.1 != name.len() as i64
            || lengths.2 != table.len() as i64
            // Page one belongs to SQLite's schema. Each admitted table/index
            // must own a distinct positive B-tree root; canonical SQL alone
            // does not prevent writable_schema root-page aliases.
            || lengths.4 <= 1
            || !roots.insert(lengths.4)
            || match (lengths.3, expected_sql) {
                (None, None) => false,
                (Some(actual), Some(expected)) => actual < 0 || actual > expected.len() as i64,
                _ => true,
            }
        {
            return Err(Error::Integrity);
        }
        let actual: (String, String, String, Option<String>) = connection
            .query_row(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| Error::Integrity)?;
        if actual.0 != kind || actual.1 != name || actual.2 != table {
            return Err(Error::Integrity);
        }
        match (actual.3.as_deref(), expected_sql) {
            (None, None) => {}
            (Some(actual), Some(expected)) if tokens(actual)? == tokens(expected)? => {}
            _ => return Err(Error::Integrity),
        }
    }
    if legacy {
        return Err(Error::Malformed("legacy native schema unsupported"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_schema_writer_transaction_prevents_admission_mutation_race() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("schema-race.sqlite");
        let limits = Limits {
            max_payload_bytes: 64,
            max_metadata_bytes: 16,
            max_records: 4,
        };
        drop(Vault::diagnostic_create(&path, b"schema-race-synthetic", limits).unwrap());
        let mut connection = connect(&path, false).unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        admit(&transaction).unwrap();
        let attacker = Connection::open(&path).unwrap();
        attacker.busy_timeout(std::time::Duration::ZERO).unwrap();
        let error = attacker
            .execute_batch(
                "CREATE TRIGGER race AFTER INSERT ON records BEGIN DELETE FROM records; END;",
            )
            .unwrap_err();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(error, _) if error.code == rusqlite::ErrorCode::DatabaseBusy)
        );
        transaction.rollback().unwrap();
        attacker
            .execute_batch(
                "CREATE TRIGGER race AFTER INSERT ON records BEGIN DELETE FROM records; END;",
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(admit(&transaction), Err(Error::Integrity)));
        transaction.rollback().unwrap();
    }

    #[test]
    fn native_schema_connection_rejects_temp_schema_and_attach() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("sealed.sqlite");
        drop(
            Vault::diagnostic_create(
                &path,
                b"schema-seal-synthetic",
                Limits {
                    max_payload_bytes: 64,
                    max_metadata_bytes: 16,
                    max_records: 4,
                },
            )
            .unwrap(),
        );
        let connection = connect(&path, false).unwrap();
        for sql in [
            "CREATE TEMP TABLE external(value BLOB)",
            "ATTACH ':memory:' AS external",
            "CREATE TRIGGER external AFTER INSERT ON records BEGIN DELETE FROM records; END",
            "PRAGMA trusted_schema=ON",
            "SELECT randomblob(100)",
        ] {
            assert!(connection.execute_batch(sql).is_err(), "{sql}");
        }
        let transaction = connection.unchecked_transaction().unwrap();
        admit(&transaction).unwrap();
        transaction.commit().unwrap();
    }
}
