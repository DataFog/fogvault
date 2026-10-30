#![cfg(all(feature = "native", not(target_arch = "wasm32")))]
use fogvault::KdfPolicy;
use fogvault_disposable_prototype::{CommitFault, Error, Limits, Vault};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::{Arc, Barrier},
};
use tempfile::tempdir;
const PASSWORD: &[u8] = b"synthetic-process-writer-password";
const ID: [u8; 16] = [0x61; 16];
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 1024,
        max_metadata_bytes: 0,
        max_records: 1,
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn child(mode: &str, path: &std::path::Path) -> Process {
    let mut process = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_process_writer_fixture", "--nocapture"])
            .env("FOGVAULT_SYNTHETIC_WRITER_MODE", mode)
            .env("FOGVAULT_SYNTHETIC_WRITER_PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let output = process.0.stdout.take().unwrap();
    let mut reader = BufReader::new(output);
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "writer exited before readiness"
        );
        if line.trim_end().ends_with("WRITER_READY") {
            break;
        }
    }
    process.0.stdout = Some(reader.into_inner());
    process
}
#[test]
fn native_process_writer_fixture() {
    let Ok(mode) = std::env::var("FOGVAULT_SYNTHETIC_WRITER_MODE") else {
        return;
    };
    let path = std::env::var_os("FOGVAULT_SYNTHETIC_WRITER_PATH").unwrap();
    if mode == "hold-transaction" {
        let mut connection = rusqlite::Connection::open(path).unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        transaction.execute("DELETE FROM records", []).unwrap();
        println!("WRITER_READY");
        std::io::stdout().flush().unwrap();
        let mut byte = [0];
        let _ = std::io::stdin().read_exact(&mut byte);
        drop(transaction); // Parent kills this OS process before rollback runs.
    } else {
        let mut vault = Vault::diagnostic_open(path, limits()).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        println!("WRITER_READY");
        std::io::stdout().flush().unwrap();
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte).unwrap();
        assert!(matches!(
            vault.save(&token, ID, Some(1), b"", b"stale child", [3; 16]),
            Err(Error::Conflict)
        ));
    }
}
#[test]
fn native_real_process_death_releases_writer_and_stale_process_cannot_commit() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("process.sqlite");
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"", b"accepted", [1; 16])
        .unwrap();
    let mut held = child("hold-transaction", &path);
    held.0.kill().unwrap();
    assert!(!held.0.wait().unwrap().success());
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"accepted"
    );
    let mut stale = child("stale-snapshot", &path);
    vault
        .save(&token, ID, Some(1), b"", b"fresh parent", [2; 16])
        .unwrap();
    stale.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    assert!(stale.0.wait().unwrap().success());
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"fresh parent"
    );
}
#[test]
fn native_prepared_creators_race_and_orphan_cleanup_is_explicit() {
    let scratch = tempdir().unwrap();
    let path = scratch.path().join("create-race.sqlite");
    let abandoned =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    let receipt = abandoned.receipt();
    assert!(matches!(
        abandoned.publish(&path, CommitFault::BeforeCommit),
        Err(Error::InjectedFailure)
    ));
    assert!(!path.exists());
    Vault::discard_creation_stage(scratch.path(), &receipt, limits(), fogvault::DESCRIPTOR_LEN)
        .unwrap();
    assert!(!path.exists());
    let first =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    let second =
        Vault::diagnostic_prepare_creation(PASSWORD, limits(), KdfPolicy::baseline()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for prepared in [first, second] {
        let path = path.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            match prepared.publish(path, CommitFault::None) {
                Ok(vault) => {
                    drop(vault);
                    true
                }
                Err(Error::Exists) => false,
                Err(error) => panic!("unexpected publication outcome: {error}"),
            }
        }));
    }
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap().then_some(()))
            .count(),
        1
    );
    let mut vault = Vault::diagnostic_open(&path, limits()).unwrap();
    assert!(vault.unlock(PASSWORD).is_ok());
}
