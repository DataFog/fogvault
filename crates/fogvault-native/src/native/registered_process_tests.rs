//! Parent-only process loss at ordinary registered mutation boundaries.
//! These are local process/SQLite proofs, not physical power-loss qualification.
use super::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const PASSWORD: &[u8] = b"SYNTHETIC-registered-process-password";
const ID: [u8; 16] = [0xd1; 16];
const REQUEST: [u8; 16] = [0xd2; 16];
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 64,
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

#[test]
fn registered_native_parent_death_fixture() {
    let Some(namespace) = std::env::var_os("FOGVAULT_REGISTERED_DEATH_NAMESPACE") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("FOGVAULT_REGISTERED_DEATH_VAULT").unwrap());
    let host = NativeHost::open_required(namespace).unwrap();
    let mut vault = host.open(&path, limits(), KdfPolicy::baseline()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    if std::env::var("FOGVAULT_REGISTERED_DEATH_MODE").as_deref() == Ok("race") {
        println!("REGISTERED_WRITE_READY");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_exact(&mut [0; 1]).unwrap();
        let request_byte: u8 = std::env::var("FOGVAULT_REGISTERED_RACE_REQUEST")
            .unwrap()
            .parse()
            .unwrap();
        let request =
            if std::env::var("FOGVAULT_REGISTERED_RACE_SAME_REQUEST").as_deref() == Ok("true") {
                [0xd5; 16]
            } else {
                [request_byte; 16]
            };
        let result = vault.save(&token, ID, None, b"", &[request_byte], request);
        match result {
            Ok(receipt) => {
                assert_eq!(receipt.generation, 1);
                println!("REGISTERED_RACE_COMMITTED");
            }
            Err(Error::Conflict) => println!("REGISTERED_RACE_CONFLICT"),
            Err(error) => panic!("unexpected concurrent registered outcome: {error:?}"),
        }
        std::io::stdout().flush().unwrap();
    } else {
        // The cfg(test) publication pause is in the ordinary Vault::save path.
        // The parent kills only this caller after the actual durable boundary.
        vault
            .save(&token, ID, None, b"", b"exact retained target", REQUEST)
            .unwrap();
        panic!("process fixture did not reach the selected pause");
    }
}

fn process(namespace: &Path, path: &Path, mode: &str, request: u8, same_request: bool) -> Process {
    Process(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native::registered_process_tests::registered_native_parent_death_fixture",
                "--nocapture",
            ])
            .env("FOGVAULT_REGISTERED_DEATH_NAMESPACE", namespace)
            .env("FOGVAULT_REGISTERED_DEATH_VAULT", path)
            .env("FOGVAULT_REGISTERED_DEATH_MODE", mode)
            .env("FOGVAULT_REGISTERED_RACE_REQUEST", request.to_string())
            .env(
                "FOGVAULT_REGISTERED_RACE_SAME_REQUEST",
                same_request.to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}
fn ready(process: &mut Process, expected: &str) {
    let mut reader = BufReader::new(process.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "registered writer exited before {expected}"
        );
        if line.trim_end().ends_with(expected) {
            break;
        }
    }
    process.0.stdout = Some(reader.into_inner());
}

#[test]
fn registered_native_real_parent_death_preserves_submission_and_recovers_exact_target() {
    for phase in [
        "after-preparation",
        "after-submission",
        "after-vault-commit",
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let namespace = scratch.path().join("independent-control");
        let path = scratch.path().join("actual-process-death.sqlite");
        let host = NativeHost::create_new(&namespace).unwrap();
        drop(
            host.create(&path, PASSWORD, limits(), KdfPolicy::baseline())
                .unwrap(),
        );
        let marker = scratch.path().join("observed-publication-boundary");
        let mut child = Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native::registered_process_tests::registered_native_parent_death_fixture",
                    "--nocapture",
                ])
                .env("FOGVAULT_REGISTERED_DEATH_NAMESPACE", &namespace)
                .env("FOGVAULT_REGISTERED_DEATH_VAULT", &path)
                .env("FOGVAULT_REGISTERED_DEATH_MODE", "death")
                .env("FOGVAULT_REGISTERED_PAUSE", phase)
                .env("FOGVAULT_REGISTERED_MARKER", &marker)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        ready(&mut child, &format!("REGISTERED_PAUSE_READY {phase}"));
        assert!(marker.is_file());
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        let mut vault = host.open(&path, limits(), KdfPolicy::baseline()).unwrap();
        let state = vault.registered_control_state().unwrap();
        assert_eq!(state.accepted().generation, 0);
        let intent = state.pending().unwrap();
        assert_eq!(intent.request_id, REQUEST);
        if phase == "after-preparation" {
            assert!(intent.submission().is_none());
            assert!(matches!(
                vault.reconcile_registered(REQUEST),
                Err(Error::Conflict)
            ));
            vault.abandon_registered_preparation(REQUEST).unwrap();
            let finished = vault.registered_control_state().unwrap();
            assert!(finished.pending().is_none());
            assert_eq!(finished.accepted(), state.accepted());
            let token = vault.unlock(PASSWORD).unwrap();
            assert!(matches!(vault.read(&token, ID), Err(Error::NotFound)));
            continue;
        }
        assert_eq!(intent.submission().unwrap().generation, 1);
        assert!(!vault.is_unlocked());
        assert!(
            matches!(vault.abandon_registered_preparation(REQUEST), Err(Error::OutcomeUnknown { request_id }) if request_id == REQUEST)
        );
        let receipt = vault.reconcile_registered(REQUEST).unwrap();
        assert_eq!(
            receipt.head_digest,
            intent.submission().unwrap().head_digest
        );
        assert!(!vault.is_unlocked());
        let finished = vault.registered_control_state().unwrap();
        assert!(finished.pending().is_none());
        assert_eq!(finished.accepted().head_digest, receipt.head_digest);
        let token = vault.unlock(PASSWORD).unwrap();
        assert_eq!(
            vault.read(&token, ID).unwrap().payload.as_slice(),
            b"exact retained target"
        );
    }
}

#[test]
fn registered_native_real_process_competitors_have_one_authorized_successor() {
    competing_writers(false);
}

#[test]
fn registered_native_same_request_competitors_cannot_claim_or_clear_other_target() {
    competing_writers(true);
}

fn competing_writers(same_request: bool) {
    let scratch = tempfile::tempdir().unwrap();
    let namespace = scratch.path().join("independent-control");
    let path = scratch.path().join("competing.sqlite");
    let host = NativeHost::create_new(&namespace).unwrap();
    drop(
        host.create(&path, PASSWORD, limits(), KdfPolicy::baseline())
            .unwrap(),
    );
    // Each actual process authenticates the same source before either may write.
    let mut first = process(&namespace, &path, "race", 0xd3, same_request);
    let mut second = process(&namespace, &path, "race", 0xd4, same_request);
    // The request identity differs while the accepted source is identical.
    ready(&mut first, "REGISTERED_WRITE_READY");
    ready(&mut second, "REGISTERED_WRITE_READY");
    first.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    second.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    let mut outputs = String::new();
    for child in [&mut first, &mut second] {
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut outputs)
            .unwrap();
        assert!(child.0.wait().unwrap().success());
    }
    assert_eq!(outputs.matches("REGISTERED_RACE_COMMITTED").count(), 1);
    assert_eq!(outputs.matches("REGISTERED_RACE_CONFLICT").count(), 1);
    let mut vault = host.open(&path, limits(), KdfPolicy::baseline()).unwrap();
    let state = vault.registered_control_state().unwrap();
    assert!(state.pending().is_none());
    assert_eq!(state.accepted().generation, 1);
    let token = vault.unlock(PASSWORD).unwrap();
    let record = vault.read(&token, ID).unwrap();
    assert_eq!(record.revision, 1);
    assert!(matches!(record.payload.as_slice(), [0xd3] | [0xd4]));
}
