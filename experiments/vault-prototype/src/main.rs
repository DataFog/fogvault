use std::{env, path::PathBuf, process::ExitCode};

use fogvault_disposable_prototype::{crypto, Error, Limits, Vault};

const PASSWORD: &[u8] = b"DEMO-ONLY synthetic passphrase: never real secrets";
const METADATA: &[u8] = b"independent.synthetic-record/v1";
const PAYLOAD: &[u8] = b"SYNTHETIC-SECRET-DO-NOT-USE-IN-PRODUCTION";

fn limits() -> Limits {
    // Fixture-derived bounds: this command exercises exactly one synthetic record.
    Limits {
        max_payload_bytes: PAYLOAD.len(),
        max_metadata_bytes: METADATA.len(),
        max_records: 1,
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().collect();
    let command = arguments.get(1).map(String::as_str).unwrap_or("demo");
    if command == "reopen-proof" {
        let path = PathBuf::from(
            arguments
                .get(2)
                .ok_or("reopen-proof requires a scratch DB path")?,
        );
        let mut vault = Vault::diagnostic_open(&path, limits())?;
        let session = vault.unlock(PASSWORD)?;
        let record = vault.read(&session, [1u8; 16])?;
        if record.payload.as_slice() != PAYLOAD || record.metadata.as_slice() != METADATA {
            return Err("reopened payload mismatch".into());
        }
        println!("PASS second-process reopen -> unlock -> read (secret redacted)");
        vault.lock();
        return Ok(());
    }
    if command != "demo" {
        return Err(
            "usage: vault-prototype [demo [unused-scratch-path] | reopen-proof scratch-path]"
                .into(),
        );
    }
    let path = match arguments.get(2) {
        Some(path) => PathBuf::from(path),
        None => {
            let nonce = crypto::random::<16>()?;
            let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
            env::temp_dir().join(format!("PROTOTYPE-WIPE-ME-fogvault-{name}.sqlite"))
        }
    };
    println!(
        "DISPOSABLE EXPERIMENT — synthetic data only\nScratch store: {}",
        path.display()
    );
    let mut vault = Vault::diagnostic_create(&path, PASSWORD, limits())?;
    println!("PASS create (locked)");
    let session = vault.unlock(PASSWORD)?;
    println!("PASS unlock (generation 0)");
    let receipt = vault.save(&session, [1u8; 16], None, METADATA, PAYLOAD, [2u8; 16])?;
    println!("PASS save (generation {})", receipt.generation);
    vault.lock();
    if !matches!(vault.read(&session, [1u8; 16]), Err(Error::Locked)) {
        return Err("locked read unexpectedly admitted".into());
    }
    println!("PASS lock (old session rejected)");
    drop(vault);
    let status = std::process::Command::new(env::current_exe()?)
        .arg("reopen-proof")
        .arg(&path)
        .status()?;
    if !status.success() {
        return Err("second-process proof failed".into());
    }
    println!("PASS create -> unlock -> save -> lock -> reopen -> read\nScratch file retained for inspection; remove only this synthetic experiment when finished.");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Experiment failed: {error}");
            ExitCode::FAILURE
        }
    }
}
