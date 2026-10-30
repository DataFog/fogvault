//! Synthetic standalone consumer: no DataFog dependency and no real credentials.
//! The temporary control directory demonstrates the API, not OS trust isolation.
use fogvault_native::{Host, KdfPolicy, Limits};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let namespace = temporary.path().join("control");
    let path = temporary.path().join("vault.sqlite");
    // An explicit policy for this small demonstration, not a production default.
    let limits = Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 128,
        max_records: 16,
    };
    let password = Zeroizing::new(b"SYNTHETIC-public-example-password".to_vec());
    let payload = Zeroizing::new(b"SYNTHETIC standalone consumer data".to_vec());
    let host = Host::create_new(&namespace)?;
    let mut vault = host.create(&path, &password, limits, KdfPolicy::baseline())?;
    let session = vault.unlock(&password)?;
    vault.save(&session, [1; 16], None, b"example", &payload, [2; 16])?;
    vault.lock();
    assert!(vault.read(&session, [1; 16]).is_err());
    drop(vault);
    let host = Host::open(&namespace)?;
    let mut reopened = host.open_vault(&path, limits, KdfPolicy::baseline())?;
    let session = reopened.unlock(&password)?;
    let record = reopened.read(&session, [1; 16])?;
    assert_eq!(record.payload.as_slice(), payload.as_slice());
    reopened.lock();
    println!("create → unlock → save → lock → reopen → read passed");
    Ok(())
}
