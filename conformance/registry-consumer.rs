//! Synthetic registry-only package consumer with the exact published Core beta.3.
//! The temporary control directory demonstrates the API, not OS trust isolation.
use fogvault_native::{Host, KdfPolicy, Limits};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let namespace = temporary.path().join("control");
    let path = temporary.path().join("vault.sqlite");
    // An explicit policy for this small demonstration, not a production default.
    let limits = Limits {
        max_payload_bytes: 1048576,
        max_metadata_bytes: 128,
        max_records: 16,
    };
    let password = Zeroizing::new(b"SYNTHETIC-public-example-password".to_vec());
    let workspace = datafog_core::workspace::Workspace::create([5; 16], [6; 16])?;
    let payload = Zeroizing::new(workspace.export_bundle()?);
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
    let restored = datafog_core::workspace::Workspace::open_bundle(&record.payload)?;
    assert_eq!(restored.namespace()?, workspace.namespace()?);
    assert_eq!(restored.head()?, workspace.head()?);
    reopened.lock();
    println!("create → unlock → save → lock → reopen → read passed");
    Ok(())
}
