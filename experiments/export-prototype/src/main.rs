use age::secrecy::ExposeSecret;
use fogvault_export_feasibility::{
    export_records_file, hex, import_to_new_artifact, ImportPermit, Observation, Policy, Source,
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 2 => {
            let identity = age::x25519::Identity::generate();
            // Test driver captures this secret in memory and never logs it.
            println!("{}", identity.to_string().expose_secret());
            println!("{}", identity.to_public());
        }
        Some("export-records") if args.len() == 4 => {
            let recipient: age::x25519::Recipient = args[2].parse()?;
            let receipt = export_records_file(&recipient, Path::new(&args[3]))?;
            println!("{{\"ciphertext_sha256\":\"{}\",\"ciphertext_bytes\":{}}}", hex(&receipt.ciphertext_sha256), receipt.ciphertext_bytes);
        }
        Some("import-records") if args.len() == 6 => {
            let mut secret = Zeroizing::new(String::new());
            // Native X25519 identity encoding: 15-character HRP + separator +
            // 52 five-bit data symbols + six checksum symbols = 74 characters.
            // Permit exactly that line and a final newline; no unbounded read.
            io::stdin().take(76).read_to_string(&mut secret)?;
            if secret.trim_end_matches('\n').len() != 74 { return Err("identity encoding width".into()); }
            let identity: age::x25519::Identity = secret.trim_end_matches('\n').parse()?;
            let digest: Vec<u8> = args[5].as_bytes().chunks_exact(2).map(|pair| {
                let text = std::str::from_utf8(pair).map_err(|_| "digest encoding")?;
                u8::from_str_radix(text, 16).map_err(|_| "digest encoding")
            }).collect::<Result<_,_>>()?;
            if args[5].len() != 64 || digest.len() != 32 { return Err("digest width".into()); }
            let permit = ImportPermit { source: Source::records(), completed_ciphertext_sha256: digest.try_into().map_err(|_| "digest width")?, owner_authorized: true };
            let stage = age::x25519::Identity::generate();
            let mut observation = Observation::default();
            import_to_new_artifact(File::open(&args[2])?, &identity, &stage.to_public(), Path::new(&args[3]), Path::new(&args[4]), &permit, Policy::proof(), &mut observation)?;
            println!("{{\"inner_complete\":{},\"outer_complete\":{},\"origin_verified\":{},\"stage_complete\":{},\"activated\":{},\"plaintext_bytes\":{},\"max_body_buffer\":{}}}", observation.inner_complete, observation.outer_complete, observation.origin_verified, observation.stage_complete, observation.activated, observation.plaintext_bytes, observation.max_body_buffer);
        }
        _ => return Err("expected keygen | export-records RECIPIENT OUTPUT | import-records INPUT SCRATCH DEST RECEIPT_SHA256".into()),
    }
    Ok(())
}
