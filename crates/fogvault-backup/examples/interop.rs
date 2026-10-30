//! Synthetic standard-age interoperability probe. No persistent private keys.
use fogvault_backup::*;
use std::{
    io::{self, BufRead, Cursor, Write},
    str::FromStr,
};
use zeroize::Zeroizing;
const FRAME: &[u8] = include_bytes!("../../../conformance/export-vectors-records.bin");
fn policy() -> Policy {
    Policy {
        header_bytes: 2 * 1024 * 1024,
        stanzas: 1024,
        ciphertext_bytes: 4 * 1024 * 1024,
        total_plaintext_bytes: 1024 * 1024,
        records: 2,
        schema_bytes: 256,
        metadata_bytes: 256,
        payload_bytes: 1024 * 1024,
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let key = Identity::generate();
            println!("{}\n{}", &*export_identity(&key), key.to_public());
        }
        Some("export") => {
            let recipient = Recipient::from_str(args.get(2).ok_or("recipient required")?)?;
            export_payload(
                Cursor::new(FRAME),
                io::stdout().lock(),
                &recipient,
                policy(),
                &mut Observation::default(),
            )?;
        }
        Some("import") => {
            let digest = args.get(2).ok_or("trusted public digest required")?;
            if digest.len() != 64 {
                return Err("bad digest".into());
            }
            let mut expected = [0; 32];
            for (i, byte) in expected.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&digest[2 * i..2 * i + 2], 16)?;
            }
            let mut input = io::stdin().lock();
            let mut text = Zeroizing::new(String::new());
            input.read_line(&mut text)?;
            let key = Identity::from_str(text.trim_end_matches(['\n', '\r']))?;
            let stage = Identity::generate();
            let source = SourceSnapshot::from_header(FRAME[..104].try_into()?)?;
            let permit = FreshImportPermit::origin_checked(source, expected, [0xa5; 16])?;
            let mut encrypted = Vec::new();
            let complete = stage_import(
                &mut input,
                &key,
                &stage.to_public(),
                &mut encrypted,
                &permit,
                policy(),
                &mut Observation::default(),
            )?;
            let records = read_staged_records(
                Cursor::new(encrypted),
                &stage,
                &complete,
                [0xa5; 16],
                policy(),
            )?;
            if records.len() != 2
                || &*records[0].payload != b"alpha\0beta"
                || records[1].payload.as_slice() != [0, 255, 128, 1]
            {
                return Err("interoperability contents differ".into());
            }
            writeln!(
                io::stdout(),
                "{{\"pass\":true,\"records\":2,\"origin_verified\":{}}}",
                complete.origin_verified()
            )?;
        }
        _ => return Err("keygen | export RECIPIENT | import TRUSTED_DIGEST".into()),
    }
    Ok(())
}
