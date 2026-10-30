use fogvault_backup::*;
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Write};
use zeroize::Zeroizing;

const RECORDS: &[u8] = include_bytes!("../../../conformance/export-vectors-records.bin");
const EMPTY: &[u8] = include_bytes!("../../../conformance/export-vectors-empty.bin");
fn policy() -> Policy {
    Policy {
        header_bytes: 2 * 1024 * 1024,
        stanzas: 1024,
        ciphertext_bytes: 20 * 1024 * 1024,
        total_plaintext_bytes: 17 * 1024 * 1024,
        records: 2,
        schema_bytes: 256,
        metadata_bytes: 256,
        payload_bytes: 16 * 1024 * 1024,
    }
}
fn source(bytes: &[u8]) -> SourceSnapshot {
    SourceSnapshot::from_header(bytes[..104].try_into().unwrap()).unwrap()
}
fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
fn raw_encrypt(data: &[u8], recipient: &Recipient) -> Vec<u8> {
    let mut bytes = Vec::new();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient)).unwrap();
    let mut writer = encryptor.wrap_output(&mut bytes).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    bytes
}
fn clear(ciphertext: &[u8], identity: &Identity) -> Vec<u8> {
    let decryptor = age::Decryptor::new(Cursor::new(ciphertext)).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut data = Vec::new();
    reader.read_to_end(&mut data).unwrap();
    data
}
fn fixture_records() -> Vec<io::Result<RecordData>> {
    let mut cursor = Cursor::new(&RECORDS[104..]);
    let mut records = Vec::new();
    for _ in 0..2 {
        let mut fixed = [0; 45];
        cursor.read_exact(&mut fixed).unwrap();
        let schema = u32::from_be_bytes(fixed[25..29].try_into().unwrap()) as usize;
        let metadata = u64::from_be_bytes(fixed[29..37].try_into().unwrap()) as usize;
        let payload = u64::from_be_bytes(fixed[37..45].try_into().unwrap()) as usize;
        let mut body = |n| {
            let mut v = Zeroizing::new(vec![0; n]);
            cursor.read_exact(&mut v).unwrap();
            v
        };
        records.push(Ok(RecordData {
            id: fixed[1..17].try_into().unwrap(),
            revision: u64::from_be_bytes(fixed[17..25].try_into().unwrap()),
            schema: body(schema),
            metadata: body(metadata),
            payload: body(payload),
        }));
    }
    records
}
fn exported(identity: &Identity) -> (Vec<u8>, ExportReceipt) {
    let mut cipher = Vec::new();
    let receipt = export_snapshot(
        source(RECORDS),
        fixture_records(),
        &mut cipher,
        &identity.to_public(),
        policy(),
        &mut Observation::default(),
    )
    .unwrap();
    (cipher, receipt)
}
fn stage(
    ciphertext: &[u8],
    identity: &Identity,
    stage_key: &Identity,
    permit: &FreshImportPermit,
) -> io::Result<(Vec<u8>, CompletedImport)> {
    let mut bytes = Vec::new();
    let complete = stage_import(
        Cursor::new(ciphertext),
        identity,
        &stage_key.to_public(),
        &mut bytes,
        permit,
        policy(),
        &mut Observation::default(),
    )?;
    Ok((bytes, complete))
}

#[test]
fn typed_snapshot_export_matches_permanent_wire_bytes_and_finished_receipt() {
    let identity = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    assert_eq!(clear(&cipher, &identity), RECORDS);
    assert_eq!(receipt.ciphertext_sha256, digest(&cipher));
    assert_eq!(receipt.ciphertext_bytes, cipher.len() as u64);
    let mut empty = Vec::new();
    export_snapshot(
        source(EMPTY),
        Vec::<io::Result<RecordData>>::new(),
        &mut empty,
        &identity.to_public(),
        policy(),
        &mut Observation::default(),
    )
    .unwrap();
    assert_eq!(clear(&empty, &identity), EMPTY);
}
#[test]
fn complete_import_returns_only_encrypted_stage_and_target_bound_guarded_records() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let permit =
        FreshImportPermit::origin_checked(source(RECORDS), receipt.ciphertext_sha256, [0xa5; 16])
            .unwrap();
    let (bytes, completed) = stage(&cipher, &identity, &stage_key, &permit).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    assert_eq!(clear(&bytes, &stage_key), RECORDS);
    assert!(completed.origin_verified());
    assert_eq!(completed.stage_sha256(), digest(&bytes));
    let records = read_staged_records(
        Cursor::new(&bytes),
        &stage_key,
        &completed,
        [0xa5; 16],
        policy(),
    )
    .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(&*records[0].payload, b"alpha\0beta");
    assert_eq!(&*records[1].payload, &[0, 255, 128, 1]);
    assert!(read_staged_records(
        Cursor::new(&bytes),
        &stage_key,
        &completed,
        [0xa6; 16],
        policy()
    )
    .is_err());
    let mut altered = bytes.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    assert!(read_staged_records(
        Cursor::new(altered),
        &stage_key,
        &completed,
        [0xa5; 16],
        policy()
    )
    .is_err());
}
#[test]
fn every_outer_truncation_tamper_trailing_byte_and_wrong_key_refuses_completion() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let wrong = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let permit =
        FreshImportPermit::origin_checked(source(RECORDS), receipt.ciphertext_sha256, [0xa5; 16])
            .unwrap();
    for end in 0..cipher.len() {
        assert!(
            stage(&cipher[..end], &identity, &stage_key, &permit).is_err(),
            "truncation {end}"
        );
    }
    let mut tampered = cipher.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut trailing = cipher.clone();
    trailing.push(1);
    for bytes in [tampered, trailing] {
        assert!(stage(&bytes, &identity, &stage_key, &permit).is_err());
    }
    assert!(stage(&cipher, &wrong, &stage_key, &permit).is_err());
}
#[test]
fn complete_inner_in_authenticated_nonfinal_chunk_is_not_complete_import() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let source = SourceSnapshot::new([0x61; 16], [2; 32], [3; 32], 0, 1);
    let records = [Ok(RecordData {
        id: [7; 16],
        revision: 1,
        schema: Zeroizing::new(Vec::new()),
        metadata: Zeroizing::new(Vec::new()),
        payload: Zeroizing::new(vec![0x5a; CHUNK - 190]),
    })];
    let mut proper = Vec::new();
    export_snapshot(
        source.clone(),
        records,
        &mut proper,
        &identity.to_public(),
        policy(),
        &mut Observation::default(),
    )
    .unwrap();
    let mut inner = clear(&proper, &identity);
    assert_eq!(inner.len(), CHUNK);
    inner.push(7);
    let mut incomplete = raw_encrypt(&inner, &identity.to_public());
    incomplete.truncate(incomplete.len() - 17);
    let permit =
        FreshImportPermit::origin_checked(source, digest(&incomplete), [0xa5; 16]).unwrap();
    let mut output = Vec::new();
    let mut observation = Observation::default();
    assert!(stage_import(
        Cursor::new(&incomplete),
        &identity,
        &stage_key.to_public(),
        &mut output,
        &permit,
        policy(),
        &mut observation
    )
    .is_err());
    assert!(observation.inner_complete);
    assert!(!observation.outer_complete && !observation.stage_complete);
}
#[test]
fn source_claims_do_not_replace_trusted_receipts_and_unverified_import_is_explicit() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let trusted =
        FreshImportPermit::origin_checked(source(RECORDS), receipt.ciphertext_sha256, [0xa5; 16])
            .unwrap();
    let mut changed = RECORDS.to_vec();
    changed[149] ^= 1;
    let last = changed.len() - 32;
    let mut hash = Sha256::new();
    hash.update(b"fogvault/export/payload/v1\0");
    hash.update(&changed[..last]);
    changed[last..].copy_from_slice(&hash.finalize());
    let attacker = raw_encrypt(&changed, &identity.to_public());
    assert!(stage(&attacker, &identity, &stage_key, &trusted).is_err());
    let unverified =
        FreshImportPermit::owner_accepted_unverified(source(RECORDS), [0xa5; 16]).unwrap();
    let (_, completed) = stage(&attacker, &identity, &stage_key, &unverified).unwrap();
    assert!(!completed.origin_verified());
    assert!(FreshImportPermit::owner_accepted_unverified(
        source(RECORDS),
        source(RECORDS).vault_id()
    )
    .is_err());
    assert!(stage(&cipher, &identity, &stage_key, &trusted)
        .unwrap()
        .1
        .origin_verified());
}
#[test]
fn header_cap_stanzas_and_scrypt_reject_before_identity_work() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let permit =
        FreshImportPermit::origin_checked(source(RECORDS), receipt.ciphertext_sha256, [0xa5; 16])
            .unwrap();
    for restricted in [
        Policy {
            header_bytes: 21,
            ..policy()
        },
        Policy {
            stanzas: 0,
            ..policy()
        },
    ] {
        let mut observation = Observation::default();
        assert!(stage_import(
            Cursor::new(&cipher),
            &identity,
            &stage_key.to_public(),
            Vec::new(),
            &permit,
            restricted,
            &mut observation
        )
        .is_err());
        assert!(!observation.identity_work_started);
    }
    let mut observation = Observation::default();
    assert!(stage_import(
        Cursor::new(b"age-encryption.org/v1\n-> scrypt salt 99\nabc\n--- ignored\n"),
        &identity,
        &stage_key.to_public(),
        Vec::new(),
        &permit,
        policy(),
        &mut observation
    )
    .is_err());
    assert!(!observation.identity_work_started);
}
#[test]
fn every_permanent_invalid_payload_is_rejected_even_under_valid_age_encryption() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let mut count = 0;
    for file in std::fs::read_dir(directory).unwrap() {
        let path = file.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.starts_with("export-vectors-invalid-") || !name.ends_with(".bin") {
            continue;
        }
        count += 1;
        let cipher = raw_encrypt(&std::fs::read(path).unwrap(), &identity.to_public());
        let permit =
            FreshImportPermit::origin_checked(source(RECORDS), digest(&cipher), [0xa5; 16])
                .unwrap();
        assert!(stage(&cipher, &identity, &stage_key, &permit).is_err());
    }
    assert_eq!(count, 10);
}
#[test]
fn source_omission_extra_ordering_and_policy_violation_never_finish_export() {
    let identity = Identity::generate();
    let mut missing = fixture_records();
    missing.pop();
    let mut extra = fixture_records();
    extra.push(Ok(RecordData {
        id: [255; 16],
        revision: 1,
        schema: Zeroizing::new(Vec::new()),
        metadata: Zeroizing::new(Vec::new()),
        payload: Zeroizing::new(Vec::new()),
    }));
    let mut unordered = fixture_records();
    unordered.reverse();
    for records in [missing, extra, unordered] {
        assert!(export_snapshot(
            source(RECORDS),
            records,
            Vec::new(),
            &identity.to_public(),
            policy(),
            &mut Observation::default()
        )
        .is_err());
    }
    assert!(export_snapshot(
        source(RECORDS),
        fixture_records(),
        Vec::new(),
        &identity.to_public(),
        Policy {
            payload_bytes: 0,
            ..policy()
        },
        &mut Observation::default()
    )
    .is_err());
    assert!(export_snapshot(
        source(RECORDS),
        fixture_records(),
        Vec::new(),
        &identity.to_public(),
        Policy {
            ciphertext_bytes: 1,
            ..policy()
        },
        &mut Observation::default()
    )
    .is_err());
}
struct FailedSink;
impl Write for FailedSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected destination failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn sink_failure_cannot_issue_export_receipt_or_import_completion() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let (cipher, receipt) = exported(&identity);
    assert!(export_snapshot(
        source(RECORDS),
        fixture_records(),
        FailedSink,
        &identity.to_public(),
        policy(),
        &mut Observation::default()
    )
    .is_err());
    let permit =
        FreshImportPermit::origin_checked(source(RECORDS), receipt.ciphertext_sha256, [0xa5; 16])
            .unwrap();
    assert!(stage_import(
        Cursor::new(cipher),
        &identity,
        &stage_key.to_public(),
        FailedSink,
        &permit,
        policy(),
        &mut Observation::default()
    )
    .is_err());
}

#[test]
fn sixteen_mib_record_streams_through_transport_with_fixed_body_chunk() {
    let identity = Identity::generate();
    let stage_key = Identity::generate();
    let source = SourceSnapshot::new([0x61; 16], [2; 32], [3; 32], 0, 1);
    let size = 16 * 1024 * 1024;
    let records = [Ok(RecordData {
        id: [7; 16],
        revision: 1,
        schema: Zeroizing::new(Vec::new()),
        metadata: Zeroizing::new(Vec::new()),
        payload: Zeroizing::new(vec![0x5a; size]),
    })];
    let mut cipher = Vec::new();
    let mut observed = Observation::default();
    let receipt = export_snapshot(
        source.clone(),
        records,
        &mut cipher,
        &identity.to_public(),
        policy(),
        &mut observed,
    )
    .unwrap();
    assert_eq!(observed.max_body_buffer, CHUNK);
    let permit =
        FreshImportPermit::origin_checked(source, receipt.ciphertext_sha256, [0xa5; 16]).unwrap();
    let mut encrypted = Vec::new();
    let mut observed = Observation::default();
    let completed = stage_import(
        Cursor::new(&cipher),
        &identity,
        &stage_key.to_public(),
        &mut encrypted,
        &permit,
        policy(),
        &mut observed,
    )
    .unwrap();
    assert_eq!(observed.max_body_buffer, CHUNK);
    assert!(completed.origin_verified());
    assert!(observed.inner_complete && observed.outer_complete && observed.stage_complete);
}
