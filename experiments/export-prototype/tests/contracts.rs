use fogvault_export_feasibility::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fogvault-age-proof-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn raw_encrypt(data: &[u8], recipient: &age::x25519::Recipient) -> Vec<u8> {
    let mut output = Vec::new();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient)).unwrap();
    let mut writer = encryptor.wrap_output(&mut output).unwrap();
    writer.write_all(data).unwrap();
    writer.finish().unwrap();
    output
}
fn exported(identity: &age::x25519::Identity) -> (Vec<u8>, ExportReceipt) {
    let mut output = Vec::new();
    let receipt = export_payload(
        Cursor::new(RECORDS),
        &mut output,
        &identity.to_public(),
        Policy::proof(),
        &mut Observation::default(),
    )
    .unwrap();
    assert_eq!(receipt.ciphertext_sha256, digest(&output));
    (output, receipt)
}
fn permit(receipt: &ExportReceipt, source: Source) -> ImportPermit {
    ImportPermit {
        source,
        completed_ciphertext_sha256: receipt.ciphertext_sha256,
        owner_authorized: true,
    }
}
fn staged_digest(path: &std::path::Path, identity: &age::x25519::Identity) -> [u8; 32] {
    let decryptor = age::Decryptor::new(File::open(path).unwrap()).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; CHUNK];
    loop {
        let n = reader.read(&mut buffer).unwrap();
        if n == 0 {
            return hash.finalize().into();
        }
        hash.update(&buffer[..n]);
    }
}

#[test]
fn rust_age_complete_stream_activates_only_encrypted_finished_stage() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let mut observed = Observation::default();
    import_to_new_artifact(
        Cursor::new(cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, Source::records()),
        Policy::proof(),
        &mut observed,
    )
    .unwrap();
    assert!(
        observed.inner_complete
            && observed.outer_complete
            && observed.origin_verified
            && observed.stage_complete
            && observed.activated
    );
    assert!(!scratch.exists());
    assert_eq!(staged_digest(&destination, &stage), digest(RECORDS));
    assert!(fs::read(&destination)
        .unwrap()
        .starts_with(b"age-encryption.org/v1\n"));
}

#[test]
fn rust_age_complete_inner_in_nonfinal_chunk_never_activates() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let producer = SyntheticPayload::new((CHUNK - 104 - 45 - 41) as u64);
    let source = producer.source();
    let mut inner = Vec::new();
    producer
        .take(CHUNK as u64 + 1)
        .read_to_end(&mut inner)
        .unwrap();
    assert_eq!(inner.len(), CHUNK);
    let mut extra = inner.clone();
    extra.push(7);
    let mut cipher = raw_encrypt(&extra, &identity.to_public());
    // Leave the first authenticated nonfinal full chunk, removing the final
    // one-byte chunk and its tag. Its complete inner frame must not activate.
    cipher.truncate(cipher.len() - 17);
    let receipt = ExportReceipt {
        ciphertext_sha256: digest(&cipher),
        ciphertext_bytes: cipher.len() as u64,
    };
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, source),
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert!(observed.inner_complete);
    assert!(!observed.outer_complete && !observed.activated);
    assert!(!scratch.exists() && !destination.exists());
}

#[test]
fn rust_age_every_truncation_tamper_trailing_wrong_identity_never_activates() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let wrong = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let authority = permit(&receipt, Source::records());
    for end in 0..cipher.len() {
        let mut observed = Observation::default();
        assert!(import_to_new_artifact(
            Cursor::new(&cipher[..end]),
            &identity,
            &stage.to_public(),
            &scratch,
            &destination,
            &authority,
            Policy::proof(),
            &mut observed
        )
        .is_err());
        assert!(!observed.activated && !scratch.exists() && !destination.exists());
    }
    let mut tampered = cipher.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut trailing = cipher.clone();
    trailing.push(1);
    for bytes in [tampered, trailing] {
        let mut observed = Observation::default();
        assert!(import_to_new_artifact(
            Cursor::new(bytes),
            &identity,
            &stage.to_public(),
            &scratch,
            &destination,
            &authority,
            Policy::proof(),
            &mut observed
        )
        .is_err());
        assert!(!observed.activated && !scratch.exists() && !destination.exists());
    }
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(cipher),
        &wrong,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert!(!destination.exists());
}

#[test]
fn rust_age_admission_precedes_identity_work_and_body_allocation() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let authority = permit(&receipt, Source::records());
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let mut constrained = Policy::proof();
    constrained.header_bytes = b"age-encryption.org/v1\n".len();
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(&cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        constrained,
        &mut observed
    )
    .is_err());
    assert!(!observed.identity_work_started && !scratch.exists());
    let mut constrained = Policy::proof();
    constrained.stanzas = 0;
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(&cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        constrained,
        &mut observed
    )
    .is_err());
    assert!(!observed.identity_work_started);
    let scrypt = b"age-encryption.org/v1\n-> scrypt salt 99\nabc\n--- ignored\n";
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(scrypt),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert!(!observed.identity_work_started);
    let mut too_long = RECORDS.to_vec();
    too_long[141..149].copy_from_slice(&u64::MAX.to_be_bytes());
    let malicious = raw_encrypt(&too_long, &identity.to_public());
    let authority = ImportPermit {
        completed_ciphertext_sha256: digest(&malicious),
        ..authority
    };
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(malicious),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert_eq!(observed.max_body_buffer, 0);
    assert!(!observed.activated && !scratch.exists());
}

#[test]
fn rust_age_origin_receipt_source_and_owner_authority_are_separate() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let (cipher, receipt) = exported(&identity);
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let authority = ImportPermit {
        owner_authorized: false,
        ..permit(&receipt, Source::records())
    };
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(&cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &authority,
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert!(!observed.identity_work_started);
    let mut source = Source::records();
    source.0[8] ^= 1;
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(&cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, source),
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert_eq!(observed.max_body_buffer, 0);
    // Valid replacement copies source claims but changes data and recomputes its
    // inner transcript. Anyone with the public recipient can create this.
    let mut replacement = RECORDS.to_vec();
    replacement[149] ^= 1;
    let last = replacement.len() - 32;
    let mut hash = Sha256::new();
    hash.update(b"fogvault/export/payload/v1\0");
    hash.update(&replacement[..last]);
    replacement[last..].copy_from_slice(&hash.finalize());
    let substituted = raw_encrypt(&replacement, &identity.to_public());
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(substituted),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, Source::records()),
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert!(observed.inner_complete && observed.outer_complete);
    assert!(
        !observed.origin_verified
            && !observed.activated
            && !scratch.exists()
            && !destination.exists()
    );
    // Existing target is never overwritten, even with otherwise valid input.
    fs::write(&destination, &cipher).unwrap();
    let before = file_digest(&destination).unwrap();
    let mut observed = Observation::default();
    assert!(import_to_new_artifact(
        Cursor::new(&cipher),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, Source::records()),
        Policy::proof(),
        &mut observed
    )
    .is_err());
    assert_eq!(file_digest(&destination).unwrap(), before);
    assert!(!observed.activated && !scratch.exists());
}

#[test]
fn rust_age_all_fixed_payload_vectors_and_truncated_inner_frames_reject() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let vector_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let mut invalid_count = 0;
    for entry in fs::read_dir(vector_dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if !name.starts_with("export-vectors-invalid-") || !name.ends_with(".bin") {
            continue;
        }
        invalid_count += 1;
        let invalid = fs::read(path).unwrap();
        let cipher = raw_encrypt(&invalid, &identity.to_public());
        let receipt = ExportReceipt {
            ciphertext_sha256: digest(&cipher),
            ciphertext_bytes: cipher.len() as u64,
        };
        let mut observed = Observation::default();
        assert!(import_to_new_artifact(
            Cursor::new(cipher),
            &identity,
            &stage.to_public(),
            &scratch,
            &destination,
            &permit(&receipt, Source::records()),
            Policy::proof(),
            &mut observed
        )
        .is_err());
        assert!(!observed.activated && !scratch.exists());
    }
    assert_eq!(invalid_count, 10); // Exact permanent invalid-vector inventory.
    for inner in [EMPTY, RECORDS] {
        let mut encrypted = Vec::new();
        let valid_receipt = export_payload(
            Cursor::new(inner),
            &mut encrypted,
            &identity.to_public(),
            Policy::proof(),
            &mut Observation::default(),
        )
        .unwrap();
        let source = Source(inner[..104].try_into().unwrap());
        let mut observed = Observation::default();
        import_to_new_artifact(
            Cursor::new(encrypted),
            &identity,
            &stage.to_public(),
            &scratch,
            &destination,
            &permit(&valid_receipt, source),
            Policy::proof(),
            &mut observed,
        )
        .unwrap();
        assert_eq!(staged_digest(&destination, &stage), digest(inner));
        fs::remove_file(&destination).unwrap();
        for end in 0..inner.len() {
            let cipher = raw_encrypt(&inner[..end], &identity.to_public());
            let receipt = ExportReceipt {
                ciphertext_sha256: digest(&cipher),
                ciphertext_bytes: cipher.len() as u64,
            };
            let mut source = Source::records();
            source.0.copy_from_slice(&inner[..104]);
            let mut observed = Observation::default();
            assert!(import_to_new_artifact(
                Cursor::new(cipher),
                &identity,
                &stage.to_public(),
                &scratch,
                &destination,
                &permit(&receipt, source),
                Policy::proof(),
                &mut observed
            )
            .is_err());
            assert!(!observed.activated && !scratch.exists());
        }
    }
}

#[test]
fn rust_age_sixteen_mib_payload_streams_to_encrypted_stage_with_bounded_application_buffer() {
    let temp = Temp::new();
    let identity = age::x25519::Identity::generate();
    let stage = age::x25519::Identity::generate();
    let source = SyntheticPayload::new(16 * 1024 * 1024).source();
    let incoming = temp.path("incoming.age");
    let mut incoming_file = File::create(&incoming).unwrap();
    let mut export_observation = Observation::default();
    let receipt = export_payload(
        SyntheticPayload::new(16 * 1024 * 1024),
        &mut incoming_file,
        &identity.to_public(),
        Policy::proof(),
        &mut export_observation,
    )
    .unwrap();
    incoming_file.sync_all().unwrap();
    drop(incoming_file);
    let scratch = temp.path("scratch.age");
    let destination = temp.path("active.age");
    let mut observed = Observation::default();
    import_to_new_artifact(
        File::open(&incoming).unwrap(),
        &identity,
        &stage.to_public(),
        &scratch,
        &destination,
        &permit(&receipt, source),
        Policy::proof(),
        &mut observed,
    )
    .unwrap();
    assert!(observed.activated && observed.outer_complete);
    assert_eq!(observed.max_body_buffer, CHUNK);
    assert_eq!(observed.plaintext_bytes, 16 * 1024 * 1024 + 104 + 45 + 41);
    assert_eq!(export_observation.max_body_buffer, CHUNK);
    let mut expected = Sha256::new();
    let mut plain = SyntheticPayload::new(16 * 1024 * 1024);
    let mut buffer = [0; CHUNK];
    loop {
        let n = plain.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        expected.update(&buffer[..n]);
    }
    assert_eq!(
        staged_digest(&destination, &stage),
        <[u8; 32]>::from(expected.finalize())
    );
    println!(
        "bounded-stream plaintext_bytes={} application_body_buffer={} header_bytes={}",
        observed.plaintext_bytes, observed.max_body_buffer, observed.header_bytes
    );
}

#[test]
fn rust_age_sink_failure_never_issues_finished_export_receipt() {
    struct FailedSink;
    impl Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic sink failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("synthetic sink failure"))
        }
    }
    let identity = age::x25519::Identity::generate();
    assert!(export_payload(
        Cursor::new(RECORDS),
        FailedSink,
        &identity.to_public(),
        Policy::proof(),
        &mut Observation::default()
    )
    .is_err());
    struct FlushFailed;
    impl Write for FlushFailed {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("synthetic sink completion failure"))
        }
    }
    assert!(export_payload(
        Cursor::new(RECORDS),
        FlushFailed,
        &identity.to_public(),
        Policy::proof(),
        &mut Observation::default()
    )
    .is_err());
}
