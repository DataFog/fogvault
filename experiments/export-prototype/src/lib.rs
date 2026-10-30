//! Disposable age/v1 X25519 and encrypted-staging construction proof.
//! Input/output are streams; application plaintext is never staged to a file.
//! This does not implement a native FogVault restore or trusted receipt storage.
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::Path,
    rc::Rc,
};
use zeroize::Zeroizing;

pub const CHUNK: usize = 64 * 1024; // age/v1 STREAM plaintext chunk size.
const DOMAIN: &[u8] = b"fogvault/export/payload/v1\0";
pub const RECORDS: &[u8] = include_bytes!("../../../conformance/export-vectors-records.bin");
pub const EMPTY: &[u8] = include_bytes!("../../../conformance/export-vectors-empty.bin");

fn reject(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn crypto<T>(value: Result<T, impl std::fmt::Display>) -> io::Result<T> {
    value.map_err(|_| reject("age authentication or format rejected"))
}

#[derive(Clone, Copy)]
pub struct Policy {
    pub header_bytes: usize,
    pub stanzas: usize,
    pub ciphertext_bytes: u64,
    pub total_plaintext_bytes: u64,
    pub records: u64,
    pub schema_bytes: u64,
    pub metadata_bytes: u64,
    pub payload_bytes: u64,
}
impl Policy {
    /// Explicit synthetic proof policy, not shipped limits. The header/stanza
    /// ceilings retain the previous pinned Go-tool experiment. Body bound comes
    /// from the exact beta.3 consumer fixture; framing/overhead is checked.
    pub fn proof() -> Self {
        let payload = 16 * 1024 * 1024;
        let total = 104 + 2 * 45 + b"example.test/opaque-v1".len() as u64 + 2 + payload + 41;
        Self {
            header_bytes: 2 * 1024 * 1024,
            stanzas: 1024,
            ciphertext_bytes: 2 * 1024 * 1024 + 16 + total + (total / CHUNK as u64 + 1) * 16,
            total_plaintext_bytes: total,
            records: 2,
            schema_bytes: b"example.test/opaque-v1".len() as u64,
            metadata_bytes: 2,
            payload_bytes: payload,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source(pub [u8; 104]);
impl Source {
    pub fn records() -> Self {
        Self(RECORDS[..104].try_into().expect("fixed fixture header"))
    }
}

#[derive(Default, Debug)]
pub struct Observation {
    pub header_bytes: usize,
    pub stanzas: usize,
    pub identity_work_started: bool,
    pub plaintext_bytes: u64,
    pub max_body_buffer: usize,
    pub inner_complete: bool,
    pub outer_complete: bool,
    pub origin_verified: bool,
    pub stage_complete: bool,
    pub activated: bool,
    pub cleanup_pending: bool,
}

#[derive(Clone, Debug)]
pub struct ExportReceipt {
    pub ciphertext_sha256: [u8; 32],
    pub ciphertext_bytes: u64,
}

/// Trusted caller inputs, not values inferred from the import or a sidecar.
pub struct ImportPermit {
    pub source: Source,
    pub completed_ciphertext_sha256: [u8; 32],
    pub owner_authorized: bool,
}

fn admit_header(
    input: &mut impl Read,
    policy: Policy,
    observation: &mut Observation,
) -> io::Result<Vec<u8>> {
    let mut header = Vec::new();
    let mut line_start = 0;
    let mut first = true;
    loop {
        if header.len() == policy.header_bytes || header.len() as u64 >= policy.ciphertext_bytes {
            return Err(reject("age header byte admission"));
        }
        let mut byte = [0];
        input.read_exact(&mut byte)?;
        header.push(byte[0]);
        observation.header_bytes = header.len();
        if byte != [b'\n'] {
            continue;
        }
        let line = &header[line_start..];
        if first {
            if line != b"age-encryption.org/v1\n" {
                return Err(reject("unsupported binary age profile"));
            }
            first = false;
        } else if line.starts_with(b"-> ") {
            observation.stanzas = observation
                .stanzas
                .checked_add(1)
                .ok_or_else(|| reject("stanza overflow"))?;
            if observation.stanzas > policy.stanzas {
                return Err(reject("age stanza admission"));
            }
            if line.split(|byte| *byte == b' ').nth(1) == Some(b"scrypt".as_slice()) {
                return Err(reject("scrypt capability not enabled"));
            }
        } else if line.starts_with(b"--- ") {
            if observation.stanzas == 0 {
                return Err(reject("missing recipient stanza"));
            }
            return Ok(header);
        }
        line_start = header.len();
    }
}

#[derive(Default)]
struct CipherState {
    digest: Sha256,
    bytes: u64,
}
struct CipherReader<R> {
    input: R,
    state: Rc<RefCell<CipherState>>,
    maximum: u64,
}
impl<R: Read> Read for CipherReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .maximum
            .checked_sub(self.state.borrow().bytes)
            .ok_or_else(|| reject("ciphertext admission"))?;
        let cap = output
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
        let count = self.input.read(&mut output[..cap])?;
        if count as u64 > remaining {
            return Err(reject("ciphertext admission"));
        }
        let mut state = self.state.borrow_mut();
        state.digest.update(&output[..count]);
        state.bytes += count as u64;
        Ok(count)
    }
}

struct CipherWriter<W> {
    output: W,
    digest: Sha256,
    bytes: u64,
}
impl<W: Write> Write for CipherWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.output.write(bytes)?;
        self.digest.update(&bytes[..count]);
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| reject("output size overflow"))?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

struct Payload<'a, R, W> {
    input: R,
    output: W,
    policy: Policy,
    hash: Sha256,
    consumed: u64,
    observation: &'a mut Observation,
}
impl<R: Read, W: Write> Payload<'_, R, W> {
    fn take<const N: usize>(&mut self, hashed: bool) -> io::Result<[u8; N]> {
        self.admit(N as u64)?;
        let mut value = [0; N];
        self.input.read_exact(&mut value)?;
        self.output.write_all(&value)?;
        if hashed {
            self.hash.update(value);
        }
        self.consumed += N as u64;
        self.observation.plaintext_bytes = self.consumed;
        Ok(value)
    }
    fn admit(&self, count: u64) -> io::Result<()> {
        self.consumed
            .checked_add(count)
            .filter(|n| *n <= self.policy.total_plaintext_bytes)
            .ok_or_else(|| reject("payload byte admission"))?;
        Ok(())
    }
    fn body(&mut self, mut count: u64) -> io::Result<()> {
        self.admit(count)?;
        let mut buffer = Zeroizing::new([0; CHUNK]);
        while count != 0 {
            let size = usize::try_from(count.min(CHUNK as u64))
                .map_err(|_| reject("length conversion"))?;
            self.input.read_exact(&mut buffer[..size])?;
            self.output.write_all(&buffer[..size])?;
            self.hash.update(&buffer[..size]);
            self.consumed += size as u64;
            count -= size as u64;
            self.observation.plaintext_bytes = self.consumed;
            self.observation.max_body_buffer = self.observation.max_body_buffer.max(size);
        }
        Ok(())
    }
}

fn copy_payload(
    input: impl Read,
    output: impl Write,
    policy: Policy,
    expected: Option<&Source>,
    observation: &mut Observation,
) -> io::Result<()> {
    let mut p = Payload {
        input,
        output,
        policy,
        hash: Sha256::new(),
        consumed: 0,
        observation,
    };
    p.hash.update(DOMAIN);
    let header = p.take::<104>(true)?;
    if &header[..8] != b"FVEXP001" || expected.is_some_and(|source| source.0 != header) {
        return Err(reject("payload source identity or version"));
    }
    let count = u64::from_be_bytes(header[96..104].try_into().expect("fixed field"));
    if count > policy.records
        || count
            .checked_mul(45)
            .and_then(|n| n.checked_add(145))
            .is_none_or(|n| n > policy.total_plaintext_bytes)
    {
        return Err(reject("record count admission"));
    }
    let mut previous = None;
    for _ in 0..count {
        let prefix = p.take::<45>(true)?;
        let id: [u8; 16] = prefix[1..17].try_into().expect("fixed field");
        let revision = u64::from_be_bytes(prefix[17..25].try_into().expect("fixed field"));
        if prefix[0] != 1 || revision == 0 || previous.is_some_and(|old| old >= id) {
            return Err(reject("record tag revision or ordering"));
        }
        previous = Some(id);
        let schema = u32::from_be_bytes(prefix[25..29].try_into().expect("fixed field")) as u64;
        let metadata = u64::from_be_bytes(prefix[29..37].try_into().expect("fixed field"));
        let payload = u64::from_be_bytes(prefix[37..45].try_into().expect("fixed field"));
        if schema > policy.schema_bytes
            || metadata > policy.metadata_bytes
            || payload > policy.payload_bytes
        {
            return Err(reject("record body admission"));
        }
        let length = schema
            .checked_add(metadata)
            .and_then(|n| n.checked_add(payload))
            .ok_or_else(|| reject("body length overflow"))?;
        p.admit(
            length
                .checked_add(41)
                .ok_or_else(|| reject("footer overflow"))?,
        )?;
        p.body(length)?;
    }
    let footer = p.take::<9>(true)?;
    if footer[0] != 255
        || u64::from_be_bytes(footer[1..9].try_into().expect("fixed field")) != count
    {
        return Err(reject("payload footer count"));
    }
    let expected_digest: [u8; 32] = p.hash.clone().finalize().into();
    if p.take::<32>(false)? != expected_digest {
        return Err(reject("payload transcript"));
    }
    p.observation.inner_complete = true;
    // This read is mandatory. For an age reader it demands outer authenticated
    // finality/EOF even when a valid FVEXP001 frame filled a nonfinal chunk.
    let mut extra = Zeroizing::new([0; 1]);
    if p.input.read(&mut *extra)? != 0 {
        return Err(reject("trailing payload"));
    }
    Ok(())
}

/// Receipt means successful age finish and sink flush; a file caller must also
/// sync/complete its sink before retaining this as a durable export receipt.
pub fn export_payload(
    input: impl Read,
    output: impl Write,
    recipient: &age::x25519::Recipient,
    policy: Policy,
    observation: &mut Observation,
) -> io::Result<ExportReceipt> {
    let sink = CipherWriter {
        output,
        digest: Sha256::new(),
        bytes: 0,
    };
    let encryptor = crypto(age::Encryptor::with_recipients(std::iter::once(
        recipient as &dyn age::Recipient,
    )))?;
    let mut writer = crypto(encryptor.wrap_output(sink))?;
    copy_payload(input, &mut writer, policy, None, observation)?;
    let mut sink = writer.finish()?;
    sink.flush()?;
    Ok(ExportReceipt {
        ciphertext_sha256: sink.digest.finalize().into(),
        ciphertext_bytes: sink.bytes,
    })
}

struct Scratch<'a> {
    path: &'a Path,
    remove: bool,
}
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        if self.remove {
            let _ = fs::remove_file(self.path);
        }
    }
}

/// Concrete fresh-destination encrypted-artifact publication proof. The caller
/// owns the secret stage identity. This does not restore a native vault or claim
/// authority/freshness from source fields or local filesystem placement.
#[allow(clippy::too_many_arguments)]
pub fn import_to_new_artifact(
    mut input: impl Read,
    identity: &age::x25519::Identity,
    stage_recipient: &age::x25519::Recipient,
    scratch: &Path,
    destination: &Path,
    permit: &ImportPermit,
    policy: Policy,
    observation: &mut Observation,
) -> io::Result<()> {
    if !permit.owner_authorized || scratch == destination {
        return Err(reject("explicit fresh-target authority required"));
    }
    let header = admit_header(&mut input, policy, observation)?;
    let state = Rc::new(RefCell::new(CipherState::default()));
    let metered = CipherReader {
        input: Cursor::new(header).chain(input),
        state: state.clone(),
        maximum: policy.ciphertext_bytes,
    };
    let decryptor = crypto(age::Decryptor::new(metered))?;
    if decryptor.is_scrypt() {
        return Err(reject("scrypt capability not enabled"));
    }
    observation.identity_work_started = true;
    let mut reader = crypto(decryptor.decrypt(std::iter::once(identity as &dyn age::Identity)))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(scratch)?;
    let mut cleanup = Scratch {
        path: scratch,
        remove: true,
    };
    let encryptor = crypto(age::Encryptor::with_recipients(std::iter::once(
        stage_recipient as &dyn age::Recipient,
    )))?;
    let mut staging = crypto(encryptor.wrap_output(&mut file))?;
    copy_payload(
        &mut reader,
        &mut staging,
        policy,
        Some(&permit.source),
        observation,
    )?;
    observation.outer_complete = true;
    if <[u8; 32]>::from(state.borrow().digest.clone().finalize())
        != permit.completed_ciphertext_sha256
    {
        return Err(reject("independent completed ciphertext receipt mismatch"));
    }
    observation.origin_verified = true;
    staging.finish()?.flush()?;
    file.sync_all()?;
    observation.stage_complete = true;
    // hard_link provides no-overwrite fresh-namespace publication on this
    // measured filesystem. Cross-OS/directory durability remains unqualified.
    fs::hard_link(scratch, destination)?;
    observation.activated = true;
    cleanup.remove = false;
    if fs::remove_file(scratch).is_err() {
        observation.cleanup_pending = true;
    }
    Ok(())
}

/// Fixed-memory synthetic producer for a one-record canonical full frame.
/// Used to exercise 16 MiB data and exact 64 KiB inner/outer boundaries without
/// constructing a payload-sized plaintext Vec or plaintext temporary file.
pub struct SyntheticPayload {
    prefix: Vec<u8>,
    prefix_pos: usize,
    remaining: u64,
    hash: Sha256,
    footer: Option<Vec<u8>>,
    footer_pos: usize,
}
impl SyntheticPayload {
    pub fn new(payload_bytes: u64) -> Self {
        let mut prefix = Source::records().0.to_vec();
        prefix[96..104].copy_from_slice(&1u64.to_be_bytes());
        prefix.push(1);
        prefix.extend_from_slice(&[0x42; 16]);
        prefix.extend_from_slice(&1u64.to_be_bytes());
        prefix.extend_from_slice(&0u32.to_be_bytes());
        prefix.extend_from_slice(&0u64.to_be_bytes());
        prefix.extend_from_slice(&payload_bytes.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        Self {
            prefix,
            prefix_pos: 0,
            remaining: payload_bytes,
            hash,
            footer: None,
            footer_pos: 0,
        }
    }
    pub fn source(&self) -> Source {
        Source(self.prefix[..104].try_into().expect("fixed source"))
    }
}
impl Read for SyntheticPayload {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.prefix_pos < self.prefix.len() {
            let n = output.len().min(self.prefix.len() - self.prefix_pos);
            output[..n].copy_from_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
            self.hash.update(&output[..n]);
            self.prefix_pos += n;
            return Ok(n);
        }
        if self.remaining != 0 {
            let n = output
                .len()
                .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            output[..n].fill(0xa5);
            self.hash.update(&output[..n]);
            self.remaining -= n as u64;
            return Ok(n);
        }
        let footer = self.footer.get_or_insert_with(|| {
            let mut footer = vec![255];
            footer.extend_from_slice(&1u64.to_be_bytes());
            self.hash.update(&footer);
            footer.extend_from_slice(&self.hash.clone().finalize());
            footer
        });
        let n = output.len().min(footer.len() - self.footer_pos);
        output[..n].copy_from_slice(&footer[self.footer_pos..self.footer_pos + n]);
        self.footer_pos += n;
        Ok(n)
    }
}

pub fn digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}
pub fn hex(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn export_records_file(
    recipient: &age::x25519::Recipient,
    path: &Path,
) -> io::Result<ExportReceipt> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let receipt = export_payload(
        Cursor::new(RECORDS),
        &mut file,
        recipient,
        Policy::proof(),
        &mut Observation::default(),
    )?;
    file.sync_all()?;
    Ok(receipt)
}

pub fn file_digest(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut buffer = [0; CHUNK];
    let mut hash = Sha256::new();
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buffer[..n]);
    }
}
