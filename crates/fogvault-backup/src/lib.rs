//! Standard age/v1 X25519 transport and bounded FVEXP001 framing.
//! Native/browser adapters own snapshot pinning, receipt persistence and final vault installation.
pub use age::x25519::{Identity, Recipient};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{self, Cursor, Read, Write},
    rc::Rc,
};
use zeroize::Zeroizing;
mod payload;
pub use payload::{export_snapshot, read_staged_records, RecordData};

pub const CHUNK: usize = 64 * 1024; // age/v1 STREAM plaintext chunk size.
const DOMAIN: &[u8] = b"fogvault/export/payload/v1\0";

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshot(pub(crate) [u8; 104]);
pub type Source = SourceSnapshot;
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
    maximum: u64,
    digest: Sha256,
    bytes: u64,
}
impl<W: Write> Write for CipherWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .maximum
            .checked_sub(self.bytes)
            .ok_or_else(|| reject("ciphertext capacity"))?;
        if bytes.len() as u64 > remaining {
            return Err(reject("ciphertext capacity"));
        }
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
        maximum: policy.ciphertext_bytes,
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

impl SourceSnapshot {
    pub fn new(
        vault_id: [u8; 16],
        descriptor_digest: [u8; 32],
        head_digest: [u8; 32],
        generation: u64,
        records: u64,
    ) -> Self {
        let mut bytes = [0; 104];
        bytes[..8].copy_from_slice(b"FVEXP001");
        bytes[8..24].copy_from_slice(&vault_id);
        bytes[24..56].copy_from_slice(&descriptor_digest);
        bytes[56..88].copy_from_slice(&head_digest);
        bytes[88..96].copy_from_slice(&generation.to_be_bytes());
        bytes[96..104].copy_from_slice(&records.to_be_bytes());
        Self(bytes)
    }
    pub fn from_header(bytes: [u8; 104]) -> io::Result<Self> {
        if &bytes[..8] != b"FVEXP001" {
            return Err(reject("unsupported payload version"));
        }
        Ok(Self(bytes))
    }
    pub fn header(&self) -> &[u8; 104] {
        &self.0
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.0[8..24].try_into().expect("fixed field")
    }
    pub fn generation(&self) -> u64 {
        u64::from_be_bytes(self.0[88..96].try_into().expect("fixed field"))
    }
    pub fn records(&self) -> u64 {
        u64::from_be_bytes(self.0[96..104].try_into().expect("fixed field"))
    }
}

/// Authority belongs to the caller's independently trusted registration/receipt store.
/// This permits installation only into the named fresh, unpublished target.
/// It is never derived from a checksum sidecar adjacent to an untrusted backup.
#[derive(Clone)]
pub struct FreshImportPermit {
    source: SourceSnapshot,
    expected_ciphertext: Option<[u8; 32]>,
    target: [u8; 16],
}
impl FreshImportPermit {
    pub fn origin_checked(
        source: SourceSnapshot,
        completed_ciphertext: [u8; 32],
        fresh_target: [u8; 16],
    ) -> io::Result<Self> {
        Self::new(source, Some(completed_ciphertext), fresh_target)
    }
    /// Explicit owner-accepted data import, with no source-authenticity claim.
    pub fn owner_accepted_unverified(
        source: SourceSnapshot,
        fresh_target: [u8; 16],
    ) -> io::Result<Self> {
        Self::new(source, None, fresh_target)
    }
    fn new(
        source: SourceSnapshot,
        expected_ciphertext: Option<[u8; 32]>,
        target: [u8; 16],
    ) -> io::Result<Self> {
        if source.vault_id() == target {
            return Err(reject("import requires a fresh target identity"));
        }
        Ok(Self {
            source,
            expected_ciphertext,
            target,
        })
    }
}

/// Opaque completion token. Only this crate can issue it after authenticated
/// encrypted EOF, inner EOF, origin admission and staging writer completion.
#[derive(Clone, Debug)]
pub struct CompletedImport {
    source: SourceSnapshot,
    target: [u8; 16],
    stage_ciphertext: [u8; 32],
    stage_bytes: u64,
    origin_verified: bool,
    source_ciphertext: [u8; 32],
}
impl CompletedImport {
    pub fn source(&self) -> &SourceSnapshot {
        &self.source
    }
    pub fn target_id(&self) -> [u8; 16] {
        self.target
    }
    pub fn stage_sha256(&self) -> [u8; 32] {
        self.stage_ciphertext
    }
    pub fn stage_bytes(&self) -> u64 {
        self.stage_bytes
    }
    pub fn source_ciphertext_sha256(&self) -> [u8; 32] {
        self.source_ciphertext
    }
    pub fn origin_verified(&self) -> bool {
        self.origin_verified
    }
}

/// Stream a backup into an encrypted staging sink. The host must keep that sink
/// unpublished and discard it on any error. A returned token authorizes only
/// the supplied fresh target; the adapter still owns durable publication/CAS.
#[allow(clippy::too_many_arguments)]
pub fn stage_import(
    mut input: impl Read,
    identity: &Identity,
    stage_recipient: &Recipient,
    output: impl Write,
    permit: &FreshImportPermit,
    policy: Policy,
    observation: &mut Observation,
) -> io::Result<CompletedImport> {
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
    let mut clear = crypto(decryptor.decrypt(std::iter::once(identity as &dyn age::Identity)))?;
    let sink = CipherWriter {
        output,
        maximum: policy.ciphertext_bytes,
        digest: Sha256::new(),
        bytes: 0,
    };
    let encryptor = crypto(age::Encryptor::with_recipients(std::iter::once(
        stage_recipient as &dyn age::Recipient,
    )))?;
    let mut writer = crypto(encryptor.wrap_output(sink))?;
    copy_payload(
        &mut clear,
        &mut writer,
        policy,
        Some(&permit.source),
        observation,
    )?;
    observation.outer_complete = true;
    let ciphertext_digest: [u8; 32] = state.borrow().digest.clone().finalize().into();
    if permit
        .expected_ciphertext
        .is_some_and(|expected| expected != ciphertext_digest)
    {
        return Err(reject("trusted completed-ciphertext receipt mismatch"));
    }
    observation.origin_verified = permit.expected_ciphertext.is_some();
    let mut output = writer.finish()?;
    output.flush()?;
    if output.bytes > policy.ciphertext_bytes {
        return Err(reject("encrypted staging capacity"));
    }
    observation.stage_complete = true;
    Ok(CompletedImport {
        source: permit.source.clone(),
        target: permit.target,
        stage_ciphertext: output.digest.finalize().into(),
        stage_bytes: output.bytes,
        origin_verified: observation.origin_verified,
        source_ciphertext: ciphertext_digest,
    })
}

impl Policy {
    /// Upper bound on simultaneously retained data bytes for the collecting
    /// convenience reader. Allocator/engine overhead and caller copies are not
    /// included; a host-wide budget must additionally admit those costs.
    pub fn collection_data_bytes(&self) -> io::Result<u64> {
        self.ciphertext_bytes
            .checked_add(
                self.total_plaintext_bytes
                    .checked_mul(2)
                    .ok_or_else(|| reject("collection size overflow"))?,
            )
            .and_then(|n| n.checked_add(CHUNK as u64))
            .ok_or_else(|| reject("collection size overflow"))
    }
}

/// Explicitly export an independent backup recipient secret for owner storage.
/// This is not a vault root key. Foreign-language copies remain caller-owned.
pub fn export_identity(identity: &Identity) -> Zeroizing<String> {
    use age::secrecy::ExposeSecret;
    Zeroizing::new(identity.to_string().expose_secret().to_owned())
}
