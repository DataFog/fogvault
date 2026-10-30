use super::*;
use std::fmt;

/// One decoded, owner-authorized source record. Secret fields are erased on drop.
pub struct RecordData {
    pub id: [u8; 16],
    pub revision: u64,
    pub schema: Zeroizing<Vec<u8>>,
    pub metadata: Zeroizing<Vec<u8>>,
    pub payload: Zeroizing<Vec<u8>>,
}
impl fmt::Debug for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordData")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("schema", &"[redacted]")
            .field("metadata", &"[redacted]")
            .field("payload", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    RecordPrefix,
    Schema,
    Metadata,
    Payload,
    NextRecord,
    FooterPrefix,
    FooterDigest,
    Done,
}

struct SnapshotReader<I> {
    source: SourceSnapshot,
    records: I,
    record: Option<RecordData>,
    part: Vec<u8>,
    offset: usize,
    state: Phase,
    count: u64,
    previous: Option<[u8; 16]>,
    hash: Sha256,
    total: u64,
    policy: Policy,
}
impl<I: Iterator<Item = io::Result<RecordData>>> SnapshotReader<I> {
    fn new(source: SourceSnapshot, records: I, policy: Policy) -> io::Result<Self> {
        if source.records() > policy.records
            || source
                .records()
                .checked_mul(45)
                .and_then(|n| n.checked_add(145))
                .is_none_or(|n| n > policy.total_plaintext_bytes)
        {
            return Err(reject("source inventory admission"));
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        Ok(Self {
            part: source.0.to_vec(),
            source,
            records,
            record: None,
            offset: 0,
            state: Phase::Header,
            count: 0,
            previous: None,
            hash,
            total: 0,
            policy,
        })
    }
    fn next_part(&mut self) -> io::Result<()> {
        self.offset = 0;
        match self.state {
            Phase::Header | Phase::NextRecord => {
                self.record = None;
                if self.count == self.source.records() {
                    if self.records.next().is_some() {
                        return Err(reject("extra source record"));
                    }
                    self.part.clear();
                    self.part.push(255);
                    self.part.extend_from_slice(&self.count.to_be_bytes());
                    self.state = Phase::FooterPrefix;
                } else {
                    let record = self
                        .records
                        .next()
                        .ok_or_else(|| reject("incomplete source inventory"))??;
                    if record.revision == 0 || self.previous.is_some_and(|old| old >= record.id) {
                        return Err(reject("source record ordering or revision"));
                    }
                    let schema =
                        u32::try_from(record.schema.len()).map_err(|_| reject("schema size"))?;
                    let metadata = u64::try_from(record.metadata.len())
                        .map_err(|_| reject("metadata size"))?;
                    let payload =
                        u64::try_from(record.payload.len()).map_err(|_| reject("payload size"))?;
                    if schema as u64 > self.policy.schema_bytes
                        || metadata > self.policy.metadata_bytes
                        || payload > self.policy.payload_bytes
                    {
                        return Err(reject("source record admission"));
                    }
                    let remaining = 45u64
                        .checked_add(schema as u64)
                        .and_then(|n| n.checked_add(metadata))
                        .and_then(|n| n.checked_add(payload))
                        .and_then(|n| n.checked_add(41))
                        .and_then(|n| n.checked_add(self.total))
                        .ok_or_else(|| reject("source size overflow"))?;
                    if remaining > self.policy.total_plaintext_bytes {
                        return Err(reject("source total admission"));
                    }
                    self.part.clear();
                    self.part.push(1);
                    self.part.extend_from_slice(&record.id);
                    self.part.extend_from_slice(&record.revision.to_be_bytes());
                    self.part.extend_from_slice(&schema.to_be_bytes());
                    self.part.extend_from_slice(&metadata.to_be_bytes());
                    self.part.extend_from_slice(&payload.to_be_bytes());
                    self.previous = Some(record.id);
                    self.count += 1;
                    self.record = Some(record);
                    self.state = Phase::RecordPrefix;
                }
            }
            Phase::RecordPrefix => {
                self.part.clear();
                self.state = Phase::Schema;
            }
            Phase::Schema => {
                self.state = Phase::Metadata;
            }
            Phase::Metadata => {
                self.state = Phase::Payload;
            }
            Phase::Payload => {
                self.state = Phase::NextRecord;
                self.next_part()?;
            }
            Phase::FooterPrefix => {
                self.part = self.hash.clone().finalize().to_vec();
                self.state = Phase::FooterDigest;
            }
            Phase::FooterDigest => {
                self.part.clear();
                self.state = Phase::Done;
            }
            Phase::Done => {}
        }
        Ok(())
    }
    fn current(&self) -> &[u8] {
        match self.state {
            Phase::Schema => &self.record.as_ref().expect("record body").schema,
            Phase::Metadata => &self.record.as_ref().expect("record body").metadata,
            Phase::Payload => &self.record.as_ref().expect("record body").payload,
            _ => &self.part,
        }
    }
}
impl<I: Iterator<Item = io::Result<RecordData>>> Read for SnapshotReader<I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.state == Phase::Done {
                return Ok(0);
            }
            if self.offset == self.current().len() {
                self.next_part()?;
                continue;
            }
            let size = output.len().min(self.current().len() - self.offset);
            output[..size].copy_from_slice(&self.current()[self.offset..self.offset + size]);
            if self.state != Phase::FooterDigest {
                self.hash.update(&output[..size]);
            }
            self.total = self
                .total
                .checked_add(size as u64)
                .ok_or_else(|| reject("payload overflow"))?;
            if self.total > self.policy.total_plaintext_bytes {
                return Err(reject("payload admission"));
            }
            self.offset += size;
            return Ok(size);
        }
    }
}

/// Export a complete authenticated source inventory. Adapters must pin one source
/// snapshot across the iterator and must not turn a shortened page stream into
/// a new advertised source count. At most one supplied record is retained here.
pub fn export_snapshot(
    source: SourceSnapshot,
    records: impl IntoIterator<Item = io::Result<RecordData>>,
    output: impl Write,
    recipient: &Recipient,
    policy: Policy,
    observation: &mut Observation,
) -> io::Result<ExportReceipt> {
    let input = SnapshotReader::new(source, records.into_iter(), policy)?;
    export_payload(input, output, recipient, policy, observation)
}

/// Read a previously completed encrypted stage into bounded guarded records.
/// No record is returned until exact encrypted bytes, authenticated EOF, framing
/// and the fresh-target binding all pass. This collecting convenience API needs
/// a host policy admitting the full plaintext snapshot in memory; the streaming
/// export/staging APIs above do not make that allocation.
pub fn read_staged_records(
    mut input: impl Read,
    identity: &Identity,
    completed: &CompletedImport,
    target: [u8; 16],
    policy: Policy,
) -> io::Result<Vec<RecordData>> {
    if completed.target != target || completed.stage_bytes > policy.ciphertext_bytes {
        return Err(reject("stage target or byte admission"));
    }
    // The complete stage ciphertext is authenticated before plaintext parsing or
    // returning records. The host explicitly admits both ciphertext and clear
    // snapshot memory for this convenience path.
    let mut ciphertext = Vec::new();
    let mut chunk = Zeroizing::new([0u8; CHUNK]);
    let mut hash = Sha256::new();
    loop {
        let n = input.read(&mut *chunk)?;
        if n == 0 {
            break;
        }
        let length = (ciphertext.len() as u64)
            .checked_add(n as u64)
            .ok_or_else(|| reject("stage byte overflow"))?;
        if length > policy.ciphertext_bytes || length > completed.stage_bytes {
            return Err(reject("stage byte admission"));
        }
        ciphertext
            .try_reserve(n)
            .map_err(|_| reject("stage allocation rejected"))?;
        ciphertext.extend_from_slice(&chunk[..n]);
        hash.update(&chunk[..n]);
    }
    if ciphertext.len() as u64 != completed.stage_bytes
        || <[u8; 32]>::from(hash.finalize()) != completed.stage_ciphertext
    {
        return Err(reject("completed stage changed"));
    }
    let decryptor = crypto(age::Decryptor::new(Cursor::new(ciphertext)))?;
    let mut reader = crypto(decryptor.decrypt(std::iter::once(identity as &dyn age::Identity)))?;
    let mut frame = Zeroizing::new(Vec::new());
    loop {
        let n = reader.read(&mut *chunk)?;
        if n == 0 {
            break;
        }
        if (frame.len() as u64)
            .checked_add(n as u64)
            .is_none_or(|n| n > policy.total_plaintext_bytes)
        {
            chunk.fill(0);
            return Err(reject("plaintext snapshot admission"));
        }
        frame
            .try_reserve(n)
            .map_err(|_| reject("snapshot allocation rejected"))?;
        frame.extend_from_slice(&chunk[..n]);
        chunk.fill(0);
    }
    let mut observed = Observation::default();
    copy_payload(
        Cursor::new(&*frame),
        io::sink(),
        policy,
        Some(&completed.source),
        &mut observed,
    )?;
    let mut cursor = Cursor::new(&frame[104..]);
    let mut records = Vec::new();
    for _ in 0..completed.source.records() {
        let mut fixed = [0; 45];
        cursor.read_exact(&mut fixed)?;
        let schema = u32::from_be_bytes(fixed[25..29].try_into().expect("fixed field")) as usize;
        let metadata = usize::try_from(u64::from_be_bytes(
            fixed[29..37].try_into().expect("fixed field"),
        ))
        .map_err(|_| reject("metadata size"))?;
        let payload = usize::try_from(u64::from_be_bytes(
            fixed[37..45].try_into().expect("fixed field"),
        ))
        .map_err(|_| reject("payload size"))?;
        let mut body = |length| -> io::Result<Zeroizing<Vec<u8>>> {
            let mut value = Zeroizing::new(Vec::new());
            value
                .try_reserve_exact(length)
                .map_err(|_| reject("record allocation rejected"))?;
            value.resize(length, 0);
            cursor.read_exact(&mut value)?;
            Ok(value)
        };
        let record = RecordData {
            id: fixed[1..17].try_into().expect("fixed field"),
            revision: u64::from_be_bytes(fixed[17..25].try_into().expect("fixed field")),
            schema: body(schema)?,
            metadata: body(metadata)?,
            payload: body(payload)?,
        };
        records
            .try_reserve(1)
            .map_err(|_| reject("record inventory allocation rejected"))?;
        records.push(record);
    }
    Ok(records)
}
