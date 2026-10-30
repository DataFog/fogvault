//! Independent test-only decoder for the consumer-neutral export framing.
//! This does not implement a product age backend or import publication.
use fogvault::experimental::crypto::digest;

const DOMAIN: &[u8] = b"fogvault/export/payload/v1\0";
const EMPTY: &[u8] = include_bytes!("../../../conformance/export-vectors-empty.bin");
const RECORDS: &[u8] = include_bytes!("../../../conformance/export-vectors-records.bin");

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    total_limit: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self.offset.checked_add(length).ok_or("overflow")?;
        if end > self.total_limit {
            return Err("resource");
        }
        let value = self.bytes.get(self.offset..end).ok_or("truncated")?;
        self.offset = end;
        Ok(value)
    }
    fn number(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Record {
    id: [u8; 16],
    revision: u64,
    schema: Vec<u8>,
    metadata: Vec<u8>,
    payload: Vec<u8>,
}

fn decode(bytes: &[u8]) -> Result<Vec<Record>, &'static str> {
    let mut input = Reader {
        bytes,
        offset: 0,
        // Fixed synthetic corpus size, not a product policy/default.
        total_limit: RECORDS.len(),
    };
    if input.take(8)? != b"FVEXP001" {
        return Err("version");
    }
    input.take(16 + 32 + 32)?; // Source claims are not a sender signature.
    let generation = input.number()?;
    if generation != 42 {
        return Err("fixture source");
    }
    let count = usize::try_from(input.number()?).map_err(|_| "count")?;
    if count > 2 {
        return Err("resource");
    }
    let minimum = count
        .checked_mul(45)
        .and_then(|size| size.checked_add(104 + 41))
        .ok_or("overflow")?;
    if minimum > input.total_limit {
        return Err("resource");
    }
    let mut records: Vec<Record> = Vec::new();
    for _ in 0..count {
        if input.take(1)? != [1] {
            return Err("tag");
        }
        let id: [u8; 16] = input.take(16)?.try_into().unwrap();
        if records.last().is_some_and(|last| last.id >= id) {
            return Err("order");
        }
        let revision = input.number()?;
        if revision == 0 {
            return Err("revision");
        }
        let schema = u32::from_be_bytes(input.take(4)?.try_into().unwrap()) as usize;
        let metadata = usize::try_from(input.number()?).map_err(|_| "length")?;
        let payload = usize::try_from(input.number()?).map_err(|_| "length")?;
        // These three bounds are the exact selected corpus maxima.
        if schema > b"example.test/opaque-v1".len()
            || metadata > b"m\0".len()
            || payload > b"alpha\0beta".len()
        {
            return Err("resource");
        }
        schema
            .checked_add(metadata)
            .and_then(|size| size.checked_add(payload))
            .and_then(|size| size.checked_add(input.offset))
            .and_then(|size| size.checked_add(41))
            .filter(|end| *end <= input.total_limit)
            .ok_or("resource")?;
        records.push(Record {
            id,
            revision,
            schema: input.take(schema)?.to_vec(),
            metadata: input.take(metadata)?.to_vec(),
            payload: input.take(payload)?.to_vec(),
        });
    }
    if input.take(1)? != [255] || input.number()? != count as u64 {
        return Err("footer");
    }
    let mut transcript = DOMAIN.to_vec();
    transcript.extend_from_slice(&bytes[..input.offset]);
    if input.take(32)? != digest(&transcript) {
        return Err("digest");
    }
    if input.offset != bytes.len() {
        return Err("trailing");
    }
    Ok(records)
}

#[test]
fn consumer_neutral_export_payload_has_independent_rust_framing_proof() {
    assert!(decode(EMPTY).unwrap().is_empty());
    let records = decode(RECORDS).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].revision, 7);
    assert_eq!(records[0].metadata, b"m\0");
    assert_eq!(records[0].payload, b"alpha\0beta");
    assert_eq!(records[1].revision, 9);
    assert_eq!(records[1].schema, b"example.test/opaque-v1");
    assert_eq!(records[1].payload, [0, 255, 128, 1]);
    let invalid: &[&[u8]] = &[
        include_bytes!("../../../conformance/export-vectors-invalid-unknown-version.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-unknown-record-tag.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-zero-revision.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-duplicate-id.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-out-of-order.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-footer-count-mismatch.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-header-count-mismatch.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-wrong-transcript-digest.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-trailing-byte.bin"),
        include_bytes!("../../../conformance/export-vectors-invalid-oversized-payload-length.bin"),
    ];
    for vector in invalid {
        assert!(decode(vector).is_err());
    }
    for vector in [EMPTY, RECORDS] {
        for prefix in 0..vector.len() {
            assert!(decode(&vector[..prefix]).is_err());
        }
    }
}
