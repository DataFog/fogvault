//! Disposable WebAssembly binding: the portable Rust Engine owns lifecycle logic;
//! JavaScript owns IndexedDB transactions and bounded ciphertext transport.
use fogvault::{
    AuditRequest, CommitReceipt, CredentialPlan, Engine, Error, KdfPolicy, KdfProfile, Limits,
    NodeHash, NodeStore, RecordCursor, RecordId, StoredRecord, VerifiedRecord, MAX_NODE_BYTES,
    MAX_PATH_NODES,
};
use js_sys::{Array, ArrayBuffer, BigInt, Object, Reflect, Uint8Array};
use std::collections::BTreeMap;
use wasm_bindgen::{prelude::*, JsCast};
use zeroize::Zeroizing;

trait BindingFailure: std::fmt::Display {
    fn code(&self) -> &'static str;
}
impl BindingFailure for Error {
    fn code(&self) -> &'static str {
        self.code()
    }
}
impl BindingFailure for &str {
    fn code(&self) -> &'static str {
        "InvalidInput"
    }
}
fn error(e: impl BindingFailure) -> JsValue {
    let result = js_sys::Error::new(&e.to_string());
    Reflect::set(
        result.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(e.code()),
    )
    .expect("new Error property");
    result.into()
}
fn set(o: &Object, k: &str, v: impl Into<JsValue>) {
    Reflect::set(o, &JsValue::from_str(k), &v.into()).expect("plain result object");
}
fn bytes(v: &JsValue, max: usize) -> Result<Vec<u8>, JsValue> {
    let a = v
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| error("Uint8Array required"))?;
    if a.length() as usize > max {
        return Err(error(Error::ResourceLimit));
    }
    Ok(a.to_vec())
}
// The raw credential channel accepts exact octets only. Taking JsValue keeps
// wasm-bindgen's array marshalling from coercing strings/arrays into passwords.
fn password_bytes(value: JsValue) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let array = value
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| error("password must be Uint8Array"))?;
    let buffer = array.buffer();
    if !buffer.is_instance_of::<ArrayBuffer>() {
        return Err(error("password requires nonshared ArrayBuffer backing"));
    }
    // Constructing an empty view validates attachment without copying content.
    // Reflect catches a detached-buffer TypeError as typed InvalidInput rather
    // than allowing a zero-length detached view to become an empty password.
    let constructor = Uint8Array::new_with_length(0)
        .unchecked_ref::<Object>()
        .constructor();
    Reflect::construct(
        &constructor,
        &Array::of3(buffer.as_ref(), &JsValue::from(0), &JsValue::from(0)),
    )
    .map_err(|_| error("password ArrayBuffer is detached"))?;
    Ok(Zeroizing::new(array.to_vec()))
}
fn id(value: &[u8]) -> Result<RecordId, JsValue> {
    value
        .try_into()
        .map_err(|_| error("16-byte identity required"))
}
fn key_effect(effect: fogvault::KeyEffect) -> &'static str {
    match effect {
        fogvault::KeyEffect::Preserved => "Preserved",
        fogvault::KeyEffect::FreshRootAndContentKeys => "FreshRootAndContentKeys",
    }
}
fn array_bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}
/// Read CAS input before the WebAssembly i64 ABI can truncate a BigInt.
fn expected_revision(value: &JsValue) -> Result<Option<u64>, JsValue> {
    let value = value
        .dyn_ref::<BigInt>()
        .ok_or_else(|| error(Error::Malformed("expected revision must be BigInt")))?;
    // Compare in JS BigInt space before rendering a bounded decimal string.
    if value < &BigInt::from(0) || value > &BigInt::from(i64::MAX) {
        return Err(error(Error::Malformed("expected revision range")));
    }
    let decimal = String::from(
        value
            .to_string(10)
            .map_err(|_| error(Error::Malformed("expected revision conversion")))?,
    );
    let revision = decimal
        .parse::<u64>()
        .map_err(|_| error(Error::Malformed("expected revision range")))?;
    Ok((revision != 0).then_some(revision))
}

// Host-supplied admission policy, independent of the untrusted saved header.
// Numeric fields are checked before any f64 -> u32 conversion or KDF work.
fn kdf_profile(value: &JsValue) -> Result<KdfProfile, JsValue> {
    if !value.is_object() || value.is_null() || Array::is_array(value) {
        return Err(error("KDF profile object required"));
    }
    let keys = Reflect::own_keys(value).map_err(|_| error("invalid KDF profile keys"))?;
    if keys.length() != 2
        || keys
            .iter()
            .any(|key| !matches!(key.as_string().as_deref(), Some("memory_kib" | "passes")))
    {
        return Err(error("KDF profile requires exactly memory_kib and passes"));
    }
    let field = |name: &str| -> Result<u32, JsValue> {
        let number = Reflect::get(value, &JsValue::from_str(name))
            .map_err(|_| error("invalid KDF profile field"))?
            .as_f64()
            .ok_or_else(|| error("KDF profile field must be a number"))?;
        if !number.is_finite() || number.fract() != 0.0 || number < 0.0 || number > u32::MAX as f64
        {
            return Err(error("KDF profile field outside exact u32 range"));
        }
        Ok(number as u32)
    };
    KdfProfile::argon2id(field("memory_kib")?, field("passes")?).map_err(error)
}
fn kdf_policy(value: JsValue) -> Result<KdfPolicy, JsValue> {
    if value.is_undefined() || value.is_null() {
        return Ok(KdfPolicy::baseline());
    }
    if !Array::is_array(&value) {
        return Err(error("KDF profile allowlist array required"));
    }
    let items = Array::from(&value);
    let mut profiles = Vec::new();
    for item in items.iter() {
        profiles.push(kdf_profile(&item)?);
    }
    KdfPolicy::new(profiles).map_err(error)
}

struct Cache {
    nodes: BTreeMap<NodeHash, Vec<u8>>,
    writes: BTreeMap<NodeHash, Vec<u8>>,
}
impl Cache {
    fn parse(value: JsValue, maximum: usize) -> Result<Self, JsValue> {
        if !Array::is_array(&value) {
            return Err(error("node array required"));
        }
        let items = Array::from(&value);
        if items.length() as usize > maximum {
            return Err(error(Error::ResourceLimit));
        }
        let mut nodes = BTreeMap::new();
        for item in items.iter() {
            if !Array::is_array(&item) {
                return Err(error("node pair array required"));
            }
            let pair = Array::from(&item);
            if pair.length() != 2 {
                return Err(error("node pair required"));
            }
            let hash: NodeHash = bytes(&pair.get(0), 32)?
                .as_slice()
                .try_into()
                .map_err(|_| error("hash width"))?;
            let body = bytes(&pair.get(1), MAX_NODE_BYTES)?;
            if nodes.insert(hash, body).is_some() {
                return Err(error("duplicate cache node"));
            }
        }
        Ok(Self {
            nodes,
            writes: BTreeMap::new(),
        })
    }
}
impl NodeStore for Cache {
    fn get(&mut self, hash: &NodeHash) -> fogvault::Result<Option<Vec<u8>>> {
        Ok(self.nodes.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, body: &[u8]) -> fogvault::Result<()> {
        if self.nodes.get(&hash).is_some_and(|old| old != body) {
            return Err(Error::Integrity);
        }
        self.nodes.insert(hash, body.to_vec());
        self.writes.insert(hash, body.to_vec());
        Ok(())
    }
}
/// A thin binding: the portable Engine owns keys, sessions, audits and commits.
/// JavaScript supplies bounded storage snapshots and confirms transaction completion.
#[wasm_bindgen]
pub struct BrowserSession {
    engine: Engine,
    inventory: Option<Inventory>,
}
struct Inventory {
    cursor: RecordCursor,
    pending: Option<VerifiedRecord>,
    records: Vec<(RecordId, u64)>,
    maximum: usize,
    active: bool,
    ready: bool,
    complete: bool,
    before: fogvault::IndexStats,
}
impl BrowserSession {
    fn receipt(receipt: &CommitReceipt) -> JsValue {
        let result = Object::new();
        set(&result, "generation", BigInt::from(receipt.generation));
        set(&result, "request_id", array_bytes(&receipt.request_id));
        set(&result, "head_digest", array_bytes(&receipt.head_digest));
        result.into()
    }
    fn credential_plan(plan: CredentialPlan) -> JsValue {
        let result = Object::new();
        set(&result, "replay", plan.replay);
        set(&result, "key_effect", key_effect(plan.key_effect()));
        set(&result, "receipt", Self::receipt(&plan.receipt));
        set(
            &result,
            "prior_descriptor",
            array_bytes(&plan.prior_descriptor),
        );
        set(&result, "descriptor", array_bytes(&plan.descriptor_bytes));
        set(&result, "prior_head", array_bytes(&plan.prior_head));
        set(&result, "head", array_bytes(&plan.head_bytes));
        result.into()
    }
}
#[wasm_bindgen]
impl BrowserSession {
    pub fn create(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        Ok(Self {
            engine: Engine::create(&password, limits).map_err(error)?,
            inventory: None,
        })
    }
    pub fn create_with_kdf_policy(
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let policy = kdf_policy(profiles)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        Ok(Self {
            engine: Engine::create_with_kdf_policy(&password, limits, policy).map_err(error)?,
            inventory: None,
        })
    }
    /// Creation authority stays private until the host's initialization commits.
    pub fn confirm_create(&mut self) -> Result<(), JsValue> {
        self.engine.activate_created().map_err(error)?;
        Ok(())
    }
    /// KDF work precedes the read transaction; activation follows its completion.
    pub fn begin_unlock(
        descriptor: &[u8],
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let mut engine = Engine::open(descriptor, limits).map_err(error)?;
        engine.begin_unlock(&password).map_err(error)?;
        Ok(Self {
            engine,
            inventory: None,
        })
    }
    pub fn begin_unlock_with_kdf_policy(
        descriptor: &[u8],
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] password: JsValue,
        max_payload: u32,
        max_metadata: u32,
        max_records: u32,
        profiles: JsValue,
    ) -> Result<BrowserSession, JsValue> {
        let password = password_bytes(password)?;
        let policy = kdf_policy(profiles)?;
        let limits = Limits {
            max_payload_bytes: max_payload as usize,
            max_metadata_bytes: max_metadata as usize,
            max_records: max_records as usize,
        };
        let mut engine = Engine::open_with_kdf_policy(descriptor, limits, policy).map_err(error)?;
        engine.begin_unlock(&password).map_err(error)?;
        Ok(Self {
            engine,
            inventory: None,
        })
    }
    pub fn begin_reconcile_snapshot(
        &mut self,
        descriptor: &[u8],
        head: &[u8],
        request: &[u8],
    ) -> Result<(), JsValue> {
        self.engine
            .begin_reconcile_snapshot(descriptor, head, id(request)?)
            .map_err(error)
    }
    pub fn prepare_password_change(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] old_password: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] new_password: JsValue,
        request: &[u8],
    ) -> Result<JsValue, JsValue> {
        let old_password = password_bytes(old_password)?;
        let new_password = password_bytes(new_password)?;
        let request = id(request)?;
        let draft = self
            .engine
            .draft_password_change(&old_password, &new_password, request)
            .map_err(error)?;
        let plan = self.engine.stage_credential_change(&draft).map_err(error)?;
        Ok(Self::credential_plan(plan))
    }
    pub fn prepare_kdf_upgrade(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array")] password: JsValue,
        target: JsValue,
        request: &[u8],
    ) -> Result<JsValue, JsValue> {
        let password = password_bytes(password)?;
        let target = kdf_profile(&target)?;
        let request = id(request)?;
        let draft = self
            .engine
            .draft_kdf_upgrade(&password, target, request)
            .map_err(error)?;
        let plan = self.engine.stage_credential_change(&draft).map_err(error)?;
        Ok(Self::credential_plan(plan))
    }
    pub fn confirm_credential(
        &mut self,
        descriptor: &[u8],
        head: &[u8],
    ) -> Result<JsValue, JsValue> {
        let result = self
            .engine
            .confirm_credential_commit(descriptor, head)
            .map_err(error)?;
        let receipt: Object = Self::receipt(&result.receipt).unchecked_into();
        set(&receipt, "key_effect", key_effect(result.key_effect()));
        Ok(receipt.into())
    }
    pub fn begin_audit(&mut self, head: &[u8]) -> Result<(), JsValue> {
        self.engine.begin_audit(head).map_err(error)
    }
    pub fn begin_reconcile(&mut self, head: &[u8], request: &[u8]) -> Result<(), JsValue> {
        self.engine
            .begin_reconcile(head, id(request)?)
            .map_err(error)
    }
    pub fn audit_next(&self) -> Result<JsValue, JsValue> {
        let result = Object::new();
        match self.engine.audit_next().map_err(error)? {
            AuditRequest::Record { id, entry } => {
                set(&result, "kind", "record");
                set(&result, "id", array_bytes(&id));
                set(&result, "revision", BigInt::from(entry.revision));
            }
            AuditRequest::Node(hash) => {
                set(&result, "kind", "node");
                set(&result, "hash", array_bytes(&hash));
            }
            AuditRequest::Done => set(&result, "kind", "done"),
        }
        Ok(result.into())
    }
    pub fn supply_node(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        self.engine.supply_node(bytes).map_err(error)
    }
    pub fn supply_record(&mut self, revision: u64, length: u64) -> Result<(), JsValue> {
        self.engine
            .supply_record(revision, length, None)
            .map_err(error)
    }
    pub fn finish_audit(&mut self, record_count: u64, node_count: u64) -> Result<JsValue, JsValue> {
        let stats = self
            .engine
            .finish_audit(record_count, node_count)
            .map_err(error)?;
        let result = Object::new();
        // The host's cardinality policy is u32, keeping these totals exact in JS.
        set(&result, "nodes_read", stats.nodes_read as f64);
        set(&result, "records_checked", stats.records_checked as f64);
        set(&result, "node_bytes", stats.node_bytes as f64);
        set(
            &result,
            "peak_buffered_nodes",
            stats.peak_buffered_nodes as u32,
        );
        set(&result, "peak_path_nodes", stats.peak_path_nodes as u32);
        Ok(result.into())
    }
    pub fn activate_audit(&mut self) -> Result<JsValue, JsValue> {
        self.engine
            .activate_audit()
            .map(|receipt| Self::receipt(&receipt))
            .map_err(error)
    }
    pub fn abort_audit(&mut self) {
        self.engine.abort_audit();
    }
    pub fn check_snapshot(&self, descriptor: &[u8], head: &[u8]) -> Result<(), JsValue> {
        self.engine.check_snapshot(descriptor, head).map_err(error)
    }
    /// Check lifecycle authority before JavaScript starts storage I/O.
    pub fn check_available(&self) -> Result<(), JsValue> {
        self.engine.current_receipt().map(|_| ()).map_err(error)
    }
    pub fn latest_request(&self) -> Vec<u8> {
        self.engine.latest_request().to_vec()
    }
    pub fn current_receipt(&self) -> Result<JsValue, JsValue> {
        self.engine
            .current_receipt()
            .map(|receipt| Self::receipt(&receipt))
            .map_err(error)
    }
    /// Bind externally queued mutation intent to its exact source commit.
    pub fn check_expected_head(&self, expected_head: &[u8]) -> Result<(), JsValue> {
        let expected: [u8; 32] = expected_head
            .try_into()
            .map_err(|_| error("32-byte expected head required"))?;
        if self.engine.current_receipt().map_err(error)?.head_digest != expected {
            return Err(error(Error::Conflict));
        }
        Ok(())
    }
    pub fn descriptor(&self) -> Vec<u8> {
        self.engine.descriptor_bytes().to_vec()
    }
    pub fn head(&self) -> Vec<u8> {
        self.engine.head_bytes().to_vec()
    }
    pub fn lock(&mut self) {
        self.engine.lock();
        self.inventory = None;
    }
    pub fn begin_records(&mut self) -> Result<(), JsValue> {
        let cursor = self.engine.begin_records().map_err(error)?;
        self.inventory = Some(Inventory {
            cursor,
            pending: None,
            records: Vec::new(),
            maximum: 0,
            active: false,
            ready: false,
            complete: false,
            before: fogvault::IndexStats::default(),
        });
        Ok(())
    }
    pub fn cancel_records(&mut self) {
        if let Some(scan) = &mut self.inventory {
            scan.cursor.cancel();
        }
        self.inventory = None;
    }
    pub fn start_record_page(&mut self, maximum: JsValue) -> Result<(), JsValue> {
        let value = maximum
            .as_f64()
            .ok_or_else(|| error("page size must be an exact positive u32"))?;
        if !value.is_finite() || value.fract() != 0.0 || value <= 0.0 || value > u32::MAX as f64 {
            return Err(error("page size must be an exact positive u32"));
        }
        let scan = self
            .inventory
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        self.engine.record_next(&scan.cursor).map_err(error)?;
        if scan.active || scan.pending.is_some() {
            return Err(error(Error::Conflict));
        }
        scan.records.clear();
        scan.maximum = value as usize;
        let remaining = scan
            .cursor
            .record_count()
            .checked_sub(scan.cursor.records_checked())
            .ok_or_else(|| error(Error::Integrity))?;
        scan.records
            .try_reserve(scan.maximum.min(remaining as usize))
            .map_err(|_| error(Error::ResourceLimit))?;
        scan.before = scan.cursor.stats();
        scan.active = true;
        scan.ready = false;
        scan.complete = false;
        Ok(())
    }
    pub fn record_page_next(&mut self) -> Result<JsValue, JsValue> {
        let scan = self
            .inventory
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if !scan.active || scan.ready {
            return Err(error(Error::Conflict));
        }
        let next = self.engine.record_next(&scan.cursor).map_err(error)?;
        let result = Object::new();
        if let Some(proof) = &scan.pending {
            set(&result, "kind", "record");
            set(&result, "id", array_bytes(&proof.id()));
            set(&result, "revision", BigInt::from(proof.revision()));
        } else if scan.records.len() >= scan.maximum || next.is_none() {
            scan.ready = true;
            scan.complete = next.is_none();
            set(&result, "kind", "done");
        } else if let Some(hash) = next {
            set(&result, "kind", "node");
            set(&result, "hash", array_bytes(&hash));
        }
        Ok(result.into())
    }
    pub fn supply_record_page_node(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let scan = self
            .inventory
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if !scan.active || scan.ready || scan.pending.is_some() {
            return Err(error(Error::Conflict));
        }
        scan.pending = self
            .engine
            .supply_record_node(&mut scan.cursor, bytes)
            .map_err(error)?;
        Ok(())
    }
    pub fn supply_record_page_row(
        &mut self,
        revision: u64,
        envelope: &[u8],
    ) -> Result<(), JsValue> {
        let scan = self
            .inventory
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if !scan.active || scan.ready {
            return Err(error(Error::Conflict));
        }
        let proof = scan
            .pending
            .as_ref()
            .ok_or_else(|| error(Error::Conflict))?;
        self.engine
            .verify_record(proof, revision, envelope)
            .map_err(error)?;
        scan.records.push((proof.id(), proof.revision()));
        scan.pending = None;
        Ok(())
    }
    pub fn finish_record_page(
        &mut self,
        record_count: u64,
        node_count: u64,
    ) -> Result<JsValue, JsValue> {
        let scan = self
            .inventory
            .as_mut()
            .ok_or_else(|| error(Error::Conflict))?;
        if !scan.active || !scan.ready || scan.pending.is_some() {
            return Err(error(Error::Conflict));
        }
        let expected = scan.cursor.record_count();
        let nodes = if expected == 0 {
            0
        } else {
            expected
                .checked_mul(2)
                .and_then(|n| n.checked_sub(1))
                .ok_or_else(|| error(Error::ResourceLimit))?
        };
        if record_count != expected || node_count != nodes {
            scan.cursor.cancel();
            return Err(error(Error::Integrity));
        }
        if scan.complete {
            self.engine
                .finish_records(&mut scan.cursor)
                .map_err(error)?;
        } else {
            self.engine.record_next(&scan.cursor).map_err(error)?;
        }
        let result = Object::new();
        let records = Array::new();
        for (id, revision) in &scan.records {
            let row = Object::new();
            set(&row, "id", array_bytes(id));
            set(&row, "revision", BigInt::from(*revision));
            records.push(&row);
        }
        set(&result, "records", records);
        set(&result, "complete", scan.complete);
        set(
            &result,
            "receipt",
            Self::receipt(&self.engine.current_receipt().map_err(error)?),
        );
        let stats = Object::new();
        let current = scan.cursor.stats();
        set(
            &stats,
            "nodes_read",
            (current.nodes_read - scan.before.nodes_read) as f64,
        );
        set(
            &stats,
            "node_bytes",
            (current.bytes_read - scan.before.bytes_read) as f64,
        );
        set(&stats, "records_checked", scan.records.len() as f64);
        set(
            &stats,
            "max_stack_nodes",
            scan.cursor.peak_frontier_nodes() as f64,
        );
        set(&result, "stats", stats);
        scan.active = false;
        scan.ready = false;
        scan.records.clear();
        Ok(result.into())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_delete_at(
        &mut self,
        expected_head: &[u8],
        identity: &[u8],
        expected: JsValue,
        request: &[u8],
        nodes: JsValue,
        previous: &[u8],
        stored_revision: u64,
    ) -> Result<JsValue, JsValue> {
        self.check_expected_head(expected_head)?;
        self.prepare_delete(
            identity,
            expected,
            request,
            nodes,
            previous,
            stored_revision,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_delete(
        &mut self,
        identity: &[u8],
        expected: JsValue,
        request: &[u8],
        nodes: JsValue,
        previous: &[u8],
        stored_revision: u64,
    ) -> Result<JsValue, JsValue> {
        let expected = expected_revision(&expected)?
            .ok_or_else(|| error("deletion requires a positive revision"))?;
        let identity = id(identity)?;
        let request = id(request)?;
        let draft = self
            .engine
            .draft_delete(identity, expected, request)
            .map_err(error)?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES + 1)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        let previous = if previous.is_empty() && stored_revision == 0 {
            None
        } else {
            Some(StoredRecord {
                revision: stored_revision,
                envelope: previous,
            })
        };
        let plan = self
            .engine
            .stage_delete(&draft, proof, previous, &mut cache)
            .map_err(error)?;
        let result = Object::new();
        set(&result, "replay", plan.replay);
        set(&result, "receipt", Self::receipt(&plan.receipt));
        set(
            &result,
            "prior_descriptor",
            array_bytes(&plan.prior_descriptor),
        );
        set(&result, "prior_head", array_bytes(&plan.prior_head));
        set(&result, "head", array_bytes(&plan.head_bytes));
        set(&result, "revision", BigInt::from(plan.deleted_revision));
        let written = Array::new();
        for (hash, body) in cache.writes {
            let pair = Array::new();
            pair.push(&array_bytes(&hash));
            pair.push(&array_bytes(&body));
            written.push(&pair);
        }
        let obsolete = Array::new();
        for hash in plan.obsolete {
            obsolete.push(&array_bytes(&hash));
        }
        set(&result, "nodes", written);
        set(&result, "obsolete", obsolete);
        Ok(result.into())
    }
    /// Prepare a maintained save using the source commit captured by its caller.
    /// Record revisions alone do not distinguish delete/reinsert incarnations.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_save_at(
        &mut self,
        expected_head: JsValue,
        identity: &[u8],
        expected: JsValue,
        metadata: Vec<u8>,
        payload: Vec<u8>,
        request: &[u8],
        nodes: JsValue,
        previous: &[u8],
        stored_revision: u64,
    ) -> Result<JsValue, JsValue> {
        let mut metadata = Zeroizing::new(metadata);
        let mut payload = Zeroizing::new(payload);
        let expected_head = bytes(&expected_head, 32)?;
        self.check_expected_head(&expected_head)?;
        // Transfer the admitted owned buffers without another plaintext copy.
        self.prepare_save_revision_diagnostic(
            identity,
            expected,
            std::mem::take(&mut *metadata),
            std::mem::take(&mut *payload),
            request,
            nodes,
            previous,
            stored_revision,
        )
    }
    /// Legacy experiment only: captures the execution-time source head.
    /// This is not a maintained mutation interface for externally queued intent.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_save_revision_diagnostic(
        &mut self,
        identity: &[u8],
        expected: JsValue,
        metadata: Vec<u8>,
        payload: Vec<u8>,
        request: &[u8],
        nodes: JsValue,
        previous: &[u8],
        stored_revision: u64,
    ) -> Result<JsValue, JsValue> {
        // Guard owned plaintext copies even if argument validation fails.
        let metadata = Zeroizing::new(metadata);
        let payload = Zeroizing::new(payload);
        let expected = expected_revision(&expected)?;
        let identity = id(identity)?;
        let request = id(request)?;
        let draft = self
            .engine
            .draft_save(identity, expected, &metadata, &payload, request)
            .map_err(error)?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        let previous = if previous.is_empty() && stored_revision == 0 {
            None
        } else {
            Some(StoredRecord {
                revision: stored_revision,
                envelope: previous,
            })
        };
        let plan = self
            .engine
            .stage_save(&draft, proof, previous, &mut cache)
            .map_err(error)?;
        let result = Object::new();
        set(&result, "replay", plan.replay);
        set(&result, "receipt", Self::receipt(&plan.receipt));
        set(&result, "prior_head", array_bytes(&plan.prior_head));
        set(&result, "head", array_bytes(&plan.head_bytes));
        set(&result, "revision", BigInt::from(plan.revision));
        if !plan.replay {
            set(&result, "envelope", array_bytes(&plan.envelope));
            let written = Array::new();
            for (hash, body) in cache.writes {
                let pair = Array::new();
                pair.push(&array_bytes(&hash));
                pair.push(&array_bytes(&body));
                written.push(&pair);
            }
            let obsolete = Array::new();
            for hash in plan.obsolete {
                obsolete.push(&array_bytes(&hash));
            }
            set(&result, "nodes", written);
            set(&result, "obsolete", obsolete);
        }
        Ok(result.into())
    }
    pub fn confirm(&mut self, committed: &[u8]) -> Result<JsValue, JsValue> {
        self.engine
            .confirm_commit(committed)
            .map(|receipt| Self::receipt(&receipt))
            .map_err(error)
    }
    pub fn mark_unknown(&mut self) -> Result<(), JsValue> {
        self.engine.mark_unknown().map_err(error)
    }
    pub fn abort(&mut self) -> Result<(), JsValue> {
        self.engine.abort_prepared().map_err(error)
    }
    pub fn verify_record(
        &self,
        identity: &[u8],
        nodes: JsValue,
        envelope: &[u8],
        stored_revision: u64,
    ) -> Result<u64, JsValue> {
        let identity = id(identity)?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        let record = proof.entry().ok_or_else(|| error(Error::NotFound))?;
        self.engine
            .verify_record(record, stored_revision, envelope)
            .map_err(error)
    }
    pub fn verify_absent(&self, identity: &[u8], nodes: JsValue) -> Result<(), JsValue> {
        let identity = id(identity)?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        if proof.entry().is_some() {
            return Err(error(Error::Integrity));
        }
        Ok(())
    }
    pub fn read(
        &self,
        identity: &[u8],
        nodes: JsValue,
        envelope: &[u8],
    ) -> Result<JsValue, JsValue> {
        let identity = id(identity)?;
        let mut cache = Cache::parse(nodes, MAX_PATH_NODES)?;
        let proof = self.engine.lookup(&mut cache, &identity).map_err(error)?;
        let record = proof.entry().ok_or_else(|| error(Error::NotFound))?;
        let decoded = self
            .engine
            .read_verified(record, record.revision(), envelope)
            .map_err(error)?;
        let result = Object::new();
        set(&result, "metadata", array_bytes(&decoded.metadata));
        set(&result, "payload", array_bytes(&decoded.payload));
        set(&result, "revision", BigInt::from(record.revision()));
        Ok(result.into())
    }
}
#[wasm_bindgen]
pub fn memory_bytes() -> u32 {
    wasm_bindgen::memory()
        .unchecked_into::<js_sys::WebAssembly::Memory>()
        .buffer()
        .unchecked_into::<js_sys::ArrayBuffer>()
        .byte_length()
}

/// Validate caller-chosen admission before the host opens/creates storage.
#[wasm_bindgen]
pub fn validate_kdf_policy(profiles: JsValue) -> Result<(), JsValue> {
    kdf_policy(profiles).map(|_| ())
}

/// Exercise the binding type independently of record crypto; u64 is a JS BigInt.
#[wasm_bindgen]
pub fn revision_roundtrip(value: u64) -> u64 {
    value
}
