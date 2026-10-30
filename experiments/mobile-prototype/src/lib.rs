//! Disposable single-record portable-core ABI probe with in-memory ciphertext.
//! No supported mobile storage adapter is provided.
//! The C caller owns input/output buffers. Registry IDs never reuse freed IDs.

use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, OnceLock},
};

use fogvault::{AuditRequest, Engine, Error, Limits, NodeHash, NodeStore};
use zeroize::Zeroizing;

const OK: i32 = 0;
const ARGUMENT: i32 = 1;
const AUTHENTICATION: i32 = 2;
const LOCKED: i32 = 3;
const STALE_SESSION: i32 = 4;
const BUFFER_TOO_SMALL: i32 = 5;
const INTEGRITY: i32 = 6;
const INVALID_HANDLE: i32 = 7;
const FAILURE: i32 = 8;
const INVALID_INPUT: i32 = 9;
const ID: [u8; 16] = [0x3a; 16];

#[derive(Default)]
struct Nodes(BTreeMap<NodeHash, Vec<u8>>);
impl NodeStore for Nodes {
    fn get(&mut self, hash: &NodeHash) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.get(hash).cloned())
    }
    fn put(&mut self, hash: NodeHash, bytes: &[u8]) -> Result<(), Error> {
        if self.0.get(&hash).is_some_and(|old| old != bytes) {
            return Err(Error::Integrity);
        }
        self.0.insert(hash, bytes.to_vec());
        Ok(())
    }
}

/// In-memory encrypted storage for the ABI experiment. All lifecycle and key
/// authority belongs to the same portable Engine used by the other adapters.
struct Probe {
    engine: Engine,
    head_bytes: Vec<u8>,
    envelope: Vec<u8>,
    nodes: Nodes,
}
impl Probe {
    fn create(password: &[u8], payload: &[u8]) -> Result<Self, Error> {
        let limits = Limits {
            max_payload_bytes: payload.len(),
            max_metadata_bytes: 0,
            max_records: 1, // This probe's fixture cardinality, not product policy.
        };
        let mut engine = Engine::create(password, limits)?;
        // In-memory initialization has no asynchronous commit boundary.
        engine.activate_created()?;
        let mut nodes = Nodes::default();
        let plan = engine.prepare_save(
            &mut nodes,
            ID,
            None,
            &[],
            payload,
            [0x71; 16], // Synthetic fixture request; not a product identifier policy.
            None,
        )?;
        for hash in &plan.obsolete {
            nodes.0.remove(hash);
        }
        let head_bytes = plan.head_bytes;
        let envelope = plan.envelope;
        engine.confirm_commit(&head_bytes)?;
        engine.lock();
        Ok(Self {
            engine,
            head_bytes,
            envelope,
            nodes,
        })
    }

    fn unlock(&mut self, password: &[u8]) -> Result<[u8; 16], i32> {
        // A new attempt revokes previous authority, including on a bad password.
        self.engine
            .begin_unlock(password)
            .map_err(|error| match error.code() {
                "Authentication" => AUTHENTICATION,
                _ => FAILURE,
            })?;
        let result = (|| {
            self.engine
                .begin_audit(&self.head_bytes)
                .map_err(|_| INTEGRITY)?;
            loop {
                match self.engine.audit_next().map_err(|_| INTEGRITY)? {
                    AuditRequest::Node(hash) => {
                        let bytes = self
                            .nodes
                            .get(&hash)
                            .map_err(|_| INTEGRITY)?
                            .ok_or(INTEGRITY)?;
                        self.engine.supply_node(&bytes).map_err(|_| INTEGRITY)?;
                    }
                    AuditRequest::Record { id, .. } => {
                        if id != ID {
                            return Err(INTEGRITY);
                        }
                        // This small in-memory adapter admits the complete body;
                        // browser startup can instead admit only record metadata.
                        self.engine
                            .supply_record(1, self.envelope.len() as u64, Some(&self.envelope))
                            .map_err(|_| INTEGRITY)?;
                    }
                    AuditRequest::Done => break,
                }
            }
            self.engine
                .finish_audit(1, self.nodes.0.len() as u64)
                .map_err(|_| INTEGRITY)?;
            self.engine.activate_audit().map_err(|_| INTEGRITY)?;
            let token = self.engine.current_session().map_err(|_| FAILURE)?;
            self.engine.token_bytes(&token).map_err(|_| FAILURE)
        })();
        if result.is_err() {
            self.engine.lock();
        }
        result
    }

    fn read(&mut self, token: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, i32> {
        let token = self
            .engine
            .session_from_bytes(*token)
            .map_err(read_status)?;
        self.engine.check_session(&token).map_err(read_status)?;
        self.engine
            .check_snapshot(self.engine.descriptor_bytes(), &self.head_bytes)
            .map_err(read_status)?;
        let proof = self
            .engine
            .lookup(&mut self.nodes, &ID)
            .map_err(read_status)?;
        let record = proof.entry().ok_or(INTEGRITY)?;
        self.engine
            .read_verified(record, 1, &self.envelope)
            .map(|record| record.payload)
            .map_err(read_status)
    }
}
fn read_status(error: Error) -> i32 {
    match error {
        Error::Locked => LOCKED,
        Error::StaleSession => STALE_SESSION,
        _ => INTEGRITY,
    }
}

struct Registry {
    next: u64,
    entries: BTreeMap<u64, Probe>,
}
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            entries: BTreeMap::new(),
        })
    })
}
fn boundary(operation: impl FnOnce() -> Result<(), i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => OK,
        Ok(Err(status)) => status,
        Err(_) => FAILURE,
    }
}

// The ABI cannot establish arbitrary pointer validity. Each non-null pointer must
// refer to accessible caller-owned memory of its declared length for this call.
unsafe fn input<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], i32> {
    if length > isize::MAX as usize || (pointer.is_null() && length != 0) {
        return Err(ARGUMENT);
    }
    if length == 0 {
        return Ok(&[]);
    }
    // SAFETY: validity/lifetime is the documented C caller contract; null/size checked.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

/// Validate text-password UTF-8 and copy its exact bytes without normalization.
/// Raw-byte create/unlock inputs remain a separate, unrestricted byte channel.
///
/// # Safety
/// Input/output buffers must satisfy the header's disjoint pointer/lifetime
/// contract. `written` is aligned/writable for one usize and is cleared first.
#[no_mangle]
pub unsafe extern "C" fn fv_probe_password_utf8(
    password: *const u8,
    password_len: usize,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    boundary(|| {
        if written.is_null() {
            return Err(ARGUMENT);
        }
        // SAFETY: caller supplies one writable usize, disjoint from all buffers.
        unsafe { written.write(0) };
        if capacity > isize::MAX as usize || (output.is_null() && capacity != 0) {
            return Err(ARGUMENT);
        }
        // SAFETY: caller owns accessible bytes; input checks null and length.
        let password = unsafe { input(password, password_len)? };
        let password = fogvault::password_utf8_bytes(password).map_err(|_| INVALID_INPUT)?;
        if password.len() > capacity {
            return Err(BUFFER_TOO_SMALL);
        }
        if !password.is_empty() {
            // SAFETY: admitted complete capacity and disjoint accessible buffers.
            unsafe { std::ptr::copy_nonoverlapping(password.as_ptr(), output, password.len()) };
        }
        // SAFETY: caller supplies one writable usize. Publish only complete bytes.
        unsafe { written.write(password.len()) };
        Ok(())
    })
}

/// # Safety
/// Input buffers must satisfy the header's pointer/lifetime contract; handle_out
/// is writable/aligned for one u64. No buffer may race another call.
#[no_mangle]
pub unsafe extern "C" fn fv_probe_create(
    password: *const u8,
    password_len: usize,
    payload: *const u8,
    payload_len: usize,
    handle_out: *mut u64,
) -> i32 {
    boundary(|| {
        if handle_out.is_null() {
            return Err(ARGUMENT);
        }
        // SAFETY: the caller provides a writable aligned output; clear on failure.
        unsafe { handle_out.write(0) };
        // SAFETY: inputs follow the ABI caller contract and are checked for null/size.
        let probe = Probe::create(unsafe { input(password, password_len)? }, unsafe {
            input(payload, payload_len)?
        })
        .map_err(|_| FAILURE)?;
        let mut registry = registry().lock().map_err(|_| FAILURE)?;
        let handle = registry.next;
        registry.next = handle.checked_add(1).ok_or(FAILURE)?;
        registry.entries.insert(handle, probe);
        // SAFETY: output pointer validity checked by caller contract above.
        unsafe { handle_out.write(handle) };
        Ok(())
    })
}

/// # Safety
/// Password follows the header's input contract; token_out is writable for exactly
/// 16 bytes. It is cleared before any unlock attempt, including failure.
#[no_mangle]
pub unsafe extern "C" fn fv_probe_unlock(
    handle: u64,
    password: *const u8,
    password_len: usize,
    token_out: *mut u8,
) -> i32 {
    boundary(|| {
        if token_out.is_null() {
            return Err(ARGUMENT);
        }
        // SAFETY: output is writable for 16 bytes by the caller contract.
        unsafe { token_out.write_bytes(0, 16) };
        // SAFETY: input satisfies the caller contract; null/size are checked.
        let password = unsafe { input(password, password_len)? };
        let mut registry = registry().lock().map_err(|_| FAILURE)?;
        let token = registry
            .entries
            .get_mut(&handle)
            .ok_or(INVALID_HANDLE)?
            .unlock(password)?;
        // SAFETY: Rust token is separate from the caller-owned 16-byte output.
        unsafe { std::ptr::copy_nonoverlapping(token.as_ptr(), token_out, 16) };
        Ok(())
    })
}

/// # Safety
/// Token points to 16 readable bytes; output is writable for capacity bytes;
/// written is aligned/writable for usize. Buffers must not race other calls.
#[no_mangle]
pub unsafe extern "C" fn fv_probe_read(
    handle: u64,
    token: *const u8,
    token_len: usize,
    output: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    boundary(|| {
        if written.is_null() {
            return Err(ARGUMENT);
        }
        // SAFETY: caller supplies one writable usize.
        unsafe { written.write(0) };
        if token_len != 16 || capacity > isize::MAX as usize || (output.is_null() && capacity != 0)
        {
            return Err(ARGUMENT);
        }
        // SAFETY: input contract plus exact token_len admission.
        let token: [u8; 16] = unsafe { input(token, token_len)? }
            .try_into()
            .map_err(|_| ARGUMENT)?;
        let mut registry = registry().lock().map_err(|_| FAILURE)?;
        let record = registry
            .entries
            .get_mut(&handle)
            .ok_or(INVALID_HANDLE)?
            .read(&token)?;
        if record.len() > capacity {
            return Err(BUFFER_TOO_SMALL);
        }
        if !record.is_empty() {
            // SAFETY: admitted capacity covers the complete record; disjoint owners.
            unsafe { std::ptr::copy_nonoverlapping(record.as_ptr(), output, record.len()) };
        }
        // SAFETY: output length is published only after complete successful copy.
        unsafe { written.write(record.len()) };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn fv_probe_lock(handle: u64) -> i32 {
    boundary(|| {
        registry()
            .lock()
            .map_err(|_| FAILURE)?
            .entries
            .get_mut(&handle)
            .ok_or(INVALID_HANDLE)?
            .engine
            .lock();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn fv_probe_release(handle: u64) -> i32 {
    boundary(|| {
        registry()
            .lock()
            .map_err(|_| FAILURE)?
            .entries
            .remove(&handle)
            .ok_or(INVALID_HANDLE)?;
        Ok(())
    })
}

/// Experiment-only fault injection. Not a production API.
#[no_mangle]
pub extern "C" fn fv_probe_tamper_record(handle: u64) -> i32 {
    boundary(|| {
        let mut registry = registry().lock().map_err(|_| FAILURE)?;
        let probe = registry.entries.get_mut(&handle).ok_or(INVALID_HANDLE)?;
        *probe.envelope.last_mut().ok_or(INTEGRITY)? ^= 1;
        Ok(())
    })
}
