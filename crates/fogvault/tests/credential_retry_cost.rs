//! A latest retry must not expose a fast new-password verifier to old-root holders.
//! Measure actual allocations from the public API; do not add production hooks.
use fogvault::{Engine, Error, KdfProfile, Limits};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Measured;
static TRACK: AtomicBool = AtomicBool::new(false);
static MAXIMUM: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Measured {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            MAXIMUM.fetch_max(l.size(), Ordering::Relaxed);
        }
        // SAFETY: the allocator forwards the original layout unchanged.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: the allocator forwards the matching pointer and layout.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            MAXIMUM.fetch_max(n, Ordering::Relaxed);
        }
        // SAFETY: the allocator forwards the original allocation and new size.
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOCATOR: Measured = Measured;
fn measure<T>(work: impl FnOnce() -> T) -> (T, usize) {
    MAXIMUM.store(0, Ordering::SeqCst);
    TRACK.store(true, Ordering::SeqCst);
    let result = work();
    TRACK.store(false, Ordering::SeqCst);
    (result, MAXIMUM.load(Ordering::SeqCst))
}
#[test]
fn credential_retries_pay_the_current_kdf_cost() {
    let mut engine = Engine::create(
        b"old password",
        Limits {
            max_payload_bytes: 1,
            max_metadata_bytes: 0,
            max_records: 1,
        },
    )
    .unwrap();
    engine.activate_created().unwrap();
    let draft = engine
        .draft_password_change(b"old password", b"new password", [1; 16])
        .unwrap();
    let plan = engine.stage_credential_change(&draft).unwrap();
    engine
        .confirm_credential_commit(&plan.descriptor_bytes, &plan.head_bytes)
        .unwrap();
    let original = (
        engine.descriptor_bytes().to_vec(),
        engine.head_bytes().to_vec(),
        engine.current_session().unwrap(),
    );
    let minimum_work = KdfProfile::baseline().memory_kib() as usize * 1024;
    let (wrong, allocated) =
        measure(|| engine.draft_password_change(b"old password", b"wrong guess", [1; 16]));
    assert!(matches!(wrong, Err(Error::OperationIdReuse)));
    assert!(
        allocated >= minimum_work,
        "wrong new-password retry skipped the current KDF work area"
    );
    let (same, allocated) =
        measure(|| engine.draft_password_change(b"old password", b"new password", [1; 16]));
    assert!(
        allocated >= minimum_work,
        "same new-password retry skipped the current KDF work area"
    );
    let replay = engine.stage_credential_change(&same.unwrap()).unwrap();
    assert!(replay.replay);
    assert_eq!(engine.descriptor_bytes(), original.0);
    assert_eq!(engine.head_bytes(), original.1);
    assert_eq!(engine.current_session().unwrap(), original.2);
}
