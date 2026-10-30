use fogvault::{Engine, Limits};
use std::sync::mpsc;

fn created() -> Engine {
    let mut engine = Engine::create(
        b"synthetic-revocation-password",
        Limits {
            max_payload_bytes: 0,
            max_metadata_bytes: 0,
            max_records: 1,
        },
    )
    .unwrap();
    engine.activate_created().unwrap();
    engine
}

#[test]
fn portable_revocation_precedes_delayed_work_and_cleanup() {
    let mut engine = created();
    let session = engine.current_session().unwrap();
    let work = engine.begin_host_work().unwrap();
    let revoke = engine.revocation_handle();
    let (send, wait) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        wait.recv().unwrap();
        // Simulates a provider returning valid bytes only after logical lock.
        assert!(work.check().is_err());
    });
    let receipt = revoke.revoke();
    assert!(receipt.logically_revoked());
    assert!(receipt.engine_keys_pending());
    assert_eq!(receipt.outstanding_work(), 1);
    assert!(!receipt.cleanup_complete());
    assert!(engine.check_session(&session).is_err());
    assert!(!engine.is_unlocked());
    engine.lock();
    assert!(!receipt.engine_keys_pending());
    assert!(!receipt.cleanup_complete());
    send.send(()).unwrap();
    worker.join().unwrap();
    assert!(receipt.cleanup_complete());
}

#[test]
fn portable_pending_cleanup_is_generation_scoped() {
    let mut engine = created();
    let pending = engine.begin_host_work().unwrap();
    let receipt = engine.lock_with_receipt();
    assert!(!receipt.cleanup_complete());
    // An unresolved host task may remain indefinitely, but never retains authority.
    assert!(pending.check().is_err());
    engine
        .begin_unlock(b"synthetic-revocation-password")
        .unwrap();
    assert!(pending.check().is_err());
    drop(pending);
    assert!(receipt.cleanup_complete());
    // New candidate keys do not make an older receipt pending again.
    let newer = engine.revocation_handle().revoke();
    assert!(newer.engine_keys_pending());
    assert!(newer.generation() > receipt.generation());
    assert!(receipt.cleanup_complete());
    drop(engine);
    assert!(newer.cleanup_complete());
}
