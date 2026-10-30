//! Shared logical revocation and honest cleanup accounting. No secrets live here.
use crate::{Error, Result};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Generation {
    revoked: AtomicBool,
    keys: AtomicBool,
    work: AtomicUsize,
}
struct State {
    number: u64,
    current: Arc<Generation>,
}
#[derive(Clone)]
pub(super) struct PublicationAuthority(Arc<Mutex<State>>);
impl PublicationAuthority {
    pub(super) fn new(keys: bool) -> Self {
        Self(Arc::new(Mutex::new(State {
            number: 1,
            current: Arc::new(Generation {
                revoked: AtomicBool::new(!keys),
                keys: AtomicBool::new(keys),
                work: AtomicUsize::new(0),
            }),
        })))
    }
    pub(super) fn handle(&self) -> RevocationHandle {
        RevocationHandle(self.clone())
    }
    pub(super) fn is_revoked(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .revoked
            .load(Ordering::SeqCst)
    }
    pub(super) fn begin_attempt(&self) -> Result<WorkGuard> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let number = state.number.checked_add(1).ok_or(Error::ResourceLimit)?;
        state.current.revoked.store(true, Ordering::SeqCst);
        state.number = number;
        state.current = Arc::new(Generation {
            revoked: AtomicBool::new(false),
            keys: AtomicBool::new(false),
            work: AtomicUsize::new(0),
        });
        WorkGuard::new(state.current.clone())
    }
    pub(super) fn work(&self) -> Result<WorkGuard> {
        let current = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .clone();
        WorkGuard::new(current)
    }
    pub(super) fn retain_keys(&self, work: &WorkGuard) -> Result<()> {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if !Arc::ptr_eq(&state.current, &work.generation) {
            return Err(Error::StaleSession);
        }
        work.check()?;
        state.current.keys.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub(super) fn clear_keys(&self) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current
            .keys
            .store(false, Ordering::SeqCst);
    }
}

/// A clone carries revocation authority only, never unlock/read authority.
#[derive(Clone)]
pub struct RevocationHandle(PublicationAuthority);
impl RevocationHandle {
    /// Revoke admission/publication immediately, without waiting for providers.
    /// The owning Engine still clears its keys on lock/drop or failed completion.
    pub fn revoke(&self) -> RevocationReceipt {
        let state = self.0 .0.lock().unwrap_or_else(|p| p.into_inner());
        state.current.revoked.store(true, Ordering::SeqCst);
        RevocationReceipt {
            generation: state.current.clone(),
            number: state.number,
        }
    }
}
impl std::fmt::Debug for RevocationHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationHandle([revocation only])")
    }
}

/// A receipt is tied to the revoked generation; a new unlock cannot reset it.
#[derive(Clone)]
pub struct RevocationReceipt {
    generation: Arc<Generation>,
    number: u64,
}
impl RevocationReceipt {
    pub fn generation(&self) -> u64 {
        self.number
    }
    pub fn logically_revoked(&self) -> bool {
        self.generation.revoked.load(Ordering::SeqCst)
    }
    pub fn outstanding_work(&self) -> usize {
        self.generation.work.load(Ordering::SeqCst)
    }
    pub fn engine_keys_pending(&self) -> bool {
        self.generation.keys.load(Ordering::SeqCst)
    }
    pub fn cleanup_complete(&self) -> bool {
        !self.engine_keys_pending() && self.outstanding_work() == 0
    }
}
impl std::fmt::Debug for RevocationReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationReceipt")
            .field("generation", &self.number)
            .field("logically_revoked", &self.logically_revoked())
            .field("outstanding_work", &self.outstanding_work())
            .field("cleanup_complete", &self.cleanup_complete())
            .finish()
    }
}

/// Keep this guard across external work and check immediately before accepting
/// its result, submitting a commit, or publishing plaintext/live authority.
/// Dropping it accounts for this work's cleanup, not caller-retained plaintext.
pub struct WorkGuard {
    generation: Arc<Generation>,
}
impl WorkGuard {
    fn new(generation: Arc<Generation>) -> Result<Self> {
        generation
            .work
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| Error::ResourceLimit)?;
        let guard = Self { generation };
        guard.check()?;
        Ok(guard)
    }
    pub fn check(&self) -> Result<()> {
        if self.generation.revoked.load(Ordering::SeqCst) {
            Err(Error::StaleSession)
        } else {
            Ok(())
        }
    }
}
impl Drop for WorkGuard {
    fn drop(&mut self) {
        self.generation.work.fetch_sub(1, Ordering::SeqCst);
    }
}
impl std::fmt::Debug for WorkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkGuard([publication fence])")
    }
}
