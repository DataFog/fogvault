//! Shared, finite host work admission. Values come from trusted host policy;
//! this accounting does not measure RSS or account for caller/foreign copies.
use crate::{Error, Result};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkUsage {
    pub reserved_bytes: usize,
    pub operations: usize,
}
#[derive(Debug)]
struct Inner {
    maximum_bytes: usize,
    maximum_operations: usize,
    usage: Mutex<WorkUsage>,
}
#[derive(Clone, Debug)]
pub struct WorkBudget(Arc<Inner>);
impl PartialEq for WorkBudget {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for WorkBudget {}
impl WorkBudget {
    /// No default production values. Zero capacity is invalid. Admission is
    /// immediate: no queue retains input buffers while waiting for capacity.
    pub fn new(maximum_bytes: usize, maximum_operations: usize) -> Result<Self> {
        if maximum_bytes == 0 || maximum_operations == 0 {
            return Err(Error::ResourceLimit);
        }
        Ok(Self(Arc::new(Inner {
            maximum_bytes,
            maximum_operations,
            usage: Mutex::new(WorkUsage::default()),
        })))
    }
    pub fn reserve(&self, bytes: usize) -> Result<WorkReservation> {
        if bytes == 0 {
            return Err(Error::ResourceLimit);
        }
        let mut usage = self.0.usage.lock().map_err(|_| Error::ResourceLimit)?;
        let next_bytes = usage
            .reserved_bytes
            .checked_add(bytes)
            .ok_or(Error::ResourceLimit)?;
        let next_operations = usage
            .operations
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        if next_bytes > self.0.maximum_bytes || next_operations > self.0.maximum_operations {
            return Err(Error::ResourceLimit);
        }
        usage.reserved_bytes = next_bytes;
        usage.operations = next_operations;
        Ok(WorkReservation {
            budget: self.clone(),
            bytes,
        })
    }
    pub fn usage(&self) -> Result<WorkUsage> {
        self.0
            .usage
            .lock()
            .map(|usage| *usage)
            .map_err(|_| Error::ResourceLimit)
    }
}

#[derive(Debug)]
pub struct WorkReservation {
    budget: WorkBudget,
    bytes: usize,
}
impl Drop for WorkReservation {
    fn drop(&mut self) {
        // No external code runs under this lock. Even after poisoning, release
        // this reservation rather than panicking during secret cleanup.
        let mut usage = self
            .budget
            .0
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        usage.reserved_bytes -= self.bytes;
        usage.operations -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_work_budget_refuses_aggregate_work_and_releases_on_unwind() {
        // Deliberately tiny accounting fixtures, not proposed host budgets.
        let budget = WorkBudget::new(10, 2).unwrap();
        let another_vault = budget.clone();
        let first = budget.reserve(6).unwrap();
        assert!(another_vault.reserve(5).is_err());
        let second = another_vault.reserve(4).unwrap();
        assert!(budget.reserve(1).is_err());
        assert_eq!(
            budget.usage().unwrap(),
            WorkUsage {
                reserved_bytes: 10,
                operations: 2
            }
        );
        drop(first);
        drop(second);
        let _ = std::panic::catch_unwind({
            let budget = budget.clone();
            move || {
                let _reservation = budget.reserve(10).unwrap();
                panic!("synthetic caller interruption");
            }
        });
        assert_eq!(budget.usage().unwrap(), WorkUsage::default());
        assert!(WorkBudget::new(0, 1).is_err());
        assert!(WorkBudget::new(1, 0).is_err());
    }
    #[test]
    fn shared_work_budget_is_one_controller_across_threads() {
        let budget = WorkBudget::new(1, 1).unwrap();
        let held = budget.reserve(1).unwrap();
        let other = budget.clone();
        assert!(std::thread::spawn(move || other.reserve(1).is_err())
            .join()
            .unwrap());
        drop(held);
        assert!(budget.reserve(1).is_ok());
    }
}
