use fogvault::{Engine, Error, KdfPolicy, KdfProfile, Limits, WorkBudget, WorkUsage};

#[test]
fn shared_kdf_admission_precedes_work_across_create_and_unlock() {
    let workspace = KdfProfile::baseline().memory_kib() as usize * 1024;
    // Exactly one current baseline work area is a test fixture, not a
    // recommended whole-host allowance (foreign/caller memory is excluded).
    let budget = WorkBudget::new(workspace, 1).unwrap();
    let policy = KdfPolicy::baseline().with_work_budget(budget.clone());
    let limits = Limits {
        max_payload_bytes: 64,
        max_metadata_bytes: 16,
        max_records: 1,
    };
    let held_by_another_vault = budget.reserve(workspace).unwrap();
    assert!(matches!(
        Engine::create_with_kdf_policy(b"synthetic-budget", limits, policy.clone()),
        Err(Error::Crypto(_))
    ));
    assert_eq!(
        budget.usage().unwrap(),
        WorkUsage {
            reserved_bytes: workspace,
            operations: 1
        }
    );
    drop(held_by_another_vault);
    let mut first =
        Engine::create_with_kdf_policy(b"synthetic-budget", limits, policy.clone()).unwrap();
    let descriptor = first.descriptor_bytes().to_vec();
    first.activate_created().unwrap();
    assert_eq!(budget.usage().unwrap(), WorkUsage::default());
    let mut reopened = Engine::open_with_kdf_policy(&descriptor, limits, policy).unwrap();
    let held_by_another_vault = budget.reserve(workspace).unwrap();
    let error = reopened.begin_unlock(b"synthetic-budget").unwrap_err();
    assert_eq!(error.code(), "ResourceLimit");
    assert!(matches!(reopened.current_session(), Err(Error::Locked)));
    drop(held_by_another_vault);
    reopened.begin_unlock(b"synthetic-budget").unwrap();
    assert_eq!(budget.usage().unwrap(), WorkUsage::default());
    let too_small = WorkBudget::new(workspace - 1, 1).unwrap();
    let denied = KdfPolicy::baseline().with_work_budget(too_small.clone());
    let error = Engine::create_with_kdf_policy(b"synthetic-budget", limits, denied)
        .err()
        .unwrap();
    assert_eq!(error.code(), "ResourceLimit");
    assert_eq!(too_small.usage().unwrap(), WorkUsage::default());
}
