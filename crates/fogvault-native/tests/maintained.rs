use fogvault::{
    KeyProvider, ProtectiveSource, ProviderCapabilityKind, ProviderContext, ProviderError,
    ProviderIdentity, ProviderResult,
};
use fogvault_native::{
    AccessAdmission, AccessOptions, AccessPath, AccessProfile, Error, Host, KdfPolicy, KeyEffect,
    Limits,
};
use zeroize::Zeroizing;

struct NoProvider;
impl KeyProvider for NoProvider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::RawSecret
    }
    fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        Err(ProviderError::Unsupported)
    }
    fn unwrap_seed(
        &mut self,
        _: &ProviderContext,
        _: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        Err(ProviderError::Unsupported)
    }
}
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 128,
        max_records: 16,
    }
}
fn options() -> AccessOptions {
    AccessOptions {
        admission: AccessAdmission {
            allowed_profiles: vec![AccessProfile::Portable],
            providers: vec![],
            max_device_slots: 0,
            max_provider_blob_bytes: 0,
            max_descriptor_bytes: 276,
        },
        profile: AccessProfile::Portable,
        devices: vec![],
        recovery: true,
    }
}

#[test]
fn maintained_native_public_api_persists_and_preserves_password_changes() {
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let host = Host::create_new(&ns).unwrap();
    let mut vault = host
        .create(&path, b"SYNTHETIC-first", limits(), KdfPolicy::baseline())
        .unwrap();
    let token = vault.unlock(b"SYNTHETIC-first").unwrap();
    vault
        .save(&token, [1; 16], None, b"label", b"payload", [2; 16])
        .unwrap();
    let receipt = vault
        .change_password(&token, b"SYNTHETIC-first", b"SYNTHETIC-second", [3; 16])
        .unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::Preserved);
    vault.lock();
    drop(vault);
    let mut reopened = Host::open(&ns)
        .unwrap()
        .open_vault(&path, limits(), KdfPolicy::baseline())
        .unwrap();
    assert!(reopened.unlock(b"SYNTHETIC-first").is_err());
    let token = reopened.unlock(b"SYNTHETIC-second").unwrap();
    assert_eq!(
        reopened.read(&token, [1; 16]).unwrap().payload.as_slice(),
        b"payload"
    );
}

#[test]
fn maintained_native_recovery_replacement_reencrypts_all_records_and_reopens() {
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let options = options();
    let host = Host::create_new(&ns).unwrap();
    let (mut vault, old_key) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-old",
            limits(),
            KdfPolicy::baseline(),
            &options,
            &mut NoProvider,
        )
        .unwrap();
    let old_key = old_key.unwrap();
    let token = vault
        .unlock_access(AccessPath::Password(b"SYNTHETIC-old"), &mut NoProvider)
        .unwrap();
    for n in 1..=4 {
        vault
            .save(&token, [n; 16], None, &[n], &[n; 32], [n; 16])
            .unwrap();
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    let old_records: Vec<Vec<u8>> = db
        .prepare("SELECT envelope FROM records ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(db);
    vault.lock();
    vault.recover(&old_key).unwrap();
    assert!(vault.current_session().is_err());
    let (mut replacement, new_key) = vault
        .prepare_recovery_replacement(
            &old_key,
            b"SYNTHETIC-new",
            &options,
            &mut NoProvider,
            [9; 16],
        )
        .unwrap();
    let receipt = vault.commit_protection(&mut replacement).unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::FreshRootAndContentKeys);
    for n in 1..=4 {
        assert_eq!(
            vault
                .read(&receipt.session, [n; 16])
                .unwrap()
                .payload
                .as_slice(),
            &[n; 32]
        );
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    let new_records: Vec<Vec<u8>> = db
        .prepare("SELECT envelope FROM records ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(old_records.len(), new_records.len());
    for (old, new) in old_records.iter().zip(new_records.iter()) {
        assert_ne!(old, new);
    }
    drop(db);
    drop(vault);
    let mut reopened = host
        .open_with_access(&path, limits(), KdfPolicy::baseline(), options.admission)
        .unwrap();
    assert!(reopened.recover(&old_key).is_err());
    reopened.recover(&new_key.unwrap()).unwrap();
    assert!(matches!(reopened.current_session(), Err(Error::Locked)));
    reopened.lock();
    let token = reopened
        .unlock_access(AccessPath::Password(b"SYNTHETIC-new"), &mut NoProvider)
        .unwrap();
    assert_eq!(
        reopened.read(&token, [4; 16]).unwrap().metadata.as_slice(),
        &[4]
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn maintained_native_protective_unknown_restarts_only_the_exact_target() {
    use fogvault_native::{CommitFault, DiagnosticHost};
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let options = options();
    let host = DiagnosticHost::create_new(&ns).unwrap();
    let (mut vault, old_key) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-old",
            limits(),
            KdfPolicy::baseline(),
            options.admission.clone(),
            options.profile,
            &options.devices,
            true,
            &mut NoProvider,
        )
        .unwrap();
    let old_key = old_key.unwrap();
    let token = vault
        .unlock_access(AccessPath::Password(b"SYNTHETIC-old"), &mut NoProvider)
        .unwrap();
    for n in 1..=3 {
        vault
            .save(&token, [n; 16], None, &[], &[n; 16], [n; 16])
            .unwrap();
    }
    vault.lock();
    vault.recover_access(&old_key).unwrap();
    let (mut replacement, _new_key) = vault
        .prepare_recovery_replacement(
            &old_key,
            b"SYNTHETIC-new",
            options.profile,
            &[],
            true,
            &mut NoProvider,
            options.admission.clone(),
            [8; 16],
        )
        .unwrap();
    let ticket = replacement.ticket();
    assert!(
        matches!(vault.commit_protection_with_fault(&mut replacement,CommitFault::AfterCommit),Err(Error::OutcomeUnknown{request_id}) if request_id==[8;16])
    );
    assert!(matches!(
        vault.abandon_protection(&ticket),
        Err(Error::OutcomeUnknown { .. })
    ));
    drop(replacement);
    drop(vault);
    let host = Host::open(&ns).unwrap();
    let mut reopened = host
        .open_with_access(
            &path,
            limits(),
            KdfPolicy::baseline(),
            options.admission.clone(),
        )
        .unwrap();
    let mut resumed = reopened
        .resume_protection(
            &ticket,
            ProtectiveSource::Recovery(&old_key),
            Some(options.admission.clone()),
            AccessPath::Password(b"SYNTHETIC-new"),
            options.admission,
            &mut NoProvider,
        )
        .unwrap();
    assert!(!reopened.is_unlocked());
    assert!(reopened.current_session().is_err());
    let receipt = reopened.commit_protection(&mut resumed).unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::FreshRootAndContentKeys);
    assert_eq!(
        reopened
            .read(&receipt.session, [3; 16])
            .unwrap()
            .payload
            .as_slice(),
        &[3; 16]
    );
}

#[cfg(feature = "diagnostics")]
#[test]
fn maintained_native_pending_protective_retry_rejects_tampered_stage_without_publishing() {
    use fogvault_native::{CommitFault, DiagnosticHost};
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let options = options();
    let host = DiagnosticHost::create_new(&ns).unwrap();
    let (mut vault, old_key) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-old",
            limits(),
            KdfPolicy::baseline(),
            options.admission.clone(),
            options.profile,
            &[],
            true,
            &mut NoProvider,
        )
        .unwrap();
    let old_key = old_key.unwrap();
    let token = vault
        .unlock_access(AccessPath::Password(b"SYNTHETIC-old"), &mut NoProvider)
        .unwrap();
    vault
        .save(
            &token,
            [1; 16],
            None,
            b"metadata",
            b"selected body",
            [1; 16],
        )
        .unwrap();
    vault.lock();
    vault.recover_access(&old_key).unwrap();
    let (mut replacement, _) = vault
        .prepare_recovery_replacement(
            &old_key,
            b"SYNTHETIC-new",
            options.profile,
            &[],
            true,
            &mut NoProvider,
            options.admission,
            [7; 16],
        )
        .unwrap();
    assert!(matches!(
        vault.commit_protection_with_fault(&mut replacement, CommitFault::BeforeCommit),
        Err(Error::OutcomeUnknown { .. })
    ));
    let before = std::fs::read(&path).unwrap();
    let stage = std::fs::read_dir(&ns)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("protective-")
                && p.extension().is_some_and(|x| x == "sqlite")
        })
        .unwrap();
    let db = rusqlite::Connection::open(&stage).unwrap();
    let original: Vec<u8> = db
        .query_row(
            "SELECT envelope FROM target_records WHERE id=?1",
            [[1u8; 16].as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    db.execute(
        "UPDATE target_records SET envelope=?1 WHERE id=?2",
        rusqlite::params![changed, [1u8; 16].as_slice()],
    )
    .unwrap();
    assert!(
        matches!(vault.commit_protection(&mut replacement),Err(Error::OutcomeUnknown{request_id}) if request_id==[7;16])
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(vault
        .registered_control_state()
        .unwrap()
        .pending()
        .unwrap()
        .submission()
        .is_some());
    db.execute(
        "UPDATE target_records SET envelope=?1 WHERE id=?2",
        rusqlite::params![original, [1u8; 16].as_slice()],
    )
    .unwrap();
    drop(db);
    let receipt = vault.commit_protection(&mut replacement).unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::FreshRootAndContentKeys);
    assert_eq!(
        vault
            .read(&receipt.session, [1; 16])
            .unwrap()
            .payload
            .as_slice(),
        b"selected body"
    );
}

#[test]
fn maintained_native_protective_preparation_is_revoked_by_lock() {
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let options = options();
    let host = Host::create_new(&ns).unwrap();
    let (mut vault, key) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-old",
            limits(),
            KdfPolicy::baseline(),
            &options,
            &mut NoProvider,
        )
        .unwrap();
    let key = key.unwrap();
    vault.recover(&key).unwrap();
    let (mut draft, _) = vault
        .prepare_recovery_replacement(&key, b"SYNTHETIC-new", &options, &mut NoProvider, [4; 16])
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    vault.lock();
    assert!(matches!(
        vault.commit_protection(&mut draft),
        Err(Error::StaleSession) | Err(Error::Locked)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut reopened = host
        .open_with_access(&path, limits(), KdfPolicy::baseline(), options.admission)
        .unwrap();
    reopened
        .unlock_access(AccessPath::Password(b"SYNTHETIC-old"), &mut NoProvider)
        .unwrap();
}

#[test]
fn maintained_native_device_replacement_removes_old_device_and_reencrypts_all_records() {
    use std::collections::BTreeMap;
    struct Provider(BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>);
    impl KeyProvider for Provider {
        fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
            ProviderCapabilityKind::NonExportableOperation
        }
        fn wrap_seed(&mut self, c: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
            let bytes = c.authenticated_bytes();
            self.0.insert(bytes.clone(), Zeroizing::new(*seed));
            Ok(bytes)
        }
        fn unwrap_seed(
            &mut self,
            c: &ProviderContext,
            bytes: &[u8],
        ) -> ProviderResult<Zeroizing<[u8; 32]>> {
            if c.authenticated_bytes() != bytes {
                return Err(ProviderError::IdentityChanged);
            }
            self.0
                .get(bytes)
                .map(|key| Zeroizing::new(**key))
                .ok_or(ProviderError::Unavailable)
        }
    }
    // This is a synthetic operation provider, not physical device qualification.
    let old_device = ProviderIdentity {
        provider_id: [1; 16],
        key_id: [2; 16],
        device_bound: true,
        nonexportable: true,
    };
    let new_device = ProviderIdentity {
        key_id: [3; 16],
        ..old_device
    };
    let provider_bytes = ProviderContext {
        vault_id: [0; 16],
        root_epoch: 0,
        slot_id: [0; 16],
        slot_revision: 1,
        identity: old_device,
    }
    .authenticated_bytes()
    .len();
    let options = AccessOptions {
        admission: AccessAdmission {
            allowed_profiles: vec![AccessProfile::PasswordOrDevice],
            providers: vec![old_device, new_device],
            max_device_slots: 1,
            max_provider_blob_bytes: provider_bytes,
            max_descriptor_bytes: 108 + 72 + 64 + provider_bytes + 72 + 96,
        },
        profile: AccessProfile::PasswordOrDevice,
        devices: vec![old_device],
        recovery: true,
    };
    let temp = tempfile::tempdir().unwrap();
    let ns = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let host = Host::create_new(&ns).unwrap();
    let mut provider = Provider(BTreeMap::new());
    let (mut vault, _) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-password",
            limits(),
            KdfPolicy::baseline(),
            &options,
            &mut provider,
        )
        .unwrap();
    let token = vault
        .unlock_access(AccessPath::Password(b"SYNTHETIC-password"), &mut provider)
        .unwrap();
    for n in 1..=3 {
        vault
            .save(&token, [n; 16], None, &[], &[n; 8], [n; 16])
            .unwrap();
    }
    let removed = vault.access_info().unwrap().device_slots[0].0;
    let target = AccessOptions {
        devices: vec![new_device],
        ..options
    };
    let (mut draft, _) = vault
        .prepare_device_replacement(
            &token,
            ProtectiveSource::Password(b"SYNTHETIC-password"),
            &[removed],
            b"SYNTHETIC-password",
            &target,
            &mut provider,
            [9; 16],
        )
        .unwrap();
    let receipt = vault.commit_protection(&mut draft).unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::FreshRootAndContentKeys);
    assert_eq!(vault.access_info().unwrap().device_slots.len(), 1);
    assert_eq!(vault.access_info().unwrap().device_slots[0].1, new_device);
    for n in 1..=3 {
        assert_eq!(
            vault
                .read(&receipt.session, [n; 16])
                .unwrap()
                .payload
                .as_slice(),
            &[n; 8]
        );
    }
}

#[test]
fn maintained_native_and_credentials_upgrade_requires_device_and_preserves_content() {
    use std::collections::BTreeMap;
    struct Provider(BTreeMap<Vec<u8>, Zeroizing<[u8; 32]>>);
    impl KeyProvider for Provider {
        fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
            ProviderCapabilityKind::NonExportableOperation
        }
        fn wrap_seed(
            &mut self,
            context: &ProviderContext,
            seed: &[u8; 32],
        ) -> ProviderResult<Vec<u8>> {
            let bytes = context.authenticated_bytes();
            self.0.insert(bytes.clone(), Zeroizing::new(*seed));
            Ok(bytes)
        }
        fn unwrap_seed(
            &mut self,
            context: &ProviderContext,
            bytes: &[u8],
        ) -> ProviderResult<Zeroizing<[u8; 32]>> {
            if context.authenticated_bytes() != bytes {
                return Err(ProviderError::IdentityChanged);
            }
            self.0
                .get(bytes)
                .map(|seed| Zeroizing::new(**seed))
                .ok_or(ProviderError::Unavailable)
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let namespace = temp.path().join("control");
    let path = temp.path().join("vault.sqlite");
    let device = ProviderIdentity {
        provider_id: [11; 16],
        key_id: [12; 16],
        device_bound: true,
        nonexportable: true,
    };
    let provider_bytes = ProviderContext {
        vault_id: [0; 16],
        root_epoch: 0,
        slot_id: [0; 16],
        slot_revision: 1,
        identity: device,
    }
    .authenticated_bytes()
    .len();
    let options = AccessOptions {
        profile: AccessProfile::PasswordAndDevice,
        devices: vec![device],
        recovery: false,
        admission: AccessAdmission {
            allowed_profiles: vec![AccessProfile::PasswordAndDevice],
            providers: vec![device],
            max_device_slots: 1,
            max_provider_blob_bytes: provider_bytes,
            max_descriptor_bytes: 180 + 64 + provider_bytes + 112,
        },
    };
    let base = fogvault::KdfProfile::baseline();
    let target = fogvault::KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
    let policy = KdfPolicy::new(vec![base, target]).unwrap();
    let host = Host::create_new(&namespace).unwrap();
    let mut provider = Provider(BTreeMap::new());
    let (mut vault, _) = host
        .create_with_access(
            &path,
            b"SYNTHETIC-old",
            limits(),
            policy.clone(),
            &options,
            &mut provider,
        )
        .unwrap();
    let slot = vault.access_info().unwrap().device_slots[0].0;
    let token = vault
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-old"),
            },
            &mut provider,
        )
        .unwrap();
    vault
        .save(
            &token,
            [31; 16],
            None,
            b"label",
            b"SYNTHETIC strict content",
            [32; 16],
        )
        .unwrap();
    assert!(vault
        .change_credentials_with_access(
            &token,
            AccessPath::Password(b"SYNTHETIC-old"),
            b"SYNTHETIC-new",
            target,
            &mut provider,
            [33; 16]
        )
        .is_err());
    let receipt = vault
        .change_credentials_with_access(
            &token,
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-old"),
            },
            b"SYNTHETIC-new",
            target,
            &mut provider,
            [33; 16],
        )
        .unwrap();
    assert_eq!(receipt.key_effect, KeyEffect::Preserved);
    vault.lock();
    drop(vault);
    let mut reopened = host
        .open_with_access(&path, limits(), policy, options.admission)
        .unwrap();
    assert!(reopened
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-old")
            },
            &mut provider
        )
        .is_err());
    let token = reopened
        .unlock_access(
            AccessPath::Device {
                slot_id: slot,
                password: Some(b"SYNTHETIC-new"),
            },
            &mut provider,
        )
        .unwrap();
    assert_eq!(
        reopened.read(&token, [31; 16]).unwrap().payload.as_slice(),
        b"SYNTHETIC strict content"
    );
}
