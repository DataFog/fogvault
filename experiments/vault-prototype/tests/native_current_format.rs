//! Current default creation, descriptor-aware bounds and exact published consumer.
//! Synthetic local fixtures; no physical host/provider qualification is implied.
#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use datafog_core::workspace::{Workspace, MAX_BUNDLE_BYTES};
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, KdfPolicy, KdfProfile, KeyEffect, KeyProvider,
    ProviderCapabilityKind, ProviderContext, ProviderError, ProviderIdentity, ProviderResult,
};
use fogvault_disposable_prototype::{CommitFault, Error, Limits, NativeHost, Vault};
use rusqlite::Connection;
use std::path::Path;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"SYNTHETIC-current-native-password";
const REPLACEMENT: &[u8] = b"SYNTHETIC-current-native-password-replacement";
const ID: [u8; 16] = [0xb4; 16];

fn limits() -> Limits {
    Limits {
        max_payload_bytes: 4096,
        max_metadata_bytes: 64,
        max_records: 8,
    }
}
fn policy() -> KdfPolicy {
    let baseline = KdfProfile::baseline();
    KdfPolicy::new(vec![
        baseline,
        KdfProfile::argon2id(baseline.memory_kib(), baseline.passes() + 1).unwrap(),
    ])
    .unwrap()
}
fn descriptor(path: &Path) -> Vec<u8> {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT descriptor FROM vault_state WHERE id=1", [], |row| {
            row.get(0)
        })
        .unwrap()
}
fn assert_current(path: &Path, expected_epoch: u64) {
    let bytes = descriptor(path);
    assert_eq!(&bytes[..8], b"FGVP0003");
    assert_eq!(u16::from_be_bytes(bytes[8..10].try_into().unwrap()), 3);
    assert_eq!(u16::from_be_bytes(bytes[12..14].try_into().unwrap()), 3);
    assert_eq!(
        u64::from_be_bytes(bytes[30..38].try_into().unwrap()),
        expected_epoch
    );
}
fn content(path: &Path) -> Vec<Vec<u8>> {
    let connection = Connection::open(path).unwrap();
    let mut data = Vec::new();
    for sql in [
        "SELECT envelope FROM records ORDER BY id",
        "SELECT bytes FROM index_nodes ORDER BY hash",
    ] {
        data.extend(
            connection
                .prepare(sql)
                .unwrap()
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap()
                .map(|row| row.unwrap()),
        );
    }
    data
}

#[test]
fn native_current_format_maximum_record_survives_all_read_paths_and_reopen() {
    let scratch = tempfile::tempdir().unwrap();
    let host = NativeHost::create_new(scratch.path().join("protected-host")).unwrap();
    let path = scratch.path().join("current.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    assert_current(&path, 0);
    assert_eq!(descriptor(&path).len(), 180);
    let token = vault.unlock(PASSWORD).unwrap();
    let metadata = vec![0xa5; 64];
    let payload = vec![0x5a; 4096];
    let receipt = vault
        .save(&token, ID, None, &metadata, &payload, [0xb5; 16])
        .unwrap();
    let envelope = content(&path).remove(0);
    assert_eq!(envelope.len(), 4096 + 64 + 176);
    assert_eq!(&envelope[..8], b"FGVR0003");
    assert_eq!(u64::from_be_bytes(envelope[32..40].try_into().unwrap()), 0);
    let read = vault.read(&token, ID).unwrap();
    assert_eq!(read.metadata.as_slice(), metadata);
    assert_eq!(read.payload.as_slice(), payload);
    drop(read);
    let mut cursor = vault.begin_records(&token).unwrap();
    let page = vault.record_page(&token, &mut cursor, 1).unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.complete);
    vault.audit(&token).unwrap();
    vault.lock();
    assert!(vault.read(&token, ID).is_err());
    drop(vault);
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let read = vault.read(&token, ID).unwrap();
    assert_eq!(read.metadata.as_slice(), metadata);
    assert_eq!(read.payload.as_slice(), payload);
    assert_eq!(
        vault
            .registered_control_state()
            .unwrap()
            .accepted()
            .head_digest,
        receipt.head_digest
    );
}

#[test]
fn native_current_format_preserves_exact_beta3_bundle_and_head() {
    let scratch = tempfile::tempdir().unwrap();
    let host = NativeHost::create_new(scratch.path().join("protected-host")).unwrap();
    let path = scratch.path().join("beta3.sqlite");
    let namespace = [0xc1; 16];
    let mut workspace = Workspace::create(namespace, [0xc2; 16]).unwrap();
    let head = workspace.head().unwrap();
    let bytes = Zeroizing::new(workspace.export_bundle().unwrap());
    let mut metadata = namespace.to_vec();
    metadata.extend_from_slice(&head.revision.to_be_bytes());
    metadata.extend_from_slice(&head.commit_id);
    let limits = Limits {
        max_payload_bytes: MAX_BUNDLE_BYTES,
        max_metadata_bytes: metadata.len(),
        max_records: 1,
    };
    let mut vault = host.create(&path, PASSWORD, limits, policy()).unwrap();
    assert_current(&path, 0);
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, &metadata, &bytes, [0xc3; 16])
        .unwrap();
    workspace.close();
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits, policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    let record = vault.read(&token, ID).unwrap();
    assert_eq!(record.metadata.as_slice(), metadata);
    assert_eq!(record.payload.as_slice(), bytes.as_slice());
    let mut restored = Workspace::open_bundle(&record.payload).unwrap();
    assert_eq!(restored.namespace().unwrap(), namespace);
    assert_eq!(restored.head().unwrap(), head);
    restored.close();
    vault.lock();
    assert!(vault.read(&token, ID).is_err());
}

#[test]
fn native_current_format_password_and_kdf_maintenance_preserve_content() {
    let scratch = tempfile::tempdir().unwrap();
    let host = NativeHost::create_new(scratch.path().join("protected-host")).unwrap();
    let path = scratch.path().join("maintenance.sqlite");
    let mut vault = host.create(&path, PASSWORD, limits(), policy()).unwrap();
    let token = vault.unlock(PASSWORD).unwrap();
    vault
        .save(&token, ID, None, b"metadata", b"payload", [0xd1; 16])
        .unwrap();
    let before = content(&path);
    let changed = vault
        .change_password(&token, PASSWORD, REPLACEMENT, [0xd2; 16])
        .unwrap();
    assert_eq!(changed.key_effect(), KeyEffect::Preserved);
    assert_eq!(before, content(&path));
    assert_current(&path, 0);
    let baseline = KdfProfile::baseline();
    let target = KdfProfile::argon2id(baseline.memory_kib(), baseline.passes() + 1).unwrap();
    let upgraded = vault
        .upgrade_kdf(&changed.session, REPLACEMENT, target, [0xd3; 16])
        .unwrap();
    assert_eq!(upgraded.key_effect(), KeyEffect::Preserved);
    assert_eq!(before, content(&path));
    assert_current(&path, 0);
    vault.lock();
    drop(vault);
    let mut vault = host.open(&path, limits(), policy()).unwrap();
    assert!(vault.unlock(PASSWORD).is_err());
    let token = vault.unlock(REPLACEMENT).unwrap();
    assert_eq!(
        vault.read(&token, ID).unwrap().payload.as_slice(),
        b"payload"
    );
}

struct NoDevice;
impl KeyProvider for NoDevice {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        panic!("portable fixture called a provider")
    }
    fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        panic!("portable fixture called a provider")
    }
    fn unwrap_seed(
        &mut self,
        _: &ProviderContext,
        _: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        panic!("portable fixture called a provider")
    }
}

#[test]
fn native_current_format_refuses_legacy_enrollment_without_modifying_input() {
    for access_grammar in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let host = NativeHost::create_new(scratch.path().join("protected-host")).unwrap();
        let path = scratch.path().join("legacy.sqlite");
        let mut vault = if access_grammar {
            let (prepared, recovery) = Vault::diagnostic_prepare_access_creation(
                PASSWORD,
                limits(),
                policy(),
                AccessAdmission {
                    allowed_profiles: vec![AccessProfile::Portable],
                    providers: vec![],
                    max_descriptor_bytes: 180,
                    max_device_slots: 0,
                    max_provider_blob_bytes: 0,
                },
                AccessProfile::Portable,
                &[],
                false,
                &mut NoDevice,
            )
            .unwrap();
            assert!(recovery.is_none());
            prepared.publish(&path, CommitFault::None).unwrap()
        } else {
            Vault::diagnostic_create_with_kdf_policy(&path, PASSWORD, limits(), policy()).unwrap()
        };
        let token = if access_grammar {
            vault
                .unlock_access(fogvault::AccessPath::Password(PASSWORD), &mut NoDevice)
                .unwrap()
        } else {
            vault.unlock(PASSWORD).unwrap()
        };
        vault
            .save(
                &token,
                ID,
                None,
                b"old metadata",
                b"old payload",
                [0xe1; 16],
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            host.register_existing(&mut vault, &token),
            Err(Error::UnsupportedCapability)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(host.open(&path, limits(), policy()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            vault.read(&token, ID).unwrap().payload.as_slice(),
            b"old payload"
        );
    }
}

// Synthetic software operation provider. The declaration below is only a test
// capability: it establishes no hardware confinement or provider qualification.
struct SyntheticProvider;
impl KeyProvider for SyntheticProvider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        fogvault_disposable_prototype::crypto::seal(
            &[0xf4; 32],
            &context.authenticated_bytes(),
            seed,
        )
        .map_err(|_| ProviderError::Failure)
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        let bytes = fogvault_disposable_prototype::crypto::open(
            &[0xf4; 32],
            &context.authenticated_bytes(),
            wrapped,
        )
        .map_err(|_| ProviderError::InvalidResponse)?;
        Ok(Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::InvalidResponse)?,
        ))
    }
}

#[test]
fn native_current_format_all_access_profiles_reopen_maximum_records_at_epoch_zero() {
    for profile in [
        AccessProfile::Portable,
        AccessProfile::PasswordOrDevice,
        AccessProfile::PasswordAndDevice,
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let host = NativeHost::create_new(scratch.path().join("protected-host")).unwrap();
        let path = scratch.path().join("profile.sqlite");
        let identities = if profile == AccessProfile::Portable {
            vec![]
        } else {
            vec![ProviderIdentity {
                provider_id: [0xf1; 16],
                key_id: [0xf2; 16],
                device_bound: true,
                nonexportable: true,
            }]
        };
        // Exact encoded descriptor width from the fixed P3 slot grammar:
        // portable180; OR180+(slot64+provider72+wrap72); AND108+(64+72+112).
        let width = match profile {
            AccessProfile::Portable => 180,
            AccessProfile::PasswordOrDevice => 388,
            AccessProfile::PasswordAndDevice => 356,
        };
        let admission = AccessAdmission {
            allowed_profiles: vec![profile],
            providers: identities.clone(),
            max_descriptor_bytes: width,
            max_device_slots: identities.len(),
            max_provider_blob_bytes: if identities.is_empty() { 0 } else { 72 },
        };
        let mut provider = SyntheticProvider;
        let (mut vault, recovery) = host
            .create_with_access(
                &path,
                PASSWORD,
                limits(),
                policy(),
                admission.clone(),
                profile,
                &identities,
                false,
                &mut provider,
            )
            .unwrap();
        assert!(recovery.is_none());
        assert_eq!(descriptor(&path).len(), width);
        assert_current(&path, 0);
        let info = vault.access_info().unwrap();
        assert_eq!(info.profile, profile);
        let slot = info.device_slots.first().map(|slot| slot.0);
        let path_for_unlock = || {
            if profile == AccessProfile::PasswordAndDevice {
                AccessPath::Device {
                    slot_id: slot.unwrap(),
                    password: Some(PASSWORD),
                }
            } else {
                AccessPath::Password(PASSWORD)
            }
        };
        let token = vault
            .unlock_access(path_for_unlock(), &mut provider)
            .unwrap();
        let metadata = vec![0x46; 64];
        let payload = vec![0x47; 4096];
        vault
            .save(&token, ID, None, &metadata, &payload, [0xf3; 16])
            .unwrap();
        assert_eq!(content(&path)[0].len(), 4096 + 64 + 176);
        vault.audit(&token).unwrap();
        vault.lock();
        drop(vault);
        let mut vault = host
            .open_with_access(&path, limits(), policy(), admission)
            .unwrap();
        let token = vault
            .unlock_access(path_for_unlock(), &mut provider)
            .unwrap();
        let record = vault.read(&token, ID).unwrap();
        assert_eq!(record.metadata.as_slice(), metadata);
        assert_eq!(record.payload.as_slice(), payload);
    }
}
