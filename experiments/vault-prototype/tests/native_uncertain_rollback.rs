//! A source snapshot is an observation, not proof of noncommit in hostile storage.
use fogvault::{
    AccessAdmission, AccessChange, AccessPath, AccessProfile, KdfPolicy, KdfProfile, KeyProvider,
    ProviderCapabilityKind, ProviderContext, ProviderError, ProviderIdentity, ProviderResult,
};
use fogvault_disposable_prototype::{CommitFault, Error, Limits, Vault};
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"uncertain-rollback-synthetic-password";
const NEW: &[u8] = b"uncertain-rollback-replacement";
const REQUEST: [u8; 16] = [0x71; 16];
fn limits() -> Limits {
    Limits {
        max_payload_bytes: 64,
        max_metadata_bytes: 16,
        max_records: 4,
    }
}
fn unknown<T>(result: Result<T, Error>) {
    assert!(matches!(result, Err(Error::OutcomeUnknown { request_id }) if request_id == REQUEST));
}
struct NoProvider;
impl KeyProvider for NoProvider {
    fn capability_kind(&self, _: &ProviderIdentity) -> ProviderCapabilityKind {
        ProviderCapabilityKind::ConvenienceCache
    }
    fn wrap_seed(&mut self, _: &ProviderContext, _: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        Err(ProviderError::Unavailable)
    }
    fn unwrap_seed(
        &mut self,
        _: &ProviderContext,
        _: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        Err(ProviderError::Unavailable)
    }
}
fn admission() -> AccessAdmission {
    AccessAdmission {
        allowed_profiles: vec![AccessProfile::Portable],
        providers: vec![],
        max_descriptor_bytes: 276,
        max_device_slots: 0,
        max_provider_blob_bytes: 0,
    }
}

#[test]
fn native_credential_rolled_back_lost_reply_preserves_typed_uncertainty() {
    for upgrade in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("uncertain-credential.sqlite");
        let baseline = KdfProfile::baseline();
        let target = KdfProfile::argon2id(baseline.memory_kib(), baseline.passes() + 1).unwrap();
        let policy = KdfPolicy::new(vec![baseline, target]).unwrap();
        let mut vault =
            Vault::diagnostic_create_with_kdf_policy(&path, PASSWORD, limits(), policy).unwrap();
        let token = vault.unlock(PASSWORD).unwrap();
        let before = std::fs::read(&path).unwrap();
        if upgrade {
            unknown(vault.upgrade_kdf_with_fault(
                &token,
                PASSWORD,
                target,
                REQUEST,
                CommitFault::RolledBackLostReply,
            ));
        } else {
            unknown(vault.change_password_with_fault(
                &token,
                PASSWORD,
                NEW,
                REQUEST,
                CommitFault::RolledBackLostReply,
            ));
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        unknown(vault.reconcile_latest(&token, REQUEST));
        unknown(vault.read(&token, [1; 16]));
        unknown(vault.change_password(&token, PASSWORD, NEW, [2; 16]));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn native_access_and_recovery_rolled_back_lost_reply_are_not_corruption() {
    for repair in [false, true] {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("uncertain-access.sqlite");
        let mut provider = NoProvider;
        let (creation, recovery) = Vault::diagnostic_prepare_access_creation(
            PASSWORD,
            limits(),
            KdfPolicy::baseline(),
            admission(),
            AccessProfile::Portable,
            &[],
            true,
            &mut provider,
        )
        .unwrap();
        let recovery = recovery.unwrap();
        let mut vault = creation.publish(&path, CommitFault::None).unwrap();
        let token = vault
            .unlock_access(AccessPath::Password(PASSWORD), &mut provider)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let draft = if repair {
            vault.lock();
            vault.recover_access(&recovery).unwrap();
            vault
                .prepare_recovery_maintenance(
                    &recovery,
                    NEW,
                    AccessProfile::Portable,
                    &[],
                    true,
                    &mut provider,
                    REQUEST,
                )
                .unwrap()
                .0
        } else {
            vault
                .prepare_access_maintenance(
                    &token,
                    AccessPath::Password(PASSWORD),
                    AccessChange::DisableRecovery,
                    &mut provider,
                    REQUEST,
                )
                .unwrap()
                .0
        };
        unknown(vault.commit_access_change(draft, REQUEST, CommitFault::RolledBackLostReply));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        unknown(vault.reconcile_access_latest(REQUEST));
        if repair {
            assert!(vault.current_session().is_err());
            assert!(vault.read(&token, [1; 16]).is_err());
        } else {
            unknown(vault.read(&token, [1; 16]));
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
