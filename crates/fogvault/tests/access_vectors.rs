//! Fixed P3 bytes captured explicitly once; this test never regenerates them.
#[path = "support/access_fixture_provider.rs"]
mod provider;
use fogvault::{
    AccessAdmission, AccessPath, AccessProfile, AuditRequest, Engine, KdfPolicy, Limits,
    ProviderIdentity, RecoveryKey,
};
use std::path::Path;
fn file(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance")
            .join(name),
    )
    .unwrap()
}
#[test]
fn fixed_access_vectors_enforce_parse_unlock_and_audit_boundaries() {
    let identities = vec![
        ProviderIdentity {
            provider_id: [1; 16],
            key_id: [2; 16],
            device_bound: true,
            nonexportable: true,
        },
        ProviderIdentity {
            provider_id: [3; 16],
            key_id: [4; 16],
            device_bound: true,
            nonexportable: true,
        },
    ];
    let admission = AccessAdmission {
        allowed_profiles: vec![
            AccessProfile::Portable,
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ],
        providers: identities,
        max_descriptor_bytes: 700,
        max_device_slots: 2,
        max_provider_blob_bytes: 72,
    };
    let limits = Limits {
        max_payload_bytes: 0,
        max_metadata_bytes: 0,
        max_records: 0,
    };
    let password = b"SYNTHETIC access fixture password";
    let mut visited = 0;
    for line in include_str!("../../../conformance/access-vectors.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 7);
        let id = fields[0];
        let descriptor = file(fields[1]);
        let head = file(fields[2]);
        let expected = fields[6];
        let opened = Engine::diagnostic_open_with_access(
            &descriptor,
            limits,
            KdfPolicy::baseline(),
            admission.clone(),
        );
        visited += 1;
        if expected == "parse" {
            assert!(opened.is_err(), "{id}");
            continue;
        }
        let mut engine = opened.unwrap_or_else(|error| panic!("{id}: {error}"));
        assert!(
            Engine::open(&descriptor, limits).is_err(),
            "legacy reader accepted {id}"
        );
        let mut provider = provider::FixtureProvider::new(file(fields[4]).try_into().unwrap());
        let result = match fields[5] {
            "password" => engine.begin_unlock_access(AccessPath::Password(password), &mut provider),
            "wrong_password" => {
                engine.begin_unlock_access(AccessPath::Password(b"wrong"), &mut provider)
            }
            "device" | "device_without_password" => {
                let slot = engine.access_info().unwrap().device_slots[0].0;
                engine.begin_unlock_access(
                    AccessPath::Device {
                        slot_id: slot,
                        password: if fields[5] == "device"
                            && engine.access_info().unwrap().profile
                                == AccessProfile::PasswordAndDevice
                        {
                            Some(password)
                        } else {
                            None
                        },
                    },
                    &mut provider,
                )
            }
            "recovery" => engine.begin_recovery(&RecoveryKey::import(&file(fields[3])).unwrap()),
            other => panic!("unexpected vector mode {other}"),
        };
        if expected == "unlock" {
            assert!(result.is_err(), "{id}");
            assert!(engine.current_session().is_err());
            continue;
        }
        result.unwrap_or_else(|error| panic!("{id}: {error}"));
        let started = engine.begin_audit(&head);
        if expected == "audit" {
            assert!(started.is_err(), "{id}");
            assert!(engine.current_session().is_err());
            continue;
        }
        assert_eq!(expected, "accept");
        started.unwrap();
        assert!(matches!(engine.audit_next().unwrap(), AuditRequest::Done));
        engine.finish_audit(0, 0).unwrap();
        engine.activate_audit().unwrap();
        if fields[5] == "recovery" {
            assert!(engine.is_recovery_candidate());
            assert!(engine.current_session().is_err());
        } else {
            assert!(engine.current_session().is_ok());
        }
    }
    assert_eq!(visited, 26);
}
