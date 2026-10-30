//! Explicit one-time fixture capture. Never invoked by the behavior verifier.
#[path = "../tests/support/access_fixture_provider.rs"]
mod provider;
use fogvault::{AccessAdmission, AccessProfile, Engine, KdfPolicy, Limits, ProviderIdentity};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("fresh output directory required")?,
    );
    fs::create_dir(&directory)?;
    let key = [0xa5; 32];
    fs::write(directory.join("SYNTHETIC-provider-key.bin"), key)?;
    let identities = [
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
    // max(Portable/POR/AND) for two72-byte wrapped seeds and one recovery slot:
    // max(108+72+2*(64+72+72)+96,108+2*(64+72+112)+96)=700.
    let admission = AccessAdmission {
        allowed_profiles: vec![
            AccessProfile::Portable,
            AccessProfile::PasswordOrDevice,
            AccessProfile::PasswordAndDevice,
        ],
        providers: identities.to_vec(),
        max_descriptor_bytes: 700,
        max_device_slots: 2,
        max_provider_blob_bytes: 72,
    };
    let limits = Limits {
        max_payload_bytes: 0,
        max_metadata_bytes: 0,
        max_records: 0,
    };
    for (name, profile, count) in [
        ("portable", AccessProfile::Portable, 0),
        ("convenience", AccessProfile::PasswordOrDevice, 1),
        ("strict", AccessProfile::PasswordAndDevice, 2),
    ] {
        let mut provider = provider::FixtureProvider::new(key);
        let (engine, recovery) = Engine::create_with_access(
            b"SYNTHETIC access fixture password",
            limits,
            KdfPolicy::baseline(),
            admission.clone(),
            profile,
            &identities[..count],
            true,
            &mut provider,
        )?;
        fs::write(
            directory.join(format!("{name}-descriptor.bin")),
            engine.descriptor_bytes(),
        )?;
        fs::write(
            directory.join(format!("{name}-head.bin")),
            engine.head_bytes(),
        )?;
        fs::write(
            directory.join(format!("{name}-recovery.bin")),
            recovery
                .ok_or("missing recovery fixture")?
                .export()
                .as_slice(),
        )?;
    }
    println!("Captured synthetic P3 fixtures in {}. Review and pin hashes; never regenerate automatically.",directory.display());
    Ok(())
}
