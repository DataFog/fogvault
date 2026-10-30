//! Explicit host admission for the provisional Argon2id profile.
//!
//! A profile describes work; the host's exact allowlist authorizes that work.
//! Higher settings are not accepted just because an untrusted header names them.
use crate::{crypto, Error, Result};

/// Argon2id v1.3 with one lane and a 32-byte result. Fields cannot be forged
/// through the safe public API. This does not select a production device budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfProfile {
    memory_kib: u32,
    passes: u32,
}
impl KdfProfile {
    pub const fn baseline() -> Self {
        Self {
            memory_kib: crypto::MEMORY_KIB,
            passes: crypto::PASSES,
        }
    }

    /// Construct a canonical profile at least as strong in both dimensions as
    /// the existing experiment. Four segments per lane require a multiple of
    /// four memory blocks; this avoids nominal upgrades with rounded-down work.
    pub fn argon2id(memory_kib: u32, passes: u32) -> Result<Self> {
        if memory_kib < crypto::MEMORY_KIB
            || passes < crypto::PASSES
            || !memory_kib.is_multiple_of(4)
        {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        argon2::Params::new(memory_kib, passes, crypto::LANES, Some(crypto::KEY_LEN))
            .map_err(|_| Error::Crypto(crypto::CryptoError::RejectedKdfParameters))?;
        Ok(Self { memory_kib, passes })
    }
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }
    pub const fn passes(self) -> u32 {
        self.passes
    }
    pub const fn lanes(self) -> u32 {
        crypto::LANES
    }

    /// No memory/time tradeoff is silently treated as an upgrade.
    pub fn is_strict_upgrade_from(self, current: Self) -> bool {
        self.memory_kib >= current.memory_kib && self.passes >= current.passes && self != current
    }
}
impl Default for KdfProfile {
    fn default() -> Self {
        Self::baseline()
    }
}

/// Trusted host policy: the exact profiles this host has budgeted and permits.
/// There is deliberately no newly invented universal upper bound or upgrade
/// default. Hosts must qualify every admitted setting for their own resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfPolicy {
    profiles: Vec<KdfProfile>,
    work_budget: Option<crate::budget::WorkBudget>,
}
impl KdfPolicy {
    /// Build this from trusted host configuration, never from a saved header.
    pub fn new(profiles: Vec<KdfProfile>) -> Result<Self> {
        if profiles.is_empty() {
            return Err(crypto::CryptoError::RejectedKdfParameters.into());
        }
        for (index, profile) in profiles.iter().enumerate() {
            // Cheap validation only; constructing/admitting a policy does not
            // allocate Argon2 work memory or run a password derivation.
            KdfProfile::argon2id(profile.memory_kib(), profile.passes())?;
            if profiles[..index].contains(profile) {
                return Err(crypto::CryptoError::RejectedKdfParameters.into());
            }
        }
        Ok(Self {
            profiles,
            work_budget: None,
        })
    }
    pub fn baseline() -> Self {
        Self {
            profiles: vec![KdfProfile::baseline()],
            work_budget: None,
        }
    }
    /// Attach the SAME controller to policies for all vaults sharing a host
    /// allowance. The charge covers Argon2's exact block work area only; hosts
    /// must additionally admit their application, staging and foreign buffers.
    pub fn with_work_budget(mut self, budget: crate::budget::WorkBudget) -> Self {
        self.work_budget = Some(budget);
        self
    }
    pub fn work_budget(&self) -> Option<&crate::budget::WorkBudget> {
        self.work_budget.as_ref()
    }
    pub fn admit(&self, profile: KdfProfile) -> Result<()> {
        if self.profiles.contains(&profile) {
            Ok(())
        } else {
            Err(crypto::CryptoError::RejectedKdfParameters.into())
        }
    }
}
impl Default for KdfPolicy {
    fn default() -> Self {
        Self::baseline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_admits_only_explicit_canonical_nonweaker_profiles() {
        let base = KdfProfile::baseline();
        let next = KdfProfile::argon2id(base.memory_kib(), base.passes() + 1).unwrap();
        assert!(!base.is_strict_upgrade_from(base));
        assert!(next.is_strict_upgrade_from(base));
        assert!(!base.is_strict_upgrade_from(next));
        let more_memory = KdfProfile::argon2id(base.memory_kib() + 4, base.passes()).unwrap();
        assert!(!more_memory.is_strict_upgrade_from(next));
        assert!(!next.is_strict_upgrade_from(more_memory));
        assert!(KdfPolicy::baseline().admit(base).is_ok());
        assert!(KdfPolicy::baseline().admit(next).is_err());
        assert!(KdfPolicy::new(vec![]).is_err());
        assert!(KdfPolicy::new(vec![base, base]).is_err());
        let policy = KdfPolicy::new(vec![base, next]).unwrap();
        assert!(policy.admit(next).is_ok());
        assert!(policy.admit(more_memory).is_err());
        for (memory, passes) in [
            (base.memory_kib() - 4, base.passes()),
            (base.memory_kib(), base.passes() - 1),
            (base.memory_kib() + 1, base.passes()),
            (u32::MAX, u32::MAX),
        ] {
            assert!(KdfProfile::argon2id(memory, passes).is_err());
        }
    }
}
