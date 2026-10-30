//! Synthetic vector-only provider. Its key is intentionally public test data;
//! it establishes no hardware, nonexportability or device qualification.
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use fogvault::{KeyProvider, ProviderContext, ProviderError, ProviderResult};
use zeroize::Zeroizing;
pub struct FixtureProvider {
    key: Zeroizing<[u8; 32]>,
}
impl FixtureProvider {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }
}
impl KeyProvider for FixtureProvider {
    // Synthetic operation oracle only; this declaration is not hardware evidence.
    fn capability_kind(
        &self,
        _identity: &fogvault::ProviderIdentity,
    ) -> fogvault::ProviderCapabilityKind {
        fogvault::ProviderCapabilityKind::NonExportableOperation
    }
    fn wrap_seed(&mut self, context: &ProviderContext, seed: &[u8; 32]) -> ProviderResult<Vec<u8>> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| ProviderError::Failure)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| ProviderError::Failure)?;
        let body = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: seed,
                    aad: &context.authenticated_bytes(),
                },
            )
            .map_err(|_| ProviderError::Failure)?;
        let mut output = nonce.to_vec();
        output.extend_from_slice(&body);
        Ok(output)
    }
    fn unwrap_seed(
        &mut self,
        context: &ProviderContext,
        wrapped: &[u8],
    ) -> ProviderResult<Zeroizing<[u8; 32]>> {
        if wrapped.len() != 72 {
            return Err(ProviderError::InvalidResponse);
        }
        let nonce: &[u8; 24] = wrapped[..24]
            .try_into()
            .map_err(|_| ProviderError::InvalidResponse)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| ProviderError::Failure)?;
        let output = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(*nonce),
                    Payload {
                        msg: &wrapped[24..],
                        aad: &context.authenticated_bytes(),
                    },
                )
                .map_err(|_| ProviderError::InvalidResponse)?,
        );
        Ok(Zeroizing::new(
            output
                .as_slice()
                .try_into()
                .map_err(|_| ProviderError::InvalidResponse)?,
        ))
    }
}
