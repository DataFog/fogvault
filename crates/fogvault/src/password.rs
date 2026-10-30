use crate::{Error, Result};

/// Validate a text password's UTF-8 and borrow its exact bytes.
///
/// This does not normalize Unicode, trim whitespace, change case, strip a BOM,
/// replace malformed input, or stop at NUL. Empty text is valid at this encoding
/// boundary; password-strength policy is a separate concern. No copy is made,
/// and the caller remains responsible for the input's lifetime and cleanup.
///
/// The Engine's byte-oriented credential APIs independently accept arbitrary
/// octets. Call this helper only when the input is declared to be UTF-8 text.
pub fn password_utf8_bytes(input: &[u8]) -> Result<&[u8]> {
    std::str::from_utf8(input)
        .map_err(|_| Error::Malformed("password text must be valid UTF-8"))?;
    Ok(input)
}
