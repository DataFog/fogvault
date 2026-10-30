//! Diagnostic construction proof, excluded from the ordinary public API.
use super::*;

/// Build one same-content-profile P2 or epoch-aware P3 rotated record after
/// authenticating all source fields and body. This is a diagnostic helper.
/// Rewrapping preserves the exact content ciphertext; full rotation generates a
/// fresh content key/body. Neither operation erases retained historical copies.
#[allow(clippy::too_many_arguments)]
pub fn rotate_record(
    old_descriptor: &Descriptor,
    old_wrapping: &[u8; 32],
    new_descriptor: &Descriptor,
    new_wrapping: &[u8; 32],
    id: &RecordId,
    revision: u64,
    envelope: &[u8],
    limits: Limits,
    reencrypt: bool,
) -> Result<Vec<u8>> {
    let p2 = old_descriptor.credential_format_id() == INDEX_FORMAT_ID
        && new_descriptor.credential_format_id() == INDEX_FORMAT_ID;
    let epoch = old_descriptor.credential_format_id() == 3
        && new_descriptor.credential_format_id() == 3
        && old_descriptor.format_id() == EPOCH_FORMAT_ID
        && new_descriptor.format_id() == EPOCH_FORMAT_ID;
    if !(p2 || epoch)
        || old_descriptor.vault_id != new_descriptor.vault_id
        || old_descriptor.context_hash() != new_descriptor.context_hash()
    {
        return Err(Error::Malformed("rotation content context"));
    }
    let decoded = decrypt_record(old_descriptor, old_wrapping, id, revision, envelope, limits)?;
    if reencrypt {
        return encrypt_record(
            new_descriptor,
            new_wrapping,
            id,
            revision,
            &decoded.metadata,
            &decoded.payload,
            limits,
        );
    }
    let mut reader = Reader::new(envelope);
    reader.take(8 + 16 + 8)?;
    if epoch {
        reader.u64()?;
    }
    let wrapped = reader.take(72)?;
    let key = crypto::open(
        old_wrapping,
        &record_aad(
            old_descriptor,
            id,
            revision,
            b"fogvault/prototype/record-wrap/v1",
        ),
        wrapped,
    )?;
    let key: &[u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("content key"))?;
    let replacement = crypto::seal(
        new_wrapping,
        &record_aad(
            new_descriptor,
            id,
            revision,
            b"fogvault/prototype/record-wrap/v1",
        ),
        key,
    )?;
    if replacement.len() != 72 {
        return Err(Error::Integrity);
    }
    let mut result = envelope.to_vec();
    if epoch {
        result[32..40].copy_from_slice(&new_descriptor.root_epoch().to_be_bytes());
        result[40..112].copy_from_slice(&replacement);
    } else {
        result[32..104].copy_from_slice(&replacement);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_rotation_and_full_rotation_have_distinct_retained_key_effects() {
        let (old, root) = Descriptor::create(b"synthetic-old-rotation").unwrap();
        let new_root = Zeroizing::new(crypto::random::<32>().unwrap());
        let new = old
            .rewrap(
                &new_root,
                b"synthetic-new-rotation",
                KdfProfile::baseline(),
                &KdfPolicy::baseline(),
            )
            .unwrap();
        let old_wrap = crypto::derive(&root, &old.vault_id, b"record-key-wrapping").unwrap();
        let new_wrap = crypto::derive(&new_root, &new.vault_id, b"record-key-wrapping").unwrap();
        let limits = Limits {
            max_payload_bytes: 128,
            max_metadata_bytes: 32,
            max_records: 1,
        };
        let id = [0x44; 16];
        let source = encrypt_record(
            &old,
            &old_wrap,
            &id,
            7,
            b"metadata",
            b"synthetic rotation payload",
            limits,
        )
        .unwrap();
        let retained = crypto::open(
            &old_wrap,
            &record_aad(&old, &id, 7, b"fogvault/prototype/record-wrap/v1"),
            &source[32..104],
        )
        .unwrap();
        let retained: &[u8; 32] = retained.as_slice().try_into().unwrap();
        let rewrapped = rotate_record(
            &old, &old_wrap, &new, &new_wrap, &id, 7, &source, limits, false,
        )
        .unwrap();
        assert_eq!(&source[104..], &rewrapped[104..]);
        assert_ne!(&source[32..104], &rewrapped[32..104]);
        assert!(crypto::open(
            retained,
            &record_aad(&new, &id, 7, b"fogvault/prototype/record-body/v1"),
            &rewrapped[112..]
        )
        .is_ok());
        assert!(decrypt_record(&new, &old_wrap, &id, 7, &rewrapped, limits).is_err());
        let full = rotate_record(
            &old, &old_wrap, &new, &new_wrap, &id, 7, &source, limits, true,
        )
        .unwrap();
        assert_ne!(&source[104..], &full[104..]);
        assert!(crypto::open(
            retained,
            &record_aad(&new, &id, 7, b"fogvault/prototype/record-body/v1"),
            &full[112..]
        )
        .is_err());
        assert_eq!(
            decrypt_record(&new, &new_wrap, &id, 7, &full, limits)
                .unwrap()
                .payload
                .as_slice(),
            b"synthetic rotation payload"
        );
        let mut corrupt = source.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            rotate_record(&old, &old_wrap, &new, &new_wrap, &id, 7, &corrupt, limits, false)
                .is_err()
        );
        let mut trailing = source;
        trailing.push(0);
        assert!(
            rotate_record(&old, &old_wrap, &new, &new_wrap, &id, 7, &trailing, limits, true)
                .is_err()
        );
    }
}
