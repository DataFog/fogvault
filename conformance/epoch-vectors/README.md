# Synthetic epoch-aware record fixture

All passwords, root keys, content keys and recovery material in this directory are intentionally public test data. Never use them for a real vault.

This is a separate candidate corpus for P3 credentials with **content format 3**, not a change to the existing content-two P2/P3 corpus. The default P3 opener rejects it; the candidate requires `Engine::open_epoch_access`. It is not a frozen production format or independently approved cryptographic construction.

The manifest is `../epoch-vectors.json`. Its file identities are also pinned as constants by `fixed_epoch_vectors_pin_bytes_and_reject_epoch_magic_truncation_and_context_changes` in the Rust core. The verifier consumes these fixed bytes and must never regenerate its own expectations. A one-time capture recipe is retained outside the compiled test suite at `artifacts/remediation/epoch-fixture-capture.rs.txt`. It used ordinary OS randomness; no deterministic production RNG fallback was introduced.

The descriptor uses the existing ordered `FGVP0003` frame, credential version 3, suite 1 and the explicit content-format field 3. It has vault ID `31` repeated 16 times, root epoch 7, policy epoch 9, portable password access and an independent synthetic recovery route. The owner kit remains `FGVRKEY3`. Native context is the existing framed context domain with content-format integer 3, suite 1 and vault ID. Mutable credential fields remain bound by the complete descriptor hash in the head.

The record is `FGVR0003 || record_id16 || revision_u64BE || wrapping_epoch_u64BE || wrapped_key72 || body_length_u64BE || body_AEAD`. Fixed overhead is 176 bytes, plus metadata and payload. The wrapping epoch must match the accepted descriptor's root epoch and is appended to record-wrap AAD. Record-body AAD keeps the immutable content context, vault/record identity and revision; it deliberately excludes the changing wrapping epoch. Therefore wrapping-only rotation within content format 3 preserves the body, whereas full protection generates a fresh content key and re-encrypts it. Migration from content format 2 to 3 is a full-content operation.

The fixture has record ID `42` repeated 16 times, revision 3, metadata `fixed metadata` and payload `epoch profile fixture`. The constant head frame retains its content-addressed public-index semantics: generation 11, request `55` repeated 16 times, operation digest `66` repeated 32 times, one record and the single fixed leaf. These values are test inputs, not production capacity, epoch or operation policies.

Tests read the static descriptor, authenticate its password/recovery routes and head, verify the fixed node/record digest, and decode the expected plaintext. They reject record truncations, trailing bytes, changed epoch/magic/identity/revision/length/tag, unsupported content IDs, a mismatching descriptor epoch and use through the old default opener. A separate wrapping-rotation test demonstrates both the epoch AAD binding and the continued historical-CEK access to an unchanged body.

Independent decoding with a separate primitive implementation remains additional evidence; these captured bytes and Rust tests are not that independent review.
