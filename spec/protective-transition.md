> Historical construction notes retained as verification inputs. Current creation uses content3 at epoch zero; API text below may describe earlier diagnostic paths. See the [public overview](../README.md) and [current core tests](../crates/fogvault/tests/current_format.rs). Links to omitted historical documents are shown as plain paths.

# Protective full-content transition candidate

This is the post-review construction for meaningful strengthening and compromise recovery. It is implemented as an opaque portable Rust planner, with a focused SQLite/macOS control-store realization. It is not a supported all-host rotation package or independent construction approval. Read it with trusted control state (`trusted-control-state.md`), adapter ordering (`adapter-contract.md`), [format profile](format-profile-review.md) and shared admission (`shared-admission.md`).

## Operation and authority

Entry into strict password-and-device access from a weaker persisted profile must use this operation. Header-only profile/setup/recovery-repair methods reject that strengthening. A newly created strict vault has no earlier persisted weaker descriptor and remains supported. Password/KDF maintenance continues to rewrap an unchanged root, with historical-copy exposure plainly stated.

The owner selects the target normal profile, exact devices, replacement password and recovery choice. Reauthenticate the accepted source through its approved current path, or through audited restricted recovery. Generate a fresh root, increment its epoch, rebuild and prove selected routes, and generate fresh recovery material if selected. Any credential/provider known compromised must be replaced; protecting a new root under the same compromised route is not recovery.

The source Engine retains its accepted source state while encrypted target objects are prepared in isolation. Restricted recovery can produce opaque encrypted-record proofs for this operation without granting normal read or session authority. The planner exposes no unwrapped root/content-key getter, Clone, Debug dump or ordinary serialization.

Every source record is authenticated, privately decoded and encrypted with a fresh content key, fresh wrapper/body nonces and the target root-derived wrapping key. Preserve opaque record ID, logical revision, metadata and payload bytes. Strictly increasing unique source IDs, verified membership in the fixed source head, and complete authenticated source count prevent omission/duplication. Source poisoning before trusted source selection is outside the confidentiality repair: fresh encryption cannot prove old data was never altered.

## Exact owner binding and checkpoint

The owner commitment is SHA-256 over:

`F("fogvault/prototype/protective-owner/v1") || SHA256(source_descriptor) || SHA256(source_head) || SHA256(target_descriptor) || request_id16 || full_mode_u8(1)`.

This digest acquires authority only through the separately trusted, explicitly registered host control store. Store the exact source/target/request/commitment before checkpoint-driven work. A parsed control value from the vault, a digest adjacent to staging, or a value authenticated only under the old root is insufficient. The host pins the registration identity independently of presented vault data.

The checkpoint is exactly **138 bytes**:

| Field | Bytes |
| --- | ---: |
| Magic/version `FGVPRT01` | 8 |
| Exact owner commitment | 32 |
| XChaCha encrypted progress: nonce24, plaintext58, tag16 | 98 |

Progress plaintext is `processed_u64 || last_present_u8 || last_id16 || root_present_u8 || target_index_root32`. Canonical absent fields are zero; positive progress requires present last ID/root and cannot exceed authenticated source count. Staging key is the existing HKDF construction with fresh target root/vault ID and purpose `protective-staging/v1`. AAD is the exact 40-byte public checkpoint prefix. Every checkpoint write gets a fresh nonce; retries/forks remain usage-analysis obligations.

Persist target descriptor and encrypted record/node staging separately under the operation namespace. The checkpoint contains neither root nor unwrapped content keys. Old checkpoints may require repeating work but cannot silently select a different authorized target. Resume admits exact lengths/profile before credential work; verifies the independently retained owner binding; requires the accepted source and target credentials; authenticates progress; and re-audits reachable staged records and bodies. Missing receipt, wrong factors, foreign/edited target, altered checkpoint or missing/changed staged objects refuses.

## Epoch-aware content format

Historical P2 and P3/content-two fixtures are unchanged. The new candidate retains credential grammar/version 3 and suite 1 but explicitly selects **content format 3** in its authenticated descriptor. Existing readers reject this content ID. New callers must opt in through `Engine::open_epoch_access`; ordinary P3 opening does not reinterpret it.

The record frame is:

`FGVR0003 || record_id16 || revision_u64BE || wrapping_epoch_u64BE || wrapped_content_key72 || body_length_u64BE || body_AEAD`.

Its maximum encoded overhead is **176 bytes**, eight more than content two. Use descriptor-specific `Engine::envelope_byte_limit()` before fetching/copying an encoded record, including startup, staging and reconciliation. The legacy `Limits::envelope_bytes()` still describes content one/two and must not be reused as the new profile's bound.

The immutable context uses the existing framed context hash with content-format ID 3, suite and vault identity. Record-wrap AAD appends the authenticated root/wrapping epoch to the existing framed purpose, immutable context, vault ID, record ID and revision. The encoded epoch must equal the descriptor's root epoch. Body AAD excludes the mutable wrapping epoch. This preserves a meaningful wrapping-only transformation within content three while full protection uses new content keys/bodies. Migration from content two is full encryption under the explicitly different context.

New descriptor/head/record/node/key/recovery fixtures and exact rejection checks are separately retained in [epoch vectors](../conformance/epoch-vectors.json). They are synthetic fixed bytes, not independent cryptographic derivation or production compatibility approval.

## Completion, publication and restart

The planner audits the complete reachable target graph and every staged body before returning a plan. The target head advances source generation by one, preserves record count, uses the request ID, and authenticates the complete target descriptor and index root. Its operation input is `F("fogvault/prototype/protective-full/v1") || owner_commitment`, under the fresh target operation key.

Staging may retain unreachable path nodes/orphan rows. Final publication copies only the authenticated reachable graph and exact record set; validate actual destination counts. Blindly copying all physical staging objects is not authorized by `finish()` and can make the target unreadable.

Persist the exact final target descriptor/head identity in the trusted control intent **before** possible database submission. The Engine then admits that exact plan and enters a dedicated uncertain barrier: ordinary operations cannot treat the source session as normal authority. A cached control value alone does not authorize a later write. Under the shared live per-registration coordinator, reload and match current independent intent, compare the complete source descriptor/head and required source inventory within the writer transaction, publish the complete paired target graph, and persist trusted completion before exposing normal target authority. KDF/provider work occurs outside the final coordinator.

Confirmation compares the exact pending target descriptor, encoded/parsed head, replacement session and target admission to the supplied opaque transition. It does no new entropy, KDF or provider work. Lock/revocation prevents later live authority or plaintext publication; an already admitted encrypted write may still complete and require reconciliation.

After process death, a current authenticated exact target can complete the original trusted intent. Observing the old source after possible submission remains unknown. Where the original complete encrypted stage/checkpoint survives, an explicitly named exact-target republish can re-establish the same authorized target under the live coordinator; it cannot re-encrypt, rebase, change request or infer abort. Missing receipt/stage/target factors or newer independent authority refuses. Required-control loss never triggers automatic registration or unanchored fallback.

The focused host experiments demonstrate named process-death, substitution, CAS and stale-writer interleavings under a vault-file attacker and trusted OS/control namespace. They do not qualify rollback of that namespace, hostile active host/provider, power-cut durability, real phone hardware or every supported adapter. Broad maintained bridges and physical qualification remain separate work. All six design-freeze gates remain open until their actual requirements are met.
