> Historical construction notes retained as verification inputs. Current creation uses content3 at epoch zero; API text below may describe earlier diagnostic paths. See the [public overview](../README.md) and [current core tests](../crates/fogvault/tests/current_format.rs). Links to omitted historical documents are shown as plain paths.

# Exact format and cryptographic profile for first review

This is a construction presented for review, not an approved or frozen protocol. The original handoff used P2 record/index content and P3 access descriptors retaining that content. The post-review [protective transition](protective-transition.md) adds a separately admitted content-three record profile with an explicit authenticated wrapping epoch, fresh-root/full-content strengthening and fixed new fixtures. Historical P2/P3-content-two bytes are unchanged; ordinary readers do not silently accept the new profile. Independent construction review, physical host qualification and maintained all-host operations remain open.

Read this with the review-entry contract (`review-entry.md`), access policy (`access-paths.md`), record/snapshot contract (`record-snapshots.md`), rotation/staging proof (`rotation-staging.md`), export payload (`export-payload.md`), adapter contract (`adapter-contract.md`) and support manifest (`support-manifest.md`). The ordinary Rust Engine owns secrets and authority; diagnostic codecs are not a supported raw-key API. DataFog Core remains the exact `0.5.0-beta.3` dev/test consumer and its opaque bundle remains a generic record.

## Two explicit changes from the architecture draft

The current technical specification now describes the selected implementation. Earlier architecture drafts described the stronger objects below. This records that disposition and its costs; independent approval of the selected construction remains required before freeze.

| Earlier draft expectation | Actual selected candidate | Recommendation and cost |
| --- | --- | --- |
| Earlier technical specification (`technical-specification.md`) key-role/object tables described **encrypted index nodes**. | P2 nodes are **public, content-addressed and authenticated** through the head. Leaves expose opaque record IDs, current revisions and encrypted-envelope digests. Branches expose prefixes, shape and child hashes. Sensitive labels, metadata and payload stay inside record encryption. There is no index-encryption key or node nonce. | Retain this simpler candidate only if the permitted leakage is explicitly accepted. It supports small fixed nodes and bounded traversal without another cipher/key lifecycle. Encrypting nodes would require a revised format, keys/nonces, fixtures, admission and growth evidence. It would still not hide all sizes or access patterns. |
| Draft commit-head row includes a **previous-commit commitment**. | The 129-byte head authenticates current generation, operation, count, root and full credential descriptor. It contains **no previous-head field**. Expected prior descriptor/head are compared by the publishing transaction and captured in opaque drafts/proofs. | Retain latest-state semantics if no historical ledger is promised. This detects stale concurrent mutations and selective substitution under the accepted head. It does not provide historical ancestry, non-latest receipts, fork consensus or reopened-store rollback detection. Those need separately defined authenticated history/freshness services. |

Opaque IDs are not automatically private: callers must keep sensitive labels out of them. A store observer can correlate stable IDs, revisions, unchanged objects, tree shape, counts, sizes, policy/provider identifiers and access patterns across observed snapshots. Hashes do not conceal guessed IDs or undo such correlation. A complete old authenticated store remains admissible after reopening unless independently trusted freshness state rejects it. Generation or a root epoch alone does not establish freshness.

Deletion removes the live leaf. Same-ID reinsertion starts revision one; it is a new live incarnation. There are no authenticated tombstones or global per-ID monotonic history. Maintained mutation requests therefore require expected **head/commit and record revision**, or an opaque draft/proof already bound to both. Revision-only compare-and-swap permits ABA after deletion/reinsertion; an operation ID is not a permanent intent ledger. Record/snapshot semantics (`record-snapshots.md`) specify the exact current protections and legacy diagnostic limits.

## Primitive profile and byte conventions

The implementation is [crypto.rs](../crates/fogvault/src/crypto.rs), with [KDF admission](../crates/fogvault/src/kdf.rs). All native framing integers below are unsigned **big endian**, including lengths. Exact labels are ASCII bytes. `F(x) = u64BE(len(x)) || x`; it adds no implicit terminator. Labels explicitly written with `\0` contain one actual `00` byte.

| Operation | Exact selected behavior |
| --- | --- |
| Password input | Exact byte sequence under password-bytes.md (`password-bytes.md`); scalar-text bindings use strict UTF-8 with no normalization, trimming or lossy replacement. Raw octets are a distinct API input. |
| Password KDF | Argon2id, version `0x13`, salt16, output32, baseline memory65536 KiB/time3/lanes1. Higher settings require exact trusted `KdfPolicy` admission before work allocation. Profiles are nonweaker in both memory and time; memory is a multiple of four blocks. No header can grant itself a larger budget. |
| Hierarchy derivation `D(s,v,p)` | HKDF-SHA-256, salt=`vault_id[16]`, IKM=`s[32]`, info=`b"fogvault/prototype/key-derivation/v1\0" || u64BE(len(p)) || p`, output32. |
| AEAD `E(k,a,m)` | XChaCha20-Poly1305, key32, fresh OS-random nonce24, full tag16. Stored bytes=`nonce24 || ciphertext[len(m)] || tag16`. Open rejects below40 bytes and verifies exact AAD/tag before returning plaintext. |
| Digest | SHA-256, full32 bytes. A bare digest is neither owner authentication nor a freshness anchor. |
| MAC | HMAC-SHA-256, full32-byte tags, using separate derived keys. Verification and already computed tag comparison use the dependency's constant-time operations. |
| Randomness | `getrandom::fill`; errors fail closed and zero partial output. Fresh root32, per-version content key32, nonce24 and identifiers/salts are requested from this provider. Host/VM RNG qualification is separate. |

The XChaCha construction has an [expired IETF draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt), rather than a finalized XChaCha RFC. The selected RustCrypto source (`../research/prototype-dependencies/chacha20poly1305/source/src/lib.rs`) says so explicitly. Its underlying ChaCha20-Poly1305 construction is documented in [RFC8439](https://www.rfc-editor.org/rfc/rfc8439.html). This is not a claim of NIST/FIPS approval or of a validated module.

## P2 canonical native objects

The exact implementations are [format.rs](../crates/fogvault/src/format.rs) and [index.rs](../crates/fogvault/src/index.rs). SQLite is the experimental native adapter, not an interchange format. Native backups retain the original native policy and encrypted objects; decoded-record exports are a different artifact.

### Password descriptor, 130 bytes

| Offset | Width | Field |
| --- | ---: | --- |
| 0 | 8 | `FGVP0002` |
| 8 | 2 | format2 |
| 10 | 2 | suite1 |
| 12 | 2 | KDF1 |
| 14 | 4 | Argon2 memory KiB |
| 18 | 4 | Argon2 passes |
| 22 | 4 | lanes1 |
| 26 | 16 | vault ID |
| 42 | 16 | salt |
| 58 | 72 | root AEAD: nonce24, encrypted root32, tag16 |

Root-wrap AAD=`F(b"fogvault/prototype/root-wrap/v1") || descriptor[0..58]`; key is the admitted Argon2 result. The complete descriptor hash is subsequently authenticated by the head. P1 `FGVP0001`/format1 remains only for historical component fixtures; no implicit migration is selected.

Immutable content context is `C = SHA256(F(b"fogvault/prototype/context/v1") || content_format_u16 || suite1_u16 || vault_id16)`. P2 and P3 both use content format2. Mutable password salt, KDF, access policy and wrapper bytes are deliberately excluded from `C`, allowing credential rewrap without changing every record. Their **complete descriptor** is bound by the current head instead.

Root subkeys are `D(root,vault_id,b"record-key-wrapping")`, `D(root,vault_id,b"head-authentication")` and `D(root,vault_id,b"operation-identity")`. The retained session normally holds these derived keys, not a persistent raw root. Fresh approved root reauthentication is required for operations that rebuild wrappers.

### Record envelope and body

| Offset | Width | Field |
| --- | ---: | --- |
| 0 | 8 | `FGVR0002` |
| 8 | 16 | record ID |
| 24 | 8 | revision, `1..=i64::MAX` |
| 32 | 72 | AEAD-wrapped fresh content key32 |
| 104 | 8 | complete body-AEAD byte length |
| 112 | variable | body AEAD |

For each purpose, `A(p)=F(p) || C32 || vault_id16 || record_id16 || revision_u64`. Wrapped-key purpose is `b"fogvault/prototype/record-wrap/v1"`; body purpose is `b"fogvault/prototype/record-body/v1"`. The former uses the root-derived wrapping key; the latter uses the fresh content key. Version two does not rename these existing domains; `C` binds the content version.

Body plaintext is `metadata_len_u64 || metadata || payload_len_u64 || payload`. Lengths, inner and outer exact EOF, ID, revision, magic and caller limits are checked. Complete native overhead is168 bytes in addition to metadata+payload. New encryption generates a content key and both nonces afresh. Sensitive metadata is encrypted. Schema stays application-owned; there is no invented DataFog record schema.

### Head, 129 bytes; public canonical nodes

Head fields in order: generation_u64; latest_request_id16; keyed_operation_digest32; record_count_u64; root_present_u8; root_hash32; HMAC32. The prefix before the MAC is97 bytes. MAC input=`F(b"fogvault/prototype/index-head/v2") || SHA256(complete_descriptor) || prefix97`.

Absent root requires count0 and zero hash; present root requires positive count/generation. Count must fit caller policy. Exact width, MAC and canonical flags are mandatory. There is no prior-head pointer; credential/root epochs are bound through the descriptor, not extra head fields.

Node hash=`SHA256(b"fogvault/prototype/index-node/v2\0" || exact_node_bytes)`:

| Node | Exact public bytes |
| --- | --- |
| Leaf57 | tag0_u8; record_id16; revision_u64; SHA256(complete_encrypted_envelope)32 |
| Branch82 | tag1_u8; split_bit_u8; canonical_prefix16; left_hash32; right_hash32 |

Split bits are0..127; suffix bits from the split onward are zero in the prefix; child branches have strictly increasing split positions, correct prefix/direction and distinct child hashes. A fetched node must match the expected hash and canonical shape. Missing committed nodes/rows are integrity errors; an authenticated absence is different from a missing committed object. Tree paths contain at most129 nodes. Exact full membership also requires record/node counts; it is not established by one successful point read.

## P3 access descriptor and root paths

The exact additional codecs are [format/access.rs](../crates/fogvault/src/format/access.rs), [access.rs](../crates/fogvault/src/access.rs) and [lifecycle/access.rs](../crates/fogvault/src/lifecycle/access.rs). Admission comes from trusted host configuration: explicit profiles/provider identities and descriptor/slot/provider-blob bounds. Saved policy cannot enroll a provider or raise limits by itself. Current provider execution evidence is synthetic/native; flags are declarations, not hardware attestation.

P3 is the ordered binary frame below; no CBOR/Serde representation is selected. Widths in parentheses are bytes; all length/count fields are exact:

```text
"FGVP0003"(8), credential_version3(u16), suite1(u16), content_format2(u16),
vault_id(16), root_epoch(u64), policy_epoch(u64), access_profile(u8),
password_slot_id(16), password_revision(u64), KDF1(u16),
memory_KiB(u32), passes(u32), lanes1(u32), salt(16),
password_wrapper_length(u16), password_wrapper,
device_count(u32),
each sorted device:
  slot_id(16), slot_revision(u64), provider_id(16), key_id(16),
  device_bound(u8), nonexportable(u8), protected_seed_length(u32),
  protected_seed, root_wrapper_length(u16), root_wrapper,
recovery_present(u8),
if present: recovery_slot_id(16), recovery_revision(u64), root_wrapper(72),
EOF
```

Profile0=`Portable`;1=`PasswordOrDevice`;2=`PasswordAndDevice`. Password wrapper length is72 for profiles0/1 and0 for profile2. Device root-wrapper length is72 for profile1 and112 for profile2. Device slots have strictly sorted unique IDs, do not collide with password/recovery IDs, have nonzero revisions and exact admitted identity/Boolean flags. Profile0 has no devices; profiles1/2 require devices. Policy epoch/password revision are nonzero; initial root epoch0/policy epoch1 are intentional. Parse/re-encode equality, exact EOF and bounded input are required.

Total width is `108 + password_wrapper_len + sum(64 + protected_seed_len + device_root_wrapper_len) + (96 if recovery else0)`. Thus fixture widths276/484/700 follow their actual slot choices and provider blobs. They are **not** production capacities or slot limits.

Let:

```text
PW(p) = F(p) || vault_id16 || root_epoch_u64 || password_slot_id16
        || password_revision_u64 || KDF1_u16 || memory_u32 || passes_u32
        || lanes_u32 || salt16
PC = F(b"fogvault/prototype/provider-seed/v3") || vault_id16
     || root_epoch_u64 || device_slot_id16 || slot_revision_u64
     || provider_id16 || key_id16 || device_bound_u8 || nonexportable_u8
DA = F(b"fogvault/prototype/device-component/v3") || PC
     || SHA256(protected_seed_blob)
RA = F(b"fogvault/prototype/owner-recovery/v3") || vault_id16
     || root_epoch_u64 || recovery_slot_id16 || recovery_revision_u64
```

| Path | Exact protection and authority |
| --- | --- |
| Password, profiles0/1 | `E(Argon2(password,salt), PW(b"fogvault/prototype/password-root/v3"), root32)` |
| Device, profile1 | Independent random slot seed32 is wrapped by the exact admitted provider under `PC`. Core derives `D(seed,vault_id,DA)` and uses `E(derived,DA,root32)`. Enrollment performs an unwrap proof of the generated seed. Provider never receives the root. |
| Password+device, profile2 | The same device wrapper is **inside** `E(password_key, PW(b"fogvault/prototype/password-device-outer/v3") || DA, inner72)`. Both inputs are needed to recover the root through this route; each enrolled device is an alternative device route. There is no password-only root wrapper. |
| Owner recovery, if enabled | Independent random recovery secret32 derives `D(secret,vault_id,RA)` and protects `E(derived,RA,root32)`. Recovery is an explicit alternative root path, independent of normal factors. |

**The nested profile2 construction permits offline password-guess testing through the outer AEAD tag without a device.** Its claimed AND property is root access, not device-conditioned password-guess resistance or 2SKD. Selecting a different combiner to obtain the latter would be a substantive construction change requiring its own exact proof and review. Recovery also intentionally bypasses normal AND factors; API restrictions after recovery are not another cryptographic factor.

The owner recovery kit is exactly80 bytes: `b"FGVRKEY3" || vault_id16 || slot_id16 || root_epoch_u64 || secret32`. It is secret access material, not encrypted data backup. Export is explicit and secret-owned; no vendor reset is selected. Root unwrap alone does not authenticate all policy: the complete P3 descriptor hash is authenticated by the head, and a coherent complete startup audit plus publication checks precedes usable authority. This catches tampering even in an unused wrapper.

Removing a slot or changing a password cannot revoke a retained root, old wrapper, plaintext, export or native backup. Profile transitions and recovery repair require proving the selected target graph, atomic descriptor/head publication and appropriate current root-path authority. Provider failures do not silently fall back to a weaker profile. Logical lock revokes subsequent publication; ordinary memory cleanup cannot erase caller/OS/crash copies or forcibly cancel a provider that never returns.

## Operation separation, rotation, staging and export

The original P2 diagnostic rotation below remains historical construction evidence. Current [protective transition](protective-transition.md) and trusted control state (`trusted-control-state.md`) supply the post-review fresh-key/restart proposal, including the live publication coordinator required beyond database CAS. Rust age backend screening (`rust-export-backend.md`) now executes actual Rust/Go finality and encrypted staging but **rejects production backend selection** on unsuppressed dependency findings. Passing that screening does not qualify the failed backend or close a freeze gate.

Operation MACs use the root-derived `operation-identity` key. They identify the **latest** operation, not a public password verifier, author signature, history service or unlock route. Request IDs are separate head fields. Inputs are exact bytes, not delimiter-joined labels:

| Operation | MAC input after its framed domain |
| --- | --- |
| `fogvault/prototype/save/v1` | record_id16; expected_revision_present_u8; expected_revision_or_zero_u64; `F(metadata)`; `F(payload)` |
| `fogvault/prototype/delete/v1` | vault_id16; record_id16; expected_revision_u64 |
| `fogvault/prototype/credential-change/v1` | upgrade_u8; immutable_context_hash32; target memory/passes/lanes(u32 each); complete target descriptor hash32 |
| `fogvault/prototype/access-change/v3` | typed intent bytes; complete selected target descriptor hash32 |
| `fogvault/prototype/rotate-p2/v1` | wrapping/full mode_u8; source descriptor hash32; source head hash32, under the **new** operation key |

Access intent kinds are1 enable recovery,2 replace recovery,3 disable recovery,4 add provider(identity IDs and both capability flags),5 remove slot(slot ID),6 select profile(profile code),7 setup,8 recovery repair,9 access password change(target memory/passes). Setup/repair append profile code, recovery Boolean, device_count_u64 and each exact provider/key/flags tuple in request order. These are operation identities; the descriptor and head authenticate the resulting full policy. Fresh password authentication is still required for credential retry; operation tags are not accepted as a shortcut around the KDF.

Password/KDF change rewraps the **same** root under a fresh salt/nonce and authenticates the new descriptor in a new head. Root rotation uses a fresh root and newly derived keys. Wrapping-only rotation reseals existing content keys and preserves the existing body; compromise recovery from exposed content keys must instead use fresh content keys and body encryption. [The P2 helper](../crates/fogvault/src/format/rotation.rs) authenticates the complete source before either transformation. It does not implement P3 target-factor rotation or the maintained resumable operation.

The focused [SQLite rotation proof](../experiments/vault-prototype/tests/rotation.rs) uses an unpublished encrypted checkpoint. Public header=`b"FGVROT01" || version1_u16 || operation_id16 || source_descriptor_hash32 || source_head_hash32 || F(target_descriptor) || ciphertext_length_u64`. Key=`D(new_root,vault_id,b"rotation-staging/v1")`. AAD=`F(b"fogvault/prototype/rotation-checkpoint/v1") || complete_header`, including ciphertext length. The encrypted body contains mode, progress, authenticated source count/generation, staged-root presence/hash, sorted target rows and sorted target nodes. Each blob is `F(blob)`; count/progress fields areu64. Fresh nonce per checkpoint write, resource admission and semantic completion are required. This is a diagnostic checkpoint frame, not a frozen maintained staging protocol.

No staging object activates itself. Resume requires the independently trusted owner-held operation receipt binding source, operation, exact initially prepared target descriptor and rotation mode before target-password work. A receipt supplied only by attacker-controlled staging or an adjacent sidecar establishes no origin; loss refuses resume. Resume also authenticates target credentials; publication requires complete target inventory and one atomic source-descriptor/source-head CAS. A lost completion response remains uncertain until reconciliation. Retained old roots/keys still expose historical copies; no secure-erasure or perpetual receipt claim follows from this proof.

Portable export selects binary **age/v1 native X25519 recipients** and a separate `FVEXP001` consumer-neutral plaintext frame specified in export-payload.md (`export-payload.md`). Multiple recipients are OR routes. Optional passphrase/scrypt admission is a separate, currently disabled profile; SSH/plugins/PQ recipients are not silently enabled. Exports contain decoded opaque records and source claims, **no root, content keys or native credential wrappers**. Native encrypted backup is separate.

The payload has header104 (magic, source vault, descriptor/head hashes, generation, committed count), ordered length-delimited records, and footer41 (tag, count, transcript digest), then exact EOF. Its transcript domain is `b"fogvault/export/payload/v1\0"`; the unkeyed digest is framing integrity, not origin authentication. The independent Go `age`1.3.2 tool proof verifies container interoperability and finality; **no Rust age backend has been selected or qualified**. Maintained export041/import042 and restore activation remain later work.

age recipients authenticate decryption, not the sender. An attacker knowing a recipient can create a valid replacement copying source identity/head metadata. Strong same-vault backup restore therefore requires an independently trusted receipt for the **completed ciphertext digest**, in addition to complete age/payload validation and target authorization. An adjacent checksum file under the same untrusted storage is not an anchor. Lost receipt permits only an explicit owner-accepted unverified data import into a new identity, not silent same-vault restore. Partial authenticated chunks, a complete inner frame without age final authenticated EOF, or an incomplete inventory cannot activate import.

## Key usage, nonce and forgery budgets to approve

The following bounds are engineering derivations under stated assumptions, **not complete proofs of this composition or selected operational limits**. They describe terms the reviewer must combine with primitive/derivation advantages, multi-user accounting, length limits and actual attack access. No persisted key-use counter, global failed-verification counter or fork-wide accounting exists in this candidate.

For `q` independent uniform192-bit nonces generated under the **same key**, the union bound for an exact nonce collision is `q(q−1)/2^193`. Examples: `q=2^32` gives less than`2^-129`; `2^48` less than`2^-97`; `2^64` less than`2^-65`. These are arithmetic examples, not allowed message quotas. The XChaCha draft describes a first128-bit nonce part deriving a subkey and a final64-bit nonce part used with that subkey. The displayed192-bit birthday term is only the exact repeated-full-nonce event; it is not a bound on every HChaCha/subkey collision or full construction advantage. [XChaCha draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt)

The full128-bit tag does **not** justify claiming unconditional forgery probability`v/2^128`. For authenticated input length`L=16*ceil(AAD_len/16)+16*ceil(ciphertext_len/16)+16`, let`n=L/16`. RFC8439's stated Poly1305 term is`n/2^102` for one forgery. A conservative length/attempt budget uses `min(1, sum_i(n_i)/2^102)` within the referenced primitive assumptions, **plus** nonce and ChaCha/HChaCha/derivation terms. It is not a whole-FogVault security theorem. At the consumer's16MiB payload sample with empty metadata, record-body AAD113 bytes and body plaintext16777232 bytes give`n=1048586`, approximately`2^-82` per attempt for this conservative term; `2^32` attempts would give approximately`2^-50`. This illustrates why hostile verification counts and admitted lengths matter, not a predicted practical attack or product threshold. [RFC8439 §2.8/§4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4)

The underlying RFC per-invocation cipher ceiling is`64*(2^32−1)` plaintext bytes. The selected RustCrypto implementation also rejects oversized inputs before cipher counter exhaustion; its exact guard is in cipher.rs (`../research/prototype-dependencies/chacha20poly1305/source/src/cipher.rs`). Caller limits and checked framing must stay within the actual backend limit; a largeu64 wire length does not authorize encryption or allocation. No file-size or future attachment support promise follows from the field widths.

| Key/identifier lifecycle | Accounting that matters |
| --- | --- |
| Fresh record-version content key | One body encryption per newly generated key in the honest normal save/full-rotation construction. A wrapping-only rotation deliberately retains this key/body. Key generation collisions across`r` independent256-bit keys have ideal birthday term`r(r−1)/2^257`; a fresh key is an assumption until host randomness is qualified. |
| Long-lived root-derived wrapping key | Count **all attempted wraps** under that key: committed and discarded drafts, retries that actually encrypt, imported histories, copies/forks and operations in other processes. Generation/count/revision is not that total. Root rewrap does not reset it. |
| Password wrapping key | Fresh salt normally changes the key on credential replacement; profile2 can encrypt multiple device outer wrappers under one password key. Reused salt/password, restored states and independently resumed drafts must not be assumed new keys. Offline guess attempts are not bounded by the API. |
| Device seed-derived and recovery keys | Separate seed/secret and exact purpose/context per slot. Resealing/checkpoints/forks still count every encryption under an unchanged derived key. Synthetic provider RNG/cipher evidence does not qualify hardware or provider-internal nonce management. |
| Staging key | New target root separates it from source keys; every checkpoint rewrite/resume under that same target root increments usage. Deleting a checkpoint does not undo prior use. A copied stage is another branch of the same accounting problem. |
| Head/operation HMAC keys | No nonce. Under ideal PRF assumptions, guessing a full256-bit tag has term`v/2^256`; real analysis includes HMAC/hash and multi-user terms. Unlimited copied stores/verification attempts are not a finite enforced budget. |
| SHA-256 commitments | Ideal collision term for`r` independently modeled values is`r(r−1)/2^257`; second-preimage guessing against a fixed committed digest has term roughly`v/2^256`. These are different games; an unkeyed tree root does not authenticate an owner. |
| Random vault/slot/request identifiers | A128-bit random identifier has ideal collision term`r(r−1)/2^129`. Collisions must reject safely; caller-assigned record IDs carry no random uniqueness guarantee. IDs are not encryption keys. |

The nonce model fails if RNG output is correlated, VM/process snapshots clone state, entropy fails silently, or an implementation repeats a key/nonce. OS requests and failure propagation help; they do not establish independence across every deployed host/fork. Memory zeroization covers ordinary owned buffers, not all register/allocator/OS/browser copies or process aborts. Constant-time primitive comparisons do not prove a whole host/API side-channel bound.

Before freeze, choose and justify per-profile message/byte/verification budgets and a rotation/accounting strategy that remains correct across retries, backups, forks and resumes. A single local counter cannot honestly count independent historical copies. Any claimed cap must say who enforces it and what happens at the boundary. Current finite admission policies and measured workloads are review inputs; they are not universal production caps.

## Fixed fixtures, rejection evidence and remaining vector scope

| Corpus/evidence | What it establishes and what it does not |
| --- | --- |
| [format-vectors.json](../conformance/format-vectors.json), [format_conformance.rs](../experiments/vault-prototype/tests/format_conformance.rs) | Seven independently Python-encoded fixed P1/P2 descriptor/head/node cases plus fixed node hashes. Full truncation, trailing bytes, head tag/key mutation and exact Rust encoding agreement. Descriptor suffixes are **synthetic parse-only wrappers**; not Argon2/AEAD interoperation vectors. |
| [access-vectors.json](../conformance/access-vectors.json), [access_vectors.rs](../crates/fogvault/tests/access_vectors.rs) | 26 fixed P3 cases: seven accepted paths; strict missing-factor/wrong-password rejection; malformed version/suite/profile/context/KDF/length/order/flags/revision; unused-wrapper/head/device tampering; wrong provider/recovery identities or secret. Bytes were captured once from Rust and are never regenerated on verification. Cross-host reuse tests agreement, **not an independently implemented cryptographic oracle**. Synthetic provider key is intentionally public test material. |
| [password-vectors.json](../conformance/password-vectors.json) | Shared byte/text boundary values for Rust, browser and mobile C. It does not qualify every future maintained language binding. |
| [export-vectors.json](../conformance/export-vectors.json), [export_payload.rs](../experiments/vault-prototype/tests/export_payload.rs) | Two valid and ten invalid independent fixed payload frames, all truncated prefixes, checked lengths/policy and independent Rust framing decoder. Go age tool proof additionally covers recipients, wrong identity, tampering, truncation/finality and valid-replacement rejection by trusted receipt. No maintained Rust age backend/import claim. |
| [crypto.rs tests](../crates/fogvault/src/crypto.rs), [rotation tests](../experiments/vault-prototype/tests/rotation.rs) | Key/AAD/tamper/empty-envelope checks, RFC4231 HMAC case, KDF admission; retained-key effects, encrypted checkpoint resume, stale CAS, atomic faults and anchored/unanchored restore. They are focused construction experiments, not an independent cryptographic review. |

The selected RustCrypto source includes upstream Wycheproof data, but its presence in the research tree is not evidence that FogVault's verifier executed those upstream suites. A maintained interoperability/vector plan still needs an independent implementation for native Argon2/HKDF/AEAD wrappers, target-specific backend review and a selected Rust age backend. Do not silently call implementation-captured vectors independent.

## Dependency, feature, license and advisory snapshot

Collected on **October29,2026 at16:57 PDT** with local `cargo-audit0.22.2`, warnings denied, no ignored advisories or target filters, and yanked checking enabled. The reference RustSec database was fetched once and then reused with`--no-fetch`; no FogVault repository operation, application manifest edit, lock change or pin update was performed.

The exact inventory.json (`../artifacts/review-readiness/dependency-audit/inventory.json`) SHA-256 is`e5be7a247536c170200f13420fd69219287aa5a7a9043420dda70cb74341f9dc`. It binds command/exit/stderr and result files, all package metadata and feature/license snapshots, and the advisory database content manifest. This is a point-in-time dependency match report, **not a “secure” clearance**.

| Input | Exact identity/result |
| --- | --- |
| Tool binary | `cargo-audit0.22.2`, SHA-256`b4f48ca2b4b57bde3846f876dbcb6f72c056b27cc86d701413ecdc156f96dfcb`; installation remains local under research/review-dependencies. |
| Database | [RustSec advisory-db](https://github.com/RustSec/advisory-db), revision`ee1a49a2769a24a596afc1c20cb33748d2769586`, tree`af3eaf8699bc8040565a708da432e04f1f19407a`; commit time`2026-10-29T15:05:38+01:00`;1386 advisories. |
| Tracked database content | [advisory-db-files.json](../artifacts/review-readiness/dependency-audit/advisory-db-files.json), SHA-256`0b10a7454c6dd40a226a4dbcbfa0e9a3e70a2662ec175afdfd2fabf1d4e6a09c` of sorted tracked path/length/SHA-256 tuples. |
| Core lock42 packages | SHA-256`1baba4cbf4ae96ba5d966b0add00a1e0283fb36b6708c8da52ad044769d9532d`; audit (`../artifacts/review-readiness/dependency-audit/core.json`):0 vulnerabilities,0 warnings, exit0. |
| Native lock84 packages | SHA-256`cfc53e7bbea4926053d8a8058a287289708858be2b894ae6363881454ca6b31a`; audit (`../artifacts/review-readiness/dependency-audit/native.json`):0 vulnerabilities,0 warnings, exit0. |
| Browser lock48 packages | SHA-256`95a942cc2d996550137e726cccfdef1cd260eb800c875effb63c512ad20ccb6a`; audit (`../artifacts/review-readiness/dependency-audit/browser.json`):0 vulnerabilities,0 warnings, exit0. |
| Mobile lock31 packages | SHA-256`6fc19c5c74dcd1abfadf2abb6c26c6ae19925957f69aa24d99a37fef2e516bd5`; audit (`../artifacts/review-readiness/dependency-audit/mobile.json`):0 vulnerabilities,0 warnings, exit0. |

Exact recorded commands are in commands.json (`../artifacts/review-readiness/dependency-audit/commands.json`). Metadata collection used `cargo metadata --offline --locked --format-version 1 --manifest-path PATH`; metadata command records (`../artifacts/review-readiness/dependency-audit/metadata-commands.json`) bind manifests/locks/results. Resolved package counts30/77/48/31 differ from lock membership where inactive optional/target packages remain locked. The audit covers **all locked packages**; current metadata resolves its own feature graph. Missing license metadata for an inactive locked package remains null, not approved.

The standalone [dependency verifier](../scripts/verify-dependency-audit.py) executes fresh audits for all four current locks using that pinned tool/database, `--no-fetch --deny warnings` and no suppression. Run `python3 scripts/verify-dependency-audit.py --output FRESH_JSON`. Its `fogvault-dependency-audit-proof/v1` report names nine executed checks, hashes current source/tool/database/lock/manifest inputs, rejects stale or changed baseline evidence and checks input stability after execution. A changed database, tool, manifest or lock requires explicit recollection/review; it cannot silently reuse this snapshot. Findings and raw command output are retained on a failed fresh audit. Neither this wrapper nor a passing main stage closes specialist review.

| Role | Exact direct selection / relevant resolved features |
| --- | --- |
| Core KDF | `argon2=0.6.0`, default features off;`alloc,zeroize`. |
| Core cipher | `chacha20poly1305=0.11.0`, default features off;`alloc,zeroize`. Resolves`chacha20=0.10.2` with`cipher,xchacha,zeroize`;`poly1305=0.9.1`. Reduced-round variants are not enabled. |
| Derivation/authentication/hash | `hkdf=0.13.0`;`hmac=0.13.0` with`zeroize`;`sha2=0.11.1` resolves`alloc,default,oid`. |
| Secret memory / entropy | `zeroize=1.9.1`;`getrandom=0.4.3`. Browser enables`getrandom/wasm_js`; native/mobile use their OS backend. |
| Native adapter | `rusqlite=0.40.2`, default features off,`bundled`; resolves`libsqlite3-sys=0.38.2`, bundled C SQLite. RustSec matching is not separate SQLite C advisory or power-loss qualification. |
| Native consumer/tests | `datafog-core=0.5.0-beta.3`, default features off, dev dependency only; other test/build dependencies are recorded in the full inventory. Its transitive older HMAC/SHA versions are separate instances, not replacements for core pins. |
| Browser bridge | `wasm-bindgen=0.2.127`;`js-sys=0.3.104`. Current resolved js-sys features include`default,std,unsafe-eval`; feature presence does not prove eval execution or extension CSP qualification. Exact binding/tool/runtime review remains required. |
| Diagnostic API | Native prototype enables core`experimental-codecs`; browser/mobile use ordinary core APIs, browser also enables`web`. These unpublished package features are not a maintained release matrix. |

The saved per-package lists contain exact declared SPDX/license expressions and enabled features: core (`../artifacts/review-readiness/dependency-audit/core-packages.json`), native (`../artifacts/review-readiness/dependency-audit/native-packages.json`), browser (`../artifacts/review-readiness/dependency-audit/browser-packages.json`), mobile (`../artifacts/review-readiness/dependency-audit/mobile-packages.json`). Licenses include alternative MIT/Apache choices, Unicode notices and native transitive exceptions/other permissive declarations; the root local packages currently have no declared license. This is inventory, not completed legal/license notice clearance or a release SBOM. Research source licenses and future package redistribution need their own chosen obligations.

The Go age tool's exact release/archive/binary/license provenance is in [its provenance.json](../research/review-dependencies/age-v1.3.2/provenance.json). It is an independently exercised container tool, not part of the Rust Cargo dependency graph or a selected production backend. No Rust age advisory/feature qualification is implied.

No vulnerability/warning matched this pinned database in these four locks. Unknown vulnerabilities, compromised releases, C/JS/platform advisories, build scripts, unsafe code, compiler/tool trust, target-specific side channels and the actual composed construction remain separate review obligations. Rerun after dependency/tool/database changes and bind the new identities to the review evidence; never suppress a finding to preserve a passing packet.

## Questions that require specialist disposition before freeze

1. Accept public opaque-ID/revision/digest index leakage and latest-head semantics, or require a revised encrypted-index/history construction? Reconcile the architecture draft explicitly either way.
2. Approve the full P2/P3 domain/AAD/descriptor-head composition, especially mutable-policy exclusion from record context, root-epoch separation, unused-wrapper authentication and cross-profile transitions. Are any context/key fields missing or unnecessarily duplicated?
3. Approve profile2's nested AEAD AND property **with offline password verification available**, or select a different combiner with an explicit device-conditioned guessing requirement? Approve the independently powerful recovery OR route and exact repair authority.
4. Approve provider seed wrapping/context and capability requirements after actual target provider review. What evidence is required for device locality, nonexportability, reauthentication and sync/backup behavior? Current synthetic flags do not answer this.
5. Derive complete multi-user nonce/forgery/commitment bounds and set enforceable message/byte/attempt/rotation rules, including fork/backup/resume accounting, entropy faults and backend per-message limits. Which claims are permitted when independent offline copies cannot be counted?
6. Review root-vs-content compromise recovery, target wrapper replacement, encrypted checkpoint completeness, uncertain publication and freshness/restore receipt rules. Retained historical copies and compromised live hosts must remain explicit limitations.
7. Select and qualify the maintained Rust age backend/profile and independent native wrapper vectors; review recipient OR semantics, hostile scrypt admission if enabled, age finality, trusted export receipts and import authorization.
8. Review the actual dependency/source/feature graph and target implementations in addition to advisory matching. Identify release-blocking license/notice, side-channel, backend, binding and durability obligations without calling this point-in-time audit independent security approval.

This packet makes those questions concrete enough to review. It does not close FVW-061, FVW-048, G-CRYPTO/G-FORMAT/G-INDEX/G-BUDGET/G-ADAPTER/G-BINDING, or authorize design freeze, production support, a GitHub repository or a commit.
