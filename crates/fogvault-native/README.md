# FogVault native Rust package

`fogvault-native` owns the SQLite persistence adapter for the shared `fogvault`
engine. It provides a maintained embedding surface for registered native vaults.
The crate remains unpublished (`0.0.0`, `publish = false`); independent security
review and physical-platform/power-loss qualification remain release work.

## Public API

- `Host`: create/open an independently protected host namespace; create/open a
  registered vault with explicit limits, KDF policy and optional device/recovery
  admission.
- `Vault`: unlock, read, save, delete, enumerate, audit, lock, change passwords,
  upgrade KDF parameters and reconcile uncertain point operations.
- `AccessOptions`: password-only, password-or-device or password-and-device
  selection, explicit provider admission and optional owner recovery.
- `PreparedProtection` / `ProtectionTicket`: full-content device/recovery
  replacement with fresh root/content keys and exact durable restart recovery.

Passwords are exact bytes. The host is responsible for foreign copies and for
clearing its own password/plaintext buffers. Plaintext records use the shared
core's zeroizing owner. Session tokens are revoked by lock.

The default API exposes no fault-injection controls or writable legacy-format
constructors. The `diagnostics` feature exists for the compatibility/measurement
harness and is not a supported application mode. Cryptographic primitives and
raw root keys are not exported by the normal package.

## Storage and trust

The vault file is untrusted storage. `Host` requires a caller-selected control
namespace whose OS access policy is independently protected from an attacker
who can replace vault/staging files. A separate filename or mode flag does not
establish that protection. Put the namespace under a protected parent and apply
appropriate principal/ACL isolation for the embedding application.

Ordinary operations retain their exact encrypted targets, then use the live
control coordinator and an atomic SQLite transaction. Writes return success only
after the exact target is committed and confirmed. Unknown outcomes remain
unknown; ordinary operations stay blocked until exact reconciliation.

SQLite `FULL` transaction/file flushing and process-crash/reopen behavior are the
native contract. POSIX additionally applies directory fsync barriers. Windows
validates the host directories but does not claim a portable directory-fsync or
power-loss guarantee. Real power-cut and device/provider qualification remain
separate evidence requirements on every platform. Windows/macOS/Linux CI names
the executed profiles; a local macOS run alone does not qualify the other hosts.

## Protective replacement

1. Authenticate the current vault, or enter its restricted owner-recovery path.
2. Prepare device/recovery replacement. Retain the returned new recovery key and
   persist `draft.ticket().encode()` in trusted caller storage **before** commit.
3. Call `commit_protection(&mut draft)`. It transforms encrypted records one at a
   time into protected SQLite staging, preserving record IDs and revisions.
4. The adapter re-audits the complete target, retains exact source/target bytes,
   records submission authorization and atomically publishes the full graph.
5. If the outcome is unknown, retain the draft and retry the exact operation.
   After process restart, reopen with explicit source/target admission and call
   `resume_protection` using the trusted ticket plus source and target credentials.
6. An unsubmitted preparation can be abandoned with its exact owner ticket. A
   submitted operation cannot be declared aborted merely because the source is
   still visible. After abandonment, discard the old secret-owning draft.

Recovery candidates have no ordinary read/session authority. After a successful
replacement, the returned receipt reports `FreshRootAndContentKeys`. Historical
copies remain readable by anyone who already had their old factors or plaintext.
The staging file contains encrypted source/target records and an encrypted
checkpoint, never passwords or unwrapped root/content keys. Cleanup follows
confirmed completion; a failed cleanup does not undo a committed replacement.

`ProtectionTicket::from_trusted_bytes` requires an independently trusted source.
Do not take a ticket or provider-admission policy from an untrusted vault file.

## Checks

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=2 cargo test --locked --manifest-path crates/fogvault-native/Cargo.toml --features diagnostics
cargo clippy --locked --manifest-path crates/fogvault-native/Cargo.toml --all-targets --features diagnostics -- -D warnings
```

The compatibility harness still pins published DataFog Core `=0.5.0-beta.3` as a
minimum regression baseline. The vault has no runtime DataFog dependency. Core
v1 will be verified separately. Original code is MIT; dependency/tool notices
retain their own terms.

## Run an independent consumer

```sh
cargo run --locked --manifest-path crates/fogvault-native/Cargo.toml --example native_vault
```

The example uses synthetic public credentials in temporary directories and proves
create → unlock → save → lock → reopen → read. It has no DataFog dependency.
Real embeddings must establish the independently protected host namespace.

Use `change_credentials_with_access` to change passwords or strengthen an
admitted KDF under a device-required profile. Password-only convenience methods
do not bypass a required device operation. The returned key effect is explicit.
