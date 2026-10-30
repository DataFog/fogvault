# Native and browser delivery contract

FogVault provides two equal-priority developer packages: a native Rust adapter
and a TypeScript/WASM browser SDK. Both use the same Rust engine. The current
unpublished `0.0.0` implementation is available through a repository checkout
and a locally packed browser tarball; registry publication and production
qualification are separate milestones.

## Package boundaries

| Component | Responsibility |
| --- | --- |
| `crates/fogvault` | Keys, sessions, authenticated state/index, resource policy, credential and protective-operation authority. |
| `crates/fogvault-native` | Registered SQLite persistence, live writer fencing, durable exact targets, restart reconciliation and native restore publication. |
| `crates/fogvault-wasm` | Thin bindings to the shared core, including asynchronous provider continuations. |
| `packages/browser` | Typed owner API, Worker transport/lifetime, IndexedDB transactions, website and extension examples. |
| `crates/fogvault-backup` | Standard age/v1 X25519 transport, `FVEXP001` snapshot framing and encrypted import staging. |

The compatibility experiments consume these implementations. They retain legacy
fixtures and fault injection without making those controls part of the supported
native or browser owner API. Mobile remains a separate in-memory ABI feasibility
probe and is not a durable mobile SDK.

## Implemented workflows

Both packages provide:

- Create, unlock, authenticated read/save/delete, bounded inventory enumeration,
  lock/close and uncertain-outcome reconciliation.
- Password changes and admitted KDF upgrades. Device-required profiles retain
  their device requirement during these operations.
- Explicitly admitted password-only, password-or-device and password-and-device
  access, provider-bound enrollment, and optional owner recovery.
- Explicit unchanged-key maintenance versus fresh-root/full-content protection.
  Named lost-device replacement excludes the lost provider/key identity.
- Full-record protective replacement and recovery, preserving record IDs and
  revisions in the same vault. Historical copies remain readable by holders of
  their old factors or plaintext.
- Encrypted data export and fresh restore with explicit origin and resource policy.

A public API entry is not evidence that every provider configuration or platform
is qualified. Unsupported capabilities reject explicitly. Password fallback does
not satisfy a device-only or password-and-device request.

## Storage and authority

Native uses SQLite with a caller-established, independently protected control
namespace. That namespace must be protected from the attacker who can replace
vault/staging files. A different filename or directory alone is not isolation.
Writes retain exact targets and use a live control fence around publication.
SQLite file flushing and process-crash/reopen behavior are tested; POSIX directory
barriers do not create a portable Windows directory-fsync or power-loss promise.

Browser uses an owned module Worker and IndexedDB. It is an **unanchored offline
profile**. Authentication detects missing, replaced or modified objects relative
to the accepted head, but an older valid whole-database copy needs separately
trusted state to be detected. Successful IndexedDB completion is the publication
boundary with a strict durability hint. Quota, eviction, real power cuts and
physical-device budgets need their own qualification.

An outcome that may have committed remains `OutcomeUnknown`. Retain its request
identity and reconcile the exact operation; do not infer rollback from a lost
reply. Native protective tickets must come from trusted caller storage. Browser
owners must survive transient UI loss through explicit reopening/reconciliation.

## Provider boundary

Native providers use typed wrapping/unwrapping operations. Browser providers use
asynchronous callbacks carrying the same Rust-generated context and independent
slot seed. Root keys and password-derived wrapping keys remain in Rust owners.
Jobs are bound to their operation, provider, phase and source state; cancellation
and late replies cannot grant new authority.

The host must qualify its declared `NonExportableOperation`, key identity and
device-binding/nonexportability properties. Synthetic test providers establish
API and lifecycle behavior, not actual hardware enforcement. The SDK does not
turn a software WebCrypto key into a hardware-backed device claim. Caller-owned
plaintext, strings and foreign copies remain the caller's cleanup responsibility.

The device-required profile requires both factors to unlock the root. Its outer
password wrapper still permits offline password guesses at the admitted KDF
cost; it is not a claim of device-secret-based guessing resistance.

An owner recovery kit is an independent root-unlock secret. The SDK restricts
its use to repair, but a kit holder using other software can decrypt the vault.
That workflow restriction is not cryptographic read denial to the kit holder.

## Backup is a data transfer

The backup's access policy is its independent age X25519 recipient. It is a
**decoded data snapshot**, not a raw SQLite/IndexedDB backup carrying the original
password, device and recovery wrappers. Changing source credentials does not
revoke an already created export or its recipient key.

A trusted completed-ciphertext digest must arrive outside the archive attacker's
control. A downloaded adjacent sidecar is not origin proof. The other supported
mode is explicit owner acceptance of unverified source origin; its result never
claims verified origin. Complete age and payload finality are required before
records can be installed.

Restore creates a fresh password-protected vault identity. Record IDs/data are
retained, record revisions start at one, and existing destinations are not
overwritten. Native/browser opaque-record adapters reject nonempty application
schema identifiers rather than discard them; the generic transport preserves
schema fields for a consumer that supplies an explicit mapping.

The collecting restore path requires an admitted full-snapshot memory budget.
Its logical data-byte accounting excludes allocator overhead, runtime state and
foreign copies. Browser backup has an explicit collection policy as well. Native
export streams a coherent authenticated source snapshot. Same-vault protective
replacement is a different workflow and retains existing record revisions.

## Target and evidence matrix

| Delivery target | Verified engineering evidence | Remaining qualification |
| --- | --- | --- |
| Native Windows, macOS and Linux | All three [native CI jobs passed](https://github.com/DataFog/fogvault/actions/runs/41036629415): Core, maintained/retained adapter tests, backup and private-API probes. | Physical-device/provider and power-loss qualification. |
| Website SDK: Chrome, Firefox and Edge | All three [browser CI jobs passed](https://github.com/DataFog/fogvault/actions/runs/41036629415), with every one of the 22 required SDK cases and matching source hashes. | Physical-device budgets and supported-version floors. |
| Chromium MV3 and Firefox extensions | Both actual unpacked/temporary-extension CI tests passed with zero skips/flakes. | Signed store installation is a separate claim. |
| Safari/WebKit | Existing regression profile retained. | Additional qualification is deferred. |

The complete local verifier passed all 35 required stages and 226 named required
behavior cases on commit `fbfd2be36469b76367cdb093f443d278e7a219e5`.
All seven jobs in the final CI run passed on that same implementation revision.
The earlier run at `f16c4f0bda91fc3a31c0f12b717f8d2f5932c226` is retained with
its Edge startup failure. The intervening commit changes only test HTTP serving,
CI triggers and the source inventory, with no vault/package implementation changes. The browser reports
capture source hashes and actual browser user agents. Edge testing confirmed
Windows' default `.mjs` media type was `text/plain`; the test server now sets
explicit JavaScript/WASM media types rather than inheriting registry settings.
The complete verifier report SHA256 is
`db388f89b2af86672dcbcaeb07bc26519029e9c47bd323b47009638aabafb6e4`.
The native package also built with its declared minimum Rust 1.89 and default
features. Independent consumers passed both clean source-archive extraction and
installation directly from the public Git repository.

The [workflow](../.github/workflows/maintained.yml) names the exact CI images and
toolchain. A local pass cannot substitute for another OS/browser. Supported
physical-device/provider floors, cryptographic/implementation specialist review,
real power-loss evidence and final format/API compatibility approval remain open.

Playwright uses [bundled Chromium for unpacked extension automation](https://playwright.dev/docs/chrome-extensions)
because Chrome/Edge removed the required side-load flags. Firefox uses
[temporary development installation](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/).
Neither is signed store-install qualification. The shipped examples keep vault
ownership in a privileged extension page; background contexts hold no keys and
provide no external/content-script decryption bridge.

## Compatibility and distribution

DataFog Core `0.5.0-beta.3` remains the minimum integration baseline with the exact
published beta.3 regression pin. It is a test consumer, not a runtime dependency
or a version ceiling. Core v1 must gain separate verified coverage.

Use Git/path dependencies for Rust and `npm pack` output for the browser while
packages remain unpublished. For crates.io, the localized dependency corrections
must first be upstreamed or published as distinct fork packages: versioned path
overrides alone do not preserve this corrected graph in a registry publication.
See [dependency scope](dependency-scope.md) and the package guides for exact build
and application integration commands.
