# FogVault

FogVault is an independent Rust vault for embedding in other software. Native
Rust and browser integrations are equal-priority deliverables and share one
Rust engine for keys, sessions, authenticated records and vault state.

**Current status:** maintained implementation at unpublished version `0.0.0`.
APIs and saved bytes remain provisional. Independent security approval,
physical-platform qualification and a supported production release are separate
milestones. Read the [delivery and support contract](docs/maintained.md) before
choosing a host profile.

| Package | What it provides |
| --- | --- |
| [`fogvault`](crates/fogvault/) | Portable vault engine, resource admission and provider contracts. |
| [`fogvault-native`](crates/fogvault-native/README.md) | Registered SQLite storage, durable ordinary operations, protective device/recovery replacement and fresh restore. |
| [`@datafog/fogvault-browser`](packages/browser/README.md) | TypeScript/WASM SDK, owned Workers, IndexedDB storage, website and browser-extension integrations. |
| [`fogvault-backup`](crates/fogvault-backup/) | Bounded age/v1 transport, decoded snapshot framing and encrypted import staging. |

The maintained packages implement create/unlock/read/write/delete, bounded
inventory reads, password and KDF changes, admitted device access, owner recovery,
protective replacement and backup/fresh restore. Real device providers remain a
trusted host integration; a capability declaration is not hardware attestation.

## Start with native Rust

Use the repository as a Git/path dependency while the crates are unpublished.
For a local checkout, an embedding crate can use:

```toml
[dependencies]
fogvault-native = { path = "../fogvault/crates/fogvault-native" }
```

Run the standalone synthetic consumer from this repository:

```sh
cargo run --locked --manifest-path crates/fogvault-native/Cargo.toml --example native_vault
```

It proves create → unlock → save → lock → reopen → read without a DataFog
dependency. Real applications must establish the independently protected native
control namespace described in the [native guide](crates/fogvault-native/README.md).
Pin a reviewed commit when using a Git dependency.

## Start with the browser SDK

With the WASM Rust target and matching `wasm-bindgen 0.2.127` CLI installed:

```sh
npm ci --ignore-scripts --prefix packages/browser
npm run build --prefix packages/browser
npm test --prefix packages/browser
npm run test:types --prefix packages/browser
```

Run `npm pack` in `packages/browser/` to create an installable tarball. It contains
the JavaScript entry, TypeScript declarations, Worker, WASM and third-party
notices. The [browser guide](packages/browser/README.md) covers installation,
resource policies, device callbacks, recovery and backup/restore.

Generate the working website and extension examples:

```sh
node packages/browser/scripts/build-examples.mjs chrome
node packages/browser/scripts/build-examples.mjs firefox
```

The browser adapter uses IndexedDB behind FogVault's API. It is an explicit
offline **unanchored** profile: detecting replacement of the entire vault by an
older valid copy requires separately trusted state.

## Compatibility and checks

DataFog Core **`0.5.0-beta.3` is the minimum integration baseline**. The exact
published `=0.5.0-beta.3` test pin preserves that floor; it is neither a runtime
dependency nor an upper version limit. DataFog Core v1 will be verified separately.

The [CI matrix](.github/workflows/maintained.yml) targets native Windows, macOS and
Linux; website SDK execution in Chrome, Edge and Firefox; and packaged Chromium/
Firefox extension tests. Windows/Linux/Edge acceptance is pending execution of
that matrix. Additional Safari/WebKit qualification remains deferred; existing
WebKit regressions remain required. Local test results do not qualify every host.

Run the complete development-machine profile with its documented prerequisites:

```sh
python3 scripts/bootstrap-reference-db.py
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 -u scripts/verify-vault.py --with-feasibility
```

The verifier requires named behaviors, checks actual execution, and rejects
source changes during a run. It retains the original vectors, consumer and host
regressions alongside the maintained package tests. The full profile includes
macOS/Xcode simulator and pinned Apple-arm verification tools; it is not a
universal CI command. See [checkout notes](PUBLIC-CHECKOUT-NOTES.md).

## Security and license

Report suspected vulnerabilities through this repository's private vulnerability
reporting feature. Examples use synthetic credentials and data.

FogVault's original code, documentation and tests use the [MIT License](LICENSE).
Third-party material retains its own terms. See [dependency scope](docs/dependency-scope.md),
[retained tool notices](third-party/THIRD_PARTY_NOTICES.md), and the browser
artifact's bundled notices. The dated audit and passing tests do not establish
cryptographic approval or certification.
