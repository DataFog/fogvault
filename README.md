# FogVault

FogVault is an independent Rust vault being built for embedding in other software.
DataFog Core is one consumer; the vault core has no DataFog, database or language
binding dependency.

**Experimental engineering baseline.** The crate is unpublished (`0.0.0`,
`publish = false`). APIs and saved bytes may still change. This is not a supported
production vault, security approval or certification.

## Current design

One portable Rust `Engine` owns keys, sessions, authenticated record/index checks,
credential changes and uncertain-operation outcomes. Storage adapters and thin
bindings supply host transactions and lifecycle behavior.

Normal creation uses credential grammar 3, content format 3 and root epoch zero.
The core supports explicitly admitted password-only, password-or-device and
password-and-device profiles, with optional recovery. Routine password/KDF
maintenance preserves content keys; protective replacement uses fresh root and
content keys. Older formats remain explicit diagnostic fixtures.

| Path | Role |
| --- | --- |
| [`crates/fogvault/`](crates/fogvault/) | Portable lifecycle core and default API boundary. |
| [`experiments/vault-prototype/`](experiments/vault-prototype/) | SQLite adapter and exact DataFog Core `0.5.0-beta.3` consumer tests. |
| [`experiments/browser-prototype/`](experiments/browser-prototype/) | WASM/Worker/IndexedDB transaction experiment. |
| [`experiments/mobile-prototype/`](experiments/mobile-prototype/) | In-memory C ABI and iOS simulator feasibility probe. |
| [`conformance/`](conformance/) | Behavior contracts and public synthetic fixtures. |
| [`scripts/`](scripts/) | Verifier, independent decoders and measurement runners. |

## DataFog Core compatibility

The minimum integration baseline is **DataFog Core `0.5.0-beta.3`**. The native
development tests deliberately pin `=0.5.0-beta.3` so upgrades do not erase that
coverage. This test pin is not a runtime dependency or a maximum supported
version. DataFog Core v1 will be added as a separate tested consumer when
available; v1 compatibility has not yet been verified.

The maintained package is the next delivery stage. Ordinary registered native
writes have restart/fencing proofs. Native bulk protective publication, supported
bindings/adapters, qualified exports/imports and release controls remain work.
Browser and mobile probes do not establish physical-device, secure-provider or
production storage qualification. The Rust age export experiment remains rejected
for production selection.

## Run the checks

From this checkout, run the core tests:

```sh
cargo test --locked --manifest-path crates/fogvault/Cargo.toml --no-default-features
```

The complete engineering profile is:

```sh
python3 scripts/bootstrap-reference-db.py
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 -u scripts/verify-vault.py --with-feasibility
```

The explicit bootstrap fetches the pinned public RustSec Git objects into ignored
`local-only/` state. Reviewed advisory files stay in place without a nested Git
repository. Audit runners make no database fetches.

The optimization setting changes test compilation; required assertions and checks
remain enabled. The profile retains 187 required Rust cases, four default-API
compile-fail checks, independent fixed-vector decoders, exact published DataFog
Core `=0.5.0-beta.3`, growth/resource checks and browser/mobile/control experiments.
A passing current run requires all 29 stages and stable declared source inputs.
Reports are generated under `experiments/vault-prototype/evidence/verifier-runs/`.
An earlier report is not a substitute for running this checkout.

The full local profile requires Rust/Cargo and the configured WASM/iOS/Android
targets, Python, Node, matching `wasm-bindgen` CLI, Playwright with Chromium/WebKit,
and macOS/Xcode with an iOS simulator runtime. Pinned audit/interoperability inputs
must also be present at the verifier's declared paths. Missing required tooling
or targets fail explicitly; the runner does not silently skip them. This is a
development-machine profile, not a claim of production support on every target.

## Security and licensing

Use synthetic data while evaluating this candidate. Physical-platform budgets,
real device/recovery providers and qualified independent security review remain
open before supported security claims.

Report a suspected vulnerability through this repository's private vulnerability
reporting feature rather than a public issue containing sensitive details.

FogVault's original code, documentation and tests are licensed under the
[MIT License](LICENSE). Third-party source, tools and fixtures retain their own
licenses and notices; FogVault's license does not replace those obligations.

See [checkout notes](PUBLIC-CHECKOUT-NOTES.md) for included evidence and tool scope,
and [third-party notices](third-party/THIRD_PARTY_NOTICES.md) for their separate terms.
