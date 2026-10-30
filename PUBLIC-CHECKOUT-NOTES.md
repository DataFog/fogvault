# Public checkout and verification inputs

This curated tree contains the maintained native/browser implementations and the
regression harnesses that exercise the shared Rust engine. The package entry is
[README.md](README.md); support and feature semantics are in
[the delivery contract](docs/maintained.md).

## Included material

- The portable engine, maintained native/WASM/browser/backup packages, examples,
  tests and locked dependency graphs.
- Synthetic conformance fixtures, including intentionally public test keys.
- The retained synthetic P1 SQLite fixture used only to prove legacy rejection.
  Its historical `evidence/` path is an exact exception, not a published run log.
- Exact published DataFog Core `=0.5.0-beta.3` development/test coverage for the
  minimum integration baseline. Core v1 is not yet verified.
- Selected audit, decoder, interoperability and vendored-source provenance inputs.
- Separate third-party notices; FogVault's MIT license does not relicense them.

Private reviewer attachments, full reference repositories, tracker exports, old
verifier runs, large review ZIPs and build caches stay outside the public file set.
Selected historical audit metadata retains its original host paths because its
bytes are pinned evidence. The age download provenance omits an expired signed
redirect while retaining the canonical public URL and archive/executable digests.

The two retained `spec/` notes are historical construction inputs to independent
checks. They are not the current complete product specification. Private cross-
links are rendered as reference paths. Use current package guides, tests and
[delivery scope](docs/maintained.md) for present behavior.

## Full local verification

The full profile requires Rust/Cargo, configured WASM/iOS/Android targets,
Python with `cryptography` Argon2id support, discoverable libsodium, Node/npm,
`wasm-bindgen 0.2.127`, the pinned browser tools and installed browser binaries.
Its simulator checks require macOS/Xcode and an installed iOS simulator runtime.
The bundled audit/age executables target Apple arm64 and are verification tools,
not product runtime binaries.

```sh
python3 scripts/bootstrap-reference-db.py
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 scripts/quality.py check --profile full
```

The explicit bootstrap fetches the pinned public RustSec commit into ignored
`local-only/verifier-tools/` state. The vendored advisory files have no nested Git
repository. Audit runners do not fetch, suppress findings or silently skip a
missing required capability. Cargo/npm may fetch normal dependencies; this is
not an offline dependency bundle.

Named case inventories and before/after source identities guard behavior drift.
Fresh executed reports are the proof for their exact inputs; historical audit
snapshots are inputs, not substitutes for execution. An unavailable mandatory
host/tool fails the declared profile.

The same `scripts/quality.py` interface supplies portable `contract`, `native`,
`browser` and `extensions` profiles for local use and CI. These are explicit
supported scopes, not substitutes for the full host qualification. Shared
version pins and `doctor` provide prerequisite checks without installing tools.
Browser tools are locked npm development dependencies installed by the explicit
`npm ci --ignore-scripts --prefix packages/browser` setup step.

Each CI profile retains structured source/tool/command/artifact evidence and logs
on both outcomes. A missing required report fails evidence capture. The stable
`FogVault quality` gate handles docs-only changes deliberately; `Changelog policy`
checks the entire PR against its actual target, including metadata changes.
See [contribution rules](CONTRIBUTING.md). PR evidence uses the repository's
configured Actions retention (currently 90 days), covering review and normal
post-merge diagnosis without adding an unrelated retention policy. Preserve any
evidence needed longer before expiry; release qualification must retain its
candidate proof separately when registry publication is introduced.

The [CI workflow](.github/workflows/maintained.yml) separately names the native
and browser targets. Windows/macOS/Linux native and Chrome/Firefox/Edge browser
execution have passed; [the delivery record](docs/maintained.md#target-and-evidence-matrix)
links the exact runs and distinguishes their source revisions. Packaged extension automation uses bundled Chromium and
a temporary Firefox add-on; it does not prove signed store-install behavior.
Additional WebKit qualification remains deferred while existing regressions run.

The [dependency scope](docs/dependency-scope.md) distinguishes the new maintained
backup backend from the retained rejected experiment and records the development-
tool advisory. No passing profile is a production security or certification claim.

`public-checkout-manifest.json` records a captured public input set and hashes.
Its capture status is historical; Git history identifies publication. It must be
regenerated for a new public tree. Generated evidence, builds, local tool state
and `.git` files remain excluded from source publication.
