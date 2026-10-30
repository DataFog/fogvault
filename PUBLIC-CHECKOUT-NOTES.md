# Public candidate checkout

This is a curated, experimental source tree. FogVault's original code is
licensed under the [MIT License](LICENSE); third-party material retains its own
terms. This checkout is an engineering baseline, not a supported release.

The public entry is [README.md](README.md). The maintained package remains the
next engineering stage; this checkout preserves its tested candidate baseline.

## What is included

- Portable Rust core, prototype adapters/bindings, tests and unchanged Cargo locks.
- Synthetic conformance fixtures, including intentionally public test keys.
- The retained synthetic P1 SQLite fixture used only to prove legacy rejection;
  its historical `evidence/` path is an exact exception, not a published run log.
- DataFog Core `0.5.0-beta.3` as the minimum integration baseline, with the exact
  published `=0.5.0-beta.3` development/test consumer pin retained for that floor.
  DataFog Core v1 is planned as a separate test target; it is not yet verified.
- Selected audit, decoder and interoperability inputs required by the full verifier.
- Separate third-party notices. FogVault's MIT license does not relicense these.

The bundled audit/interoperability executables are the pinned **macOS arm64**
verification tools. They are not product runtime dependencies or portable release
binaries. This tree does not claim the full profile works on every development
host. The historical dependency audit is pinned to its October 29, 2026 database;
it does not replace a current advisory check before release.

Private reviewer attachments, full reference repositories, tracker exports,
historical verifier runs, large review ZIPs and build caches are excluded. Existing
selected audit metadata retains historical host paths because those bytes are
pinned evidence. The age download provenance omits the expired signed redirect;
its canonical public URL and archive/executable digests remain intact. The public
manifest records presentation/provenance overlays separately from original inputs.

The two retained `spec/` notes are historical construction inputs to independent
checks, not a complete current product specification. Their private cross-links
are rendered as reference paths; current creation and API behavior are described
in the root/core READMEs and exercised by the tests.

## Reproduce the full profile

Use the same documented development-host prerequisites as the root README. The
decoder additionally needs Python `cryptography` with Argon2id support and an
installed discoverable libsodium. The pinned browser CLI wrapper uses Node/npm
and `@playwright/cli@0.1.22`; no Codex installation is needed. Browser binaries and
the required Xcode/simulator and Rust targets must already be installed.

```sh
python3 scripts/bootstrap-reference-db.py
CARGO_PROFILE_TEST_OPT_LEVEL=2 python3 -u scripts/verify-vault.py --with-feasibility
```

The explicit bootstrap fetches the public RustSec commit into ignored
`local-only/verifier-tools/` state. It does not create a nested repository in the
vendored advisory files. The audit itself never fetches and still checks the
exact commit, tree, complete content manifest and pinned executable. Cargo/npm
may fetch their normal dependencies. This is not an offline dependency bundle.

A fresh successful report is the proof for this tree. Copied historical audit
snapshots are inputs, not substitutes for execution. Missing required targets or
tools fail explicitly. Resource thresholds, case inventories and security
assertions have not been relaxed for publication.

`public-checkout-manifest.json` inventories the prepared inputs and their hashes.
Generated evidence, build outputs, local tools and `.git` state are not published
inputs. Check the manifest before committing the first public tree.
