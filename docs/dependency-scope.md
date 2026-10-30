# Dependency and attribution scope

FogVault original code is [MIT licensed](../LICENSE). Upstream libraries, tools,
fixtures and data retain their own terms. Source notices and the browser bundle's
attribution data describe their stated scope; they are not a certification or an
independently reconstructed executable SBOM.

## Maintained Rust graphs

The [current audit capture](../artifacts/publication/dependency-audit-maintained-20261030/inventory.json)
records seven exact locked graphs: core, retained native/browser/mobile harnesses,
maintained native, maintained WASM and maintained backup. The pinned RustSec
snapshot is commit `ee1a49a2769a24a596afc1c20cb33748d2769586` from October 29,
2026. The capture reports zero matching vulnerabilities/warnings, with no advisory
suppression or target/severity filter. The verifier repeats those audits against
the current locks and checks manifest and source identities.

This is dated advisory matching. It does not prove the absence of unknown bugs,
malicious packages, side channels or implementation defects. A release needs a
fresh advisory review and its own artifact/dependency evidence.

## Maintained backup backend

The selected engineering backend uses age `0.11.5` with localized dependency
corrections. Its [source provenance](../crates/fogvault-backup/upstream/provenance.json)
pins the original crate archives and every retained vendored file. Seven declared
non-cryptographic edits route localization dependencies to retained sources,
replace the unmaintained TOML parser and adjust localization code. All age Rust
source files remain byte-identical to the original archive; no age cryptographic
construction or authenticated context was changed.

Check the patch scope explicitly:

```sh
python3 crates/fogvault-backup/upstream/verify.py
```

Keep the vendored package license texts and provenance with the source. The
browser build also includes notices for its locked WASM source graph. The
retained earlier export experiment and its original failed audit remain rejected;
the corrected graph does not retroactively approve that experiment. Upstream
experimental status and independent construction review remain separate from a
clean matched-advisory result.

Git/path consumption preserves the corrected local dependency graph. A future
crates.io publication needs upstream fixes or separately named/published fork
packages. Cargo's versioned path handling is not a way to publish these local
corrections under an unchanged registry identity.

## Browser runtime and development tools

The browser SDK has **no runtime npm dependencies**. Its tarball contains its own
JavaScript/Worker/WASM assets and locked source-graph notices. Development tools
and `node_modules` do not ship in that tarball.

The development audit currently reports three low-severity entries in one chain:
`web-ext 10.8.0` → `addons-linter` → `deepmerge`. The underlying advisory is
[GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4), prototype
poisoning in `deepmerge` returned objects. The retained report has not been
suppressed or changed to a clean result. A force downgrade is not applied as an
apparent fix.

The narrow test-tool disposition permits this tool only for repository-owned
synthetic extension fixtures. CI installs locked dependencies without lifecycle
scripts, has read-only repository permissions and does not persist checkout
credentials. This is not approval to process untrusted extension manifests or
configuration with that tool. A new advisory, changed tool graph or broader use
requires a new assessment. It is not a claim that every development dependency
is vulnerability-free or that registry release checks are complete.

Pinned Playwright/browser tooling supplies test execution. Packaged extension
checks use [Playwright's documented Chromium setup](https://playwright.dev/docs/chrome-extensions)
and Mozilla's temporary Firefox installation flow. Passing them does not qualify
signed store installation, physical hardware or every future browser version.

## Distributed notices

A standalone public Git consumer was tested at the exact implementation revision
`f16c4f0bda91fc3a31c0f12b717f8d2f5932c226` with Rust/Cargo 1.94.1. Cargo emits
duplicate-package discovery warnings for historical `Cargo.toml` notice snapshots;
resolved metadata confirms it selected the maintained vendor manifests, with no
working-checkout path overrides. The independently tested native source archive
omits those historical snapshots. Cleaning up Git discovery warnings remains a
repository hygiene follow-up; registry publication still needs the dependency
distribution work described above.

The [retained tool notices](../third-party/THIRD_PARTY_NOTICES.md) cover their
listed audit/interoperability tools, database data and consumer excerpt. They do
not replace the maintained backup's vendored notices or the browser artifact's
own `dist/third-party/` attribution bundle. Final distributed binaries need
notices tied to the dependencies in their actual build.
