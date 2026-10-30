# Registry packaging candidate

FogVault's initial package candidate is **0.1.0**, independently versioned from
DataFog Core. Packaging checks establish local build evidence; they do not
claim security approval or platform qualification. Core's published
`=0.5.0-beta.3` regression remains unchanged; v1 coverage belongs in Core's own
release checks.

## Preserved dependency graph

| Registry package | Version | Source and purpose |
| --- | --- | --- |
| `fogvault` | 0.1.0 | Portable engine |
| `fogvault-native` | 0.1.0 | SQLite adapter; default backup remains enabled |
| `fogvault-backup` | 0.1.0 | Existing bounded age/v1 transport |
| `fogvault-age` | 0.11.5 | age 0.11.5; cryptographic Rust sources byte-identical |
| `fogvault-i18n-config` | 0.4.8 | Retained localized dependency correction |
| `fogvault-i18n-embed-impl` | 0.8.4 | Retained localized dependency correction |
| `fogvault-i18n-embed` | 0.16.0 | Retained localized dependency correction |
| `fogvault-i18n-embed-fl` | 0.10.1 | Retained localized dependency correction |

Distinct names avoid passing a modified package off as the upstream release.
The original Rust library aliases and upstream versions stay intact. The age
localization domain is explicitly `age` so its package rename does not change
message lookup. The forks expose only the exact feature/dependency closure used
by FogVault backup, with upstream dev/bench/example dependencies/targets and unused
opt-in capabilities omitted from package metadata. They do not promise general
upstream feature parity. Their package READMEs state this scope; all Rust bytes
and original upstream source archives remain retained. Retained upstream archives and a checked patch inventory record
all changes, including Cargo metadata and that localization setting. Original
licenses stay with each fork. Renamed fork dependencies must also be audited
under their original upstream identities; a namespace change does not clear an
advisory.

Cargo normalizes versioned path dependencies to registry dependencies in crate
archives. Disabling the optional backup feature does not remove its dependency
metadata or make an incomplete registry graph distributable. Removing backup or
silently switching to an uncorrected backend is therefore not a packaging fix.
The Rust WASM bindings remain an internal `publish=false` build crate; the browser
product is `@datafog/fogvault-browser@0.1.0`, with actual Worker, WASM, types and
third-party notices in the npm tarball.

## Nonpublishing proof

Install the pinned tools and browser npm development dependencies described by
`python3 scripts/quality.py doctor --profile packaging`, then run:

```sh
python3 scripts/quality.py check --profile packaging --output-dir local-only/packaging
```

The check copies approved indexed source files into a disposable workspace, then
validates retained upstream archives and declared patch scope, then uses Cargo's
batch packaging and normal archive verification for all eight
packages. The disposable workspace is seeded from the approved native lock,
expanded for workspace-only dev/optional requirements, and packaged with
`--locked`. Exact registry names, versions and checksums in native and backup
archive locks must match their audited source locks; the consumer must retain
that native graph. A silent transitive update fails the check. Every registry name/version/checksum
in every crate archive must belong to the union of the seven audited source lock
graphs; unused upstream developer graphs cannot quietly enter the release. The portable-core
library archive shares workspace optional web resolution, rather than retaining
its separate development lock verbatim; library consumers resolve their own locks.
The shipped browser artifact is built separately with its unchanged locked WASM
graph. These scopes are reported separately. It validates normalized metadata, license notices and Rust source
bytes. Cargo's temporary registry is extended with checksum-verified official
locked dependencies. A fresh Cargo home then builds and runs an offline consumer
with registry dependencies only: no path dependencies, patches or Git substitution.
The check also validates the immutable fourteen-graph local audit receipt against
the current seven lockfiles and manifests, and runs portable original-name
projection regressions. Those receipt checks do not execute the platform-specific
audit binary or claim fresh Linux audits. The full verifier retains fresh actual
audits against its pinned database. A separate original-name advisory projection
is retained for the candidate registry consumer, without using that projection
as a build lock.

That consumer saves an actual Core beta.3 workspace bundle, rejects a locked
session, reopens and reads the same bundle. All eight candidate registry identities
must resolve. Default native backup stays enabled. The ordinary native/backup
suites remain responsible for the full backup behavior coverage.

Finally it builds and packs the browser SDK and admits the actual Worker/WASM
archive contents. Reports retain source identity, tool versions, archive and log
hashes, the frozen registry input manifest and executed commands. Interrupted,
failed or stale runs cannot satisfy the shared quality gate. Network access is
used only to read official dependency archives/index metadata as needed; no token,
registry upload, tag or publish command is used. This preflight is required on
product PRs and never publishes from CI.

## Release procedure

Release authorization for FogVault 0.1.0 and the five named dependency forks was
given on October 30, 2026. Verify registry namespace ownership before uploading.
Publish the
leaf forks first (`fogvault-i18n-config`, `fogvault-i18n-embed-impl`), then
`fogvault-i18n-embed`, `fogvault-i18n-embed-fl`, `fogvault-age`, and
`fogvault-backup`; `fogvault` is independent of the backup chain. Publish
`fogvault-native` only after both its exact dependencies are available. The npm
SDK has its own artifact and authorization. Before uploads, run registry dry runs
against the now-available dependencies and confirm every archive matches the
reviewed candidate. The local preflight cannot reserve names or prove future
registry authorization. A successful packaging report alone never means that a
package has been published.


Use the release commit from `main`, a clean checkout, the pinned Rust toolchain,
and the fresh successful `packaging` report for that source. Record the report,
commit, package checksums and registry responses outside shipped source. The
release notes are in [0.1.0](releases/0.1.0.md). The normal publication order is:

| Order | Registry package | Version | Manifest |
| --- | --- | --- | --- |
| 1 | `fogvault-i18n-config` | 0.4.8 | `crates/fogvault-backup/vendor/i18n-config-0.4.8/Cargo.toml` |
| 2 | `fogvault-i18n-embed-impl` | 0.8.4 | `crates/fogvault-backup/vendor/i18n-embed-impl-0.8.4/Cargo.toml` |
| 3 | `fogvault-i18n-embed` | 0.16.0 | `crates/fogvault-backup/vendor/i18n-embed-0.16.0/Cargo.toml` |
| 4 | `fogvault-i18n-embed-fl` | 0.10.1 | `crates/fogvault-backup/vendor/i18n-embed-fl-0.10.1/Cargo.toml` |
| 5 | `fogvault-age` | 0.11.5 | `crates/fogvault-backup/vendor/age-0.11.5/Cargo.toml` |
| 6 | `fogvault` | 0.1.0 | `crates/fogvault/Cargo.toml` |
| 7 | `fogvault-backup` | 0.1.0 | `crates/fogvault-backup/Cargo.toml` |
| 8 | `fogvault-native` | 0.1.0 | `crates/fogvault-native/Cargo.toml` |

For each Rust row, wait for its dependencies to appear in the public index, run
`cargo publish --manifest-path <manifest> --locked --dry-run`, inspect the
resulting archive against the qualified package's member bytes and approved
dependency identities, then run the same command without `--dry-run`. Keep
ordinary Cargo archive verification enabled. Do not add `--no-verify`, path
patches, alternate backend substitutions or a regenerated unreviewed dependency
graph to get publication through. Release-only Git metadata can change archive
checksums, so retain both archive identities and explicitly review any difference.

The browser archive is the actual tarball produced by the fresh packaging
preflight. First run `npm publish <qualified-tarball> --access public --dry-run
--ignore-scripts`, then publish that same tarball with `--access public
--ignore-scripts`. This uploads the reviewed Worker/WASM bundle, not an npm
lifecycle rebuild. Registry credentials belong in the approved credential store or
CI environment, never a release log, command argument or tracked file.

Publication across registries is not atomic. After any error, inspect the public
registry before retrying. If a version already exists, download and compare it to
the recorded uploaded candidate; continue only when that exact version is the
intended release. Never overwrite or repoint an existing version/tag. If the
content differs, stop and resolve the version conflict rather than treating an
HTTP error as permission to skip it.

After uploads, use a fresh Cargo home and npm project to install the explicit
public versions. Run the native save/lock/reopen/read and exact published Core
beta.3 interoperability checks, and the installed browser Worker/IndexedDB
consumer checks. Record public archive checksums alongside the executed results.
Only then mark the registry release complete and create the immutable `v0.1.0`
release tag and GitHub release for the tested source. Keep unpublished/failed
channels explicit if a partial release needs recovery.
