# Third-party notices for the experimental public checkout

These files preserve third-party terms for selected verifier inputs and tools.
They do not select a license for FogVault's original code. Original upstream
notices govern their own material, including conjunctive license expressions.

| Public checkout input | Retained notices and source information |
| --- | --- |
| DataFog Core `0.5.0-beta.3` consumer source excerpt | [MIT notice](datafog-core-0.5.0-beta.3/LICENSE), from the retained beta.3 release source. The integration still resolves the exact published crate; this notice does not change that pin. |
| RustSec advisory database snapshot | [Default and exception](rustsec/LICENSE.txt), [CC0](rustsec/LICENSES/CC0-1.0.txt), [CC-BY-4.0](rustsec/LICENSES/CC-BY-4.0.txt). Preserve advisory `license` and attribution `url` metadata, including GitHub advisory imports. |
| Go age `v1.3.2` research CLI and official archive | [BSD notice](age-v1.3.2/LICENSE), [embedded module inventory](age-v1.3.2/module-notices.json), notices for six exact Go module versions, and Go 1.27.0's license. Module zip `h1` digests were checked against the binary's embedded build information. |
| cargo-audit `0.22.2` research CLI | [Package inventory](cargo-audit/package-inventory.json), package-specific license/copyright files for 321 packages, retained published source `Cargo.toml`/`Cargo.lock`, and [upstream notice provenance](cargo-audit/upstream-notice-provenance.json). This is a host-filtered source dependency graph, not a recovered binary SBOM. |
| MPL component in that cargo-audit source graph | Unmodified [uluru 3.1.0 source archive](cargo-audit/sources/uluru-3.1.0.crate), [source URL and checksum](cargo-audit/sources/inventory.json), and [MPL license](cargo-audit/packages/uluru-3.1.0/LICENSE). The archive is the source-availability copy for that tool component and can be unpacked with tar. |
| Rust standard-library attribution supplement | [Library notices](cargo-audit/rust-standard-library/COPYRIGHT-library.html) and [capture scope](cargo-audit/rust-standard-library/provenance.json) from the installed toolchain. |
| Rust export-screening experiment dependency archives | Keep the selected archives and existing package-specific `experiments/export-prototype/provenance/notices/` files together. Those dependencies retain their own licenses; the export backend remains rejected for production selection. |

The cargo-audit inventory was captured using offline, locked Cargo metadata for
the published cargo-audit 0.22.2 manifest with default features, filtered to
`aarch64-apple-darwin`. Its graph includes source/development dependencies that
may not appear in the executable. The retained binary's SHA-256 is recorded,
but no original binary build attestation or independently reproduced executable
was available. This bundle therefore does not claim an exact executable SBOM
or establish the binary's full build pedigree.

Eight published crate packages omitted their own license files. Their retained
`.cargo_vcs_info.json` revisions were used to retrieve upstream license texts;
the URLs and hashes are recorded. `quitters` declares `MIT OR Apache-2.0` but
contains no license text at its package path. For that tool component the
Apache alternative is used, with the standard Apache text retained from a
sibling package at the same upstream revision and quitters' own published
metadata retained. No substitute copyright notice was invented.

This source checkout does not include the full Cargo, browser, system-library
or platform SDK installations. Their own distributions and terms remain
applicable. Notices for later distributed FogVault binaries must follow their
actual build dependencies, rather than treating this research-tool inventory
as a release SBOM. Neither these notices nor the passing verifier constitutes
security certification, legal clearance for unrelated copied material, or
production qualification.

Primary upstream sources: [DataFog Core](https://github.com/DataFog/datafog-core),
[RustSec licensing](https://github.com/RustSec/advisory-db/blob/main/LICENSE.txt),
[age v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2),
[cargo-audit 0.22.2](https://crates.io/crates/cargo-audit/0.22.2),
[uluru 3.1.0](https://crates.io/crates/uluru/3.1.0).
