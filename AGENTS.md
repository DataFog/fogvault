# FogVault engineering rules

Read `CONTRIBUTING.md` before changing this repository. The shared command is
`python3 scripts/quality.py`; local work and CI use its named profiles.

- Prove changed behavior with useful positive and negative tests. Test the public
  contract, including failure behavior, instead of mirroring private code.
- Handle fallible results explicitly. Untrusted input must return a controlled
  error rather than trigger a panic or crash.
- Keep vault semantics in the portable Rust core. Native, browser and language
  adapters translate the host boundary; they do not redefine authorization,
  password bytes, record integrity or recovery behavior.
- Preserve DataFog Core `0.5.0-beta.3` as the tested consumer floor. The exact
  regression pin is intentional; Core is not a vault runtime dependency.
- Keep each PR focused on one behavior or maintenance goal. Avoid unrelated
  refactors, new dependencies and abstractions without a concrete need.
- Use synthetic fixtures. Do not put credentials, private vaults or raw sensitive
  provider errors in tests, logs, reports or archives. Build from reviewed inputs.
- Explain public behavior and non-obvious reasoning in comments. Write PR prose
  for a reviewer who has not read the chat: resulting behavior, reason and proof.
- Add a meaningful `CHANGELOG.md` bullet for observable behavior, API,
  configuration, installation or security changes. Internal-only exemptions need
  both `no-changelog` and a nonempty `Changelog exemption: <reason>` PR body line.
- Check the whole PR against its actual target. An earlier commit in the same PR
  counts; a parent PR's entry does not cover a stacked child.
- Send feature PRs to `staging`, then promote `staging` to `main` through a PR.
  Required checks and resolved conversations gate merges. Independent approval
  is optional under the current owner policy. Do not bypass protection or force
  push protected branches.
- Keep evidence tied to the source and artifacts actually tested. Report skipped
  or unavailable checks honestly. Passing tests are not independent security,
  physical-device, power-loss or registry-release approval.

There is no root Cargo workspace. Use the shared profiles for the supported
per-package format, Clippy and test commands. The complete legacy feasibility
profile remains a separate macOS/Xcode check; do not silently skip required
checks to turn an unavailable profile green.
