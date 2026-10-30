# Contributing to FogVault

FogVault's native and browser packages share one Rust engine. Preserve the
supported behavior in [the delivery contract](docs/maintained.md), including its
limits. A package named "vault" does not add guarantees beyond that contract.

## Branches and PRs

Start focused work from `staging` and send its PR to `staging`. Promote tested
`staging` changes to `main` through a separate PR. For stacked work, target the
actual parent branch. The branch prefix is not a security or correctness rule;
use an existing convention, or `codex/<purpose>` for a new agent branch.

PR merges can add branch history even when the files match. Before the next
staging PR after a promotion, merge the latest `main` into the feature branch.
That keeps the next promotion up to date without pushing directly to a protected
branch. Branch synchronization follows the same PR and check rules.

Protected branches require a PR, passing required checks and resolved review
conversations. A second person's approval is optional under the current owner
policy. Checks apply to bot PRs as well. Do not bypass protection, force push or
combine unrelated changes.

A PR description should explain what users now see, why the change is needed,
relevant design choices, tests and material limits. Keep it understandable
without the chat history. Reviewers still assess whether the tests, changelog
and any exemption accurately describe the change.

## Set up and check

Use the repo-owned command from the repository root:

```sh
python3 scripts/quality.py doctor --profile native
python3 scripts/quality.py check --profile policy
python3 scripts/quality.py check --profile contract
python3 scripts/quality.py check --profile native
```

`doctor` reports missing or incompatible tools and their repairs. It does not
install tools. Use its repository-sourced requirements when setting up the host.
Run the affected browser or extension profiles for those changes:

```sh
python3 scripts/quality.py doctor --profile browser
python3 scripts/quality.py check --profile browser
python3 scripts/quality.py check --profile extensions
```

CI invokes the same named profiles. The stable required gate reports a deliberate
result for docs-only changes while avoiding unrelated expensive platform tests.
Missing required suites, malformed results, child-process failures and missing
required evidence must fail the gate.

There is no root Cargo workspace. The shared profiles run the supported
per-package equivalents of format checks, Clippy with warnings denied, tests,
consumer checks and package tests. Do not treat linting a dependency as a primary
crate's lint gate. Keep the exact published DataFog Core `=0.5.0-beta.3` regression
pin; it remains the consumer floor, not a runtime dependency or version ceiling.

The full legacy verifier remains available through the `full` profile and
`scripts/verify-vault.py --with-feasibility`. It needs the documented
[macOS/Xcode and verification-tool prerequisites](PUBLIC-CHECKOUT-NOTES.md).
Use it for changes to saved bytes, crypto/access/lifecycle authority, index or
resource contracts, and before a design or production qualification decision.
A different platform's passing subset cannot replace an unavailable required
full-profile result. Additional Safari qualification remains deferred.

## Behavioral and package proof

Changes need positive and negative tests of their public contract. Cover the
relevant confidentiality, authorization, tampering, persistence, locking,
password-byte, recovery and failure boundaries. Reuse shared conformance fixtures
when native and browser interfaces promise the same result.

Test built, packed or extracted candidates as consumers use them. Source imports
or old cached packages are not proof of a new deliverable. Keep source identity,
tool versions, commands, artifact hashes and results with the evidence. A dirty
working tree needs its actual input identity; a commit SHA alone is insufficient.
Stage intentional new source files before checking native package candidates.
Their input list comes from the Git index and uses current working-file bytes;
ignored or unstaged local files do not join an archive. A commit is not needed
for this package check.

Use synthetic data. Keep credentials and private vaults outside package inputs.
Do not change measurement baselines or invent latency promises to make a run
pass. Keep timing observations distinct from blocking contract/resource limits.

## Changelog policy

This policy starts with the repository-quality setup PR on October 30, 2026.
Earlier history does not need backfilling.

Observable behavior, public API, configuration, installation and security changes
add a concise bullet under `## [Unreleased]` in `CHANGELOG.md`. Use `### Added`,
`Changed`, `Fixed`, `Deprecated`, `Removed` or `Security` as appropriate.

Internal-only work may instead use both:

- The `no-changelog` PR label.
- A nonempty `Changelog exemption: <reason>` line in the PR body.

The checker validates the complete committed PR diff from the merge-base with
its actual target. An entry in an earlier commit of the same PR counts. A parent
PR's entry does not cover a child PR. Blank/heading-only edits, whitespace changes
and edits solely to old releases do not qualify. Release preparation that only
moves entries may use the explicit exemption.

After committing the candidate, check locally:

```sh
python3 scripts/check-changelog.py --base origin/staging
```

Local checks disclose when PR labels/body are unavailable. In that mode, an entry
is required. CI reads the PR event and validates its exact base and head commits;
missing base refs or malformed event data fail. To check an existing PR locally,
fetch its actual commits and supply the event-shaped JSON explicitly:

```sh
gh api repos/DataFog/fogvault/pulls/123 --jq '{pull_request: .}' > local-only/pr-event.json
python3 scripts/check-changelog.py --base <base-sha> --head <head-sha> --event local-only/pr-event.json
```

The changelog workflow must rerun when commits, labels, body or target change.
A checker cannot prove that an entry or reason is truthful; reviewers assess it.

## Publication

The current `0.0.0` packages are unpublished. This contribution setup does not
publish a registry release or approve the design for production. Independent
security review, physical-device/provider and power-loss qualification, final
compatibility approval and registry dependency distribution remain separate
release work. Preserve immutable published versions/tags when publication begins.
