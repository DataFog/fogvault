# Changelog

## [Unreleased]

### Security

- Keep ignored local credentials and stale generated files out of FogVault source and example archives.

### Fixed

- Write shared registry index caches atomically so concurrent package versions cannot fail a cold packaging check; retain reports and package archives in CI without build caches.

- Bind required verification results to the PR target so push results cannot satisfy a broader promotion check.

- Reject browser verification reports that claim success while required cases failed or did not execute.

### Changed

- Prepare independently versioned 0.1.0 native and browser packages, retaining backup support and the exact DataFog Core beta.3 regression. Scope backend forks to FogVault's existing features while retaining Rust source and original archives. Verify eight crate archives through a local registry consumer and require nonpublishing packaging checks in CI.

- Use lowercase fogvault and datafog product names in the repository overview.

- Verify installed native and browser package candidates, and require shared quality and changelog checks through protected PRs.
