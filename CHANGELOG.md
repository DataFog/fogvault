# Changelog

## [Unreleased]

### Security

- Keep ignored local credentials and stale generated files out of FogVault source and example archives.

### Fixed

- Bind required verification results to the PR target so push results cannot satisfy a broader promotion check.

- Reject browser verification reports that claim success while required cases failed or did not execute.

### Changed

- Verify installed native and browser package candidates, and require shared quality and changelog checks through protected PRs.
