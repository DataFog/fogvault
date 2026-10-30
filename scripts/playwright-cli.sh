#!/usr/bin/env bash
set -euo pipefail

# Match the CLI used by the engineering baseline without a Codex installation.
exec npx --yes --package @playwright/cli@0.1.22 playwright-cli "$@"
