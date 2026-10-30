#!/usr/bin/env bash
set -euo pipefail

# Read the same CLI pin as the verifier and CI, without a Codex installation.
task_root="$(cd "$(dirname "$0")/.." && pwd)"
node -e 'const fs=require("fs");const root=process.argv[1];const expected=JSON.parse(fs.readFileSync(root+"/conformance/toolchains.json")).playwright_cli;let found;try{found=JSON.parse(fs.readFileSync(root+"/packages/browser/node_modules/@playwright/cli/package.json")).version}catch{}if(found!==expected){console.error("Playwright CLI found="+found+" expected="+expected+"; run npm ci --ignore-scripts --prefix packages/browser");process.exit(1)}' "$task_root"
exec node "$task_root/packages/browser/node_modules/@playwright/cli/playwright-cli.js" "$@"
