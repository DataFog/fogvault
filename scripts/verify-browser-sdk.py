#!/usr/bin/env python3
"""Execute the maintained SDK through its real Worker/WASM/IndexedDB API."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources


def identity():
    paths = [Path(__file__), ROOT / "scripts/playwright-cli.sh",
             ROOT / "conformance/maintained-contract.json", *maintained_sources(ROOT)]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


class Handler(SimpleHTTPRequestHandler):
    # Windows registry MIME associations can override Python's JavaScript
    # defaults. Module/Worker assets must have their actual web media types.
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map,
                      ".mjs": "text/javascript", ".js": "text/javascript",
                      ".wasm": "application/wasm", ".html": "text/html"}

    def log_message(self, *_):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--engines", nargs="+", choices=["chrome", "firefox", "msedge"],
                        default=["chrome", "firefox"])
    args = parser.parse_args()
    if args.output.exists() or len(set(args.engines)) != len(args.engines):
        parser.error("use a fresh output and distinct engines")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs = args.output.with_suffix(".logs")
    logs.mkdir(exist_ok=False)
    contract = json.loads((ROOT / "conformance/maintained-contract.json").read_text())["browser_sdk"]
    before = identity()
    commands, engines, sessions = [], [], []
    server = None
    override = os.environ.get("FOGVAULT_PLAYWRIGHT_CLI")
    cli = [override] if override else ["npx", "--yes", "--package", "@playwright/cli@0.1.22", "playwright-cli"]

    def run(name, command):
        # Windows npm/npx entry points are batch shims, not executables. Invoke
        # their JavaScript through Node directly so test code never passes
        # through cmd.exe quoting or a POSIX shell.
        if os.name == "nt" and command[0] in ("npm", "npx"):
            shim = shutil.which(command[0] + ".cmd")
            node = shutil.which("node")
            script = Path(shim).parent / "node_modules/npm/bin" / (command[0] + "-cli.js") if shim else None
            if not node or script is None or not script.is_file():
                raise ValueError("Node's npm/npx JavaScript entry point is required on Windows")
            command = [node, str(script), *command[1:]]
        result = subprocess.run([str(x) for x in command], cwd=ROOT,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True)
        log = logs / (name + ".log")
        log.write_text(result.stdout + result.stderr)
        commands.append({"id": name, "command": list(map(str, command)),
                         "exit_code": result.returncode, "log": str(log)})
        if result.returncode:
            raise ValueError(f"{name} failed; see {log}")
        return result.stdout

    failure = None
    try:
        run("node-tests", ["npm", "test", "--prefix", "packages/browser"])
        run("sdk-build", ["npm", "run", "build", "--prefix", "packages/browser"])
        run("type-consumer", ["npm", "run", "test:types", "--prefix", "packages/browser"])
        if identity() != before:
            raise ValueError("SDK inputs changed during build")
        server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(ROOT)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/packages/browser/test/browser.html"
        for engine in args.engines:
            session = "fogvault-sdk-" + engine + "-" + uuid.uuid4().hex
            sessions.append(session)
            run(engine + "-open", [*cli, "--session", session, "open", url, "--browser", engine])
            output = run(engine + "-result", [*cli, "--session", session, "--raw", "run-code",
                         "async page => { await page.waitForFunction(() => !!window.fogvaultSdkDone, null, {timeout: 30000}); return await page.evaluate(() => window.fogvaultSdkDone); }"])
            result = json.loads(output)
            names = [case["id"] for case in result.get("cases", [])]
            if (result.get("schema") != contract["result_schema"] or result.get("pass") is not True
                    or len(names) != len(set(names)) or set(names) != set(contract["required_cases"])):
                raise ValueError(f"{engine} did not pass every required SDK case: {result.get('error')}")
            engines.append({"name": engine, "result": result})
            run(engine + "-close", [*cli, "--session", session, "close"])
            sessions.remove(session)
        if identity() != before:
            raise ValueError("SDK source inputs changed during execution")
    except (ValueError, OSError, KeyError) as error:
        failure = str(error)
    finally:
        for session in sessions:
            try:
                run("console-" + session, [*cli, "--session", session, "console"])
            except (ValueError, OSError):
                pass
            try:
                run("cleanup-" + session, [*cli, "--session", session, "close"])
            except (ValueError, OSError):
                pass
        if server:
            server.shutdown()
            server.server_close()
    report = {"schema": "fogvault-browser-sdk-proof/v1", "pass": failure is None,
              "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "engines": engines, "commands": commands, "source_identity": before,
              "http_mime": {suffix: {"system_default": mimetypes.guess_type("asset" + suffix)[0],
                                     "served": Handler.extensions_map[suffix]}
                            for suffix in (".mjs", ".js", ".wasm", ".html")},
              "error": failure, "independent_control": "unanchored",
              "limitations": ["Desktop browser SDK execution; not hardware-provider or physical power-loss qualification.",
                              "Extension packaging/lifecycle has a separate acceptance profile."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"pass": report["pass"], "output": str(args.output), "error": failure}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
