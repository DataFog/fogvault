#!/usr/bin/env python3
"""Build, install and execute the browser tarball through its actual Worker/WASM API."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import subprocess
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from delivery_inputs import browser_package, hashes, npm_command
from evidence import artifact_identity, git_identity, tool_versions, validate_browser_cases
from source_inputs import maintained_sources


def identity():
    paths = [Path(__file__), ROOT / "scripts/playwright-cli.sh", ROOT / "scripts/evidence.py",
             ROOT / "scripts/delivery_inputs.py", ROOT / "conformance/toolchains.json",
             ROOT / "conformance/maintained-contract.json", *maintained_sources(ROOT)]
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map,
                      ".mjs": "text/javascript", ".js": "text/javascript",
                      ".wasm": "application/wasm", ".html": "text/html"}

    def log_message(self, *_):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def prepare_consumer(work: Path, package: Path, run):
    """Install the packed bytes, then reuse the real public fixtures in that isolated app."""
    files = browser_package(package)  # Admit member paths before npm extracts anything.
    consumer = work / "consumer"
    consumer.mkdir()
    (consumer / "package.json").write_text(json.dumps({"name": "fogvault-synthetic-installed-consumer",
                                                      "private": True, "type": "module"}) + "\n", encoding="utf-8")
    run("candidate-install", ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", str(package)], cwd=consumer)
    installed = consumer / "node_modules/@datafog/fogvault-browser"
    for name, expected in files.items():
        path = installed / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("installed candidate differs from packed bytes: " + name)
    fixture = (ROOT / "packages/browser/test/browser.mjs").read_text(encoding="utf-8")
    (consumer / "browser.mjs").write_text(fixture.replace("../dist/", "./node_modules/@datafog/fogvault-browser/dist/"), encoding="utf-8")
    (consumer / "browser.html").write_bytes((ROOT / "packages/browser/test/browser.html").read_bytes())
    (consumer / "types.ts").write_bytes((ROOT / "packages/browser/test/types.ts").read_bytes())
    run("type-consumer", ["node", str(ROOT / "packages/browser/node_modules/typescript/bin/tsc"),
                          "--noEmit", "--strict", "--module", "nodenext", "--target", "es2022",
                          "--lib", "es2022,dom", "types.ts"], cwd=consumer)
    (consumer / "import-smoke.mjs").write_text(
        "import {FogVault, FogVaultError, randomId, passwordTextToBytes, clearRecord} from '@datafog/fogvault-browser';\n"
        "if (typeof FogVault !== 'function' || typeof FogVaultError !== 'function' || randomId().length !== 16 || "
        "passwordTextToBytes('SYNTHETIC').length !== 9 || typeof clearRecord !== 'function') throw Error('invalid packaged exports');\n", encoding="utf-8")
    run("candidate-import", ["node", "import-smoke.mjs"], cwd=consumer)
    return consumer, {"schema": "fogvault-installed-browser-candidate/v1",
                      "package": artifact_identity(package, ROOT if package.resolve().is_relative_to(ROOT.resolve()) else None),
                      "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                      "installed_assets": hashes({name: data for name, data in files.items() if name.startswith("dist/")}),
                      "typecheck_executed": True, "import_smoke_executed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--engines", nargs="+", choices=["chrome", "firefox", "msedge"], default=["chrome", "firefox"])
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.output.exists() or not args.engines or len(set(args.engines)) != len(args.engines):
        parser.error("use a fresh output and distinct required engines")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs, work = args.output.with_suffix(".logs"), args.output.with_suffix(".candidate")
    logs.mkdir(exist_ok=False)
    work.mkdir(exist_ok=False)
    contract = json.loads((ROOT / "conformance/maintained-contract.json").read_text(encoding="utf-8"))["browser_sdk"]
    pins = json.loads((ROOT / "conformance/toolchains.json").read_text(encoding="utf-8"))
    before, source = identity(), git_identity(ROOT)
    commands, engines, sessions = [], [], []
    server, candidate = None, None
    cli = ["node", str(ROOT / "packages/browser/node_modules/@playwright/cli/playwright-cli.js")]

    def run(name, command, cwd=ROOT):
        command = npm_command([str(x) for x in command])
        result = subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8")
        log = logs / (name + ".log")
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        commands.append({"id": name, "command": command, "cwd": str(cwd),
                         "exit_code": result.returncode, "log": str(log)})
        if result.returncode:
            raise ValueError(f"{name} failed; see {log}")
        return result.stdout

    failure = None
    try:
        installed_cli = ROOT / "packages/browser/node_modules/@playwright/cli/package.json"
        if not installed_cli.is_file() or json.loads(installed_cli.read_text(encoding="utf-8")).get("version") != pins["playwright_cli"]:
            raise ValueError("required locked Playwright CLI missing/incompatible; run npm ci --ignore-scripts --prefix packages/browser")
        if run("playwright-cli-version", [*cli, "--version"]).strip() != pins["playwright_cli"]:
            raise ValueError("Playwright CLI executable does not match the repository pin")
        run("node-tests", ["npm", "test", "--prefix", "packages/browser"])
        run("sdk-build", ["npm", "run", "build", "--prefix", "packages/browser"])
        artifacts = work / "artifacts"
        artifacts.mkdir()
        packed = json.loads(run("candidate-pack", ["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(artifacts.resolve())],
                                cwd=ROOT / "packages/browser"))
        if not isinstance(packed, list) or len(packed) != 1 or Path(packed[0]["filename"]).name != packed[0]["filename"]:
            raise ValueError("npm pack must return one safe candidate name")
        package = artifacts / packed[0]["filename"]
        consumer, candidate = prepare_consumer(work, package.resolve(), run)
        if identity() != before:
            raise ValueError("SDK inputs changed during build")
        server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(consumer)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/browser.html"
        for engine in args.engines:
            session = "fogvault-sdk-" + engine + "-" + uuid.uuid4().hex
            sessions.append(session)
            run(engine + "-open", [*cli, "--session", session, "open", url, "--browser", engine])
            output = run(engine + "-result", [*cli, "--session", session, "--raw", "run-code",
                         "async page => { await page.waitForFunction(() => !!window.fogvaultSdkDone, null, {timeout: 30000}); return await page.evaluate(() => window.fogvaultSdkDone); }"])
            result = json.loads(output)
            validate_browser_cases(result, contract)
            engines.append({"name": engine, "result": result})
            run(engine + "-close", [*cli, "--session", session, "close"])
            sessions.remove(session)
        if identity() != before or git_identity(ROOT)["input_tree_sha256"] != source["input_tree_sha256"]:
            raise ValueError("SDK source inputs changed during execution")
    except (ValueError, OSError, KeyError, TypeError) as error:
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
              "engines": engines, "commands": commands, "source_identity": before, "source": source,
              "candidate": candidate,
              "tools": tool_versions({"node": ["node", "--version"], "npm": npm_command(["npm", "--version"]),
                                      "rustc": ["rustc", "--version"], "wasm_bindgen": ["wasm-bindgen", "--version"],
                                      "playwright_cli": [*cli, "--version"]}),
              "http_mime": {suffix: {"system_default": mimetypes.guess_type("asset" + suffix)[0], "served": Handler.extensions_map[suffix]}
                            for suffix in (".mjs", ".js", ".wasm", ".html")},
              "error": failure, "independent_control": "unanchored",
              "limitations": ["Desktop installed SDK execution; not hardware-provider or physical power-loss qualification.",
                              "Extension packaging/lifecycle has a separate acceptance profile."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"pass": report["pass"], "output": str(args.output), "error": failure}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
