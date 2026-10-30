#!/usr/bin/env python3
"""Execute a disposable native/iOS-simulator ABI probe and explicit mobile builds."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources

CRATE = ROOT / "experiments/mobile-prototype"
MANIFEST = CRATE / "Cargo.toml"
PROTOTYPE = ROOT / "experiments/vault-prototype"
CORE = ROOT / "crates/fogvault"
PASSWORD_VECTORS = ROOT / "conformance/password-vectors.json"
CASE_IDS = [
    "p2-create-with-caller-owned-inputs", "locked-read-rejects-without-output",
    "p2-unlock", "short-buffer-leaves-output-unchanged", "p2-read-byte-equality",
    "wrong-password-revokes-session", "old-session-after-failed-unlock-rejects", "reunlock",
    "stale-session-after-reunlock-rejects", "null-zero-capacity-is-short-buffer",
    "null-nonzero-output-rejects", "null-token-rejects", "overflow-capacity-rejects",
    "tamper-rejects-before-plaintext-copy", "lock-revokes-session", "release-live-handle",
    "released-handle-rejects", "double-release-rejects",
    "password-utf8-golden-vectors", "password-invalid-utf8-rejects-without-output",
    "password-text-boundary-argument-and-buffer-errors", "password-unicode-nul-create-unlock-read",
    "password-raw-binary-create-unlock-read", "password-empty-create-unlock-read",
    "password-invalid-text-preserves-active-authority",
]
VECTOR_CASES = {
    "password-utf8-golden-vectors": "text",
    "password-invalid-utf8-rejects-without-output": "invalid_utf8",
    "password-raw-binary-create-unlock-read": "raw_bytes",
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity() -> dict[str, str]:
    paths = [MANIFEST, CRATE / "Cargo.lock", PROTOTYPE / "Cargo.toml", PROTOTYPE / "Cargo.lock", Path(__file__), PASSWORD_VECTORS]
    paths.extend(sorted((PROTOTYPE / "src").rglob("*.rs")))
    paths.extend([CORE / "Cargo.toml", CORE / "Cargo.lock", *sorted((CORE / "src").rglob("*.rs")), *sorted((CORE / "tests").rglob("*.rs")), *sorted((CORE / "examples").rglob("*.rs"))])
    paths.extend(sorted((CRATE / "src").rglob("*.rs")))
    paths.extend(sorted(CRATE.glob("*.c")))
    paths.extend(sorted(CRATE.glob("*.h")))
    paths.extend(maintained_sources(ROOT))
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(set(paths))}


def password_vectors() -> dict:
    definition = json.loads(PASSWORD_VECTORS.read_text())
    if definition.get("schema") != "fogvault-password-vectors/v1":
        raise ValueError("unsupported password vector schema")
    for group in VECTOR_CASES.values():
        cases = definition.get(group)
        if not isinstance(cases, list) or not cases:
            raise ValueError("missing password vector group: " + group)
        ids = [case.get("id") for case in cases]
        if any(not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", identity) for identity in ids) or len(set(ids)) != len(ids):
            raise ValueError("invalid or duplicate password vector identities")
    return definition


def password_header(directory: Path, definition: dict) -> Path:
    """Compile the shared synthetic vectors into C, never regenerate expected bytes."""
    lines = ["/* Generated only from the fixed shared password vectors. */",
             "#include <stddef.h>", "#include <stdint.h>",
             "struct fv_password_text_vector { const char *id; const uint8_t *input; size_t input_len; const uint8_t *expected; size_t expected_len; };",
             "struct fv_password_bytes { const char *id; const uint8_t *bytes; size_t length; };"]
    lengths = [0]

    def array(name: str, value: bytes) -> str:
        lengths.append(len(value))
        body = ", ".join(f"0x{byte:02x}" for byte in value) or "0"
        lines.append(f"static const uint8_t {name}[] = {{{body}}};")
        return name

    rows = []
    for index, vector in enumerate(definition["text"]):
        units = vector["utf16_units"]
        if any(type(unit) is not int or unit < 0 or unit > 0xffff for unit in units):
            raise ValueError("invalid UTF-16 vector units")
        encoded = b"".join(unit.to_bytes(2, "little") for unit in units).decode("utf-16-le").encode("utf-8")
        expected = bytes.fromhex(vector["utf8_hex"])
        if encoded != expected:
            raise ValueError("password vector does not match its fixed UTF-8 bytes")
        source = array(f"fv_text_input_{index}", encoded)
        target = array(f"fv_text_expected_{index}", expected)
        rows.append(f"{{{json.dumps(vector['id'])}, {source}, {len(encoded)}, {target}, {len(expected)}}}")
    lines.append("static const struct fv_password_text_vector fv_password_text_vectors[] = {" + ",".join(rows) + "};")
    lines.append(f"#define FV_PASSWORD_TEXT_COUNT {len(rows)}")
    names = {"invalid_utf8": "invalid_utf8", "raw_bytes": "raw"}
    for group, name in names.items():
        rows = []
        for index, vector in enumerate(definition[group]):
            value = bytes.fromhex(vector["bytes_hex"])
            if group == "invalid_utf8":
                try:
                    value.decode("utf-8")
                except UnicodeDecodeError:
                    pass
                else:
                    raise ValueError("invalid UTF-8 vector is valid")
            data = array(f"fv_{name}_{index}", value)
            rows.append(f"{{{json.dumps(vector['id'])}, {data}, {len(value)}}}")
        lines.append(f"static const struct fv_password_bytes fv_password_{name}_vectors[] = {{" + ",".join(rows) + "};")
        lines.append(f"#define FV_PASSWORD_{name.upper()}_COUNT {len(rows)}")
    lifecycle = definition["lifecycle"]["old_password"]
    index = [vector["id"] for vector in definition["text"]].index(lifecycle)
    selected = bytes.fromhex(definition["text"][index]["utf8_hex"])
    if 0 not in selected or all(byte < 0x80 for byte in selected):
        raise ValueError("mobile lifecycle vector must include Unicode and embedded NUL")
    lines.append(f"#define FV_PASSWORD_LIFECYCLE_INDEX {index}")
    # One extra byte allows the probe to check that conversion does not append NUL.
    lines.append(f"#define FV_PASSWORD_VECTOR_CAPACITY {max(lengths) + 1}")
    header = directory / "password_vectors.h"
    header.write_text("\n".join(lines) + "\n")
    return header


def cases_from_output(output: str) -> list[dict]:
    observed = re.findall(r"^CASE (\S+) (PASS|FAIL)$", output, re.MULTILINE)
    if [name for name, _ in observed] != CASE_IDS or "RESULT PASS" not in output:
        raise ValueError("ABI executable omitted, duplicated or changed required cases")
    cases = [{"id": name, "status": status.lower(), "executed": True} for name, status in observed]
    if any(case["status"] != "pass" for case in cases):
        raise ValueError("an ABI behavior case failed")
    definition = password_vectors()
    observed_vectors = re.findall(r"^VECTOR (\S+) (\S+) (PASS|FAIL)$", output, re.MULTILINE)
    expected_vectors = [(case, vector["id"], "PASS") for case, group in VECTOR_CASES.items() for vector in definition[group]]
    if observed_vectors != expected_vectors:
        raise ValueError("ABI executable omitted, duplicated or failed a shared password vector")
    observed_counts = re.findall(r"^COUNT (\S+) (\d+)$", output, re.MULTILINE)
    if observed_counts != [(case, str(len(definition[group]))) for case, group in VECTOR_CASES.items()]:
        raise ValueError("ABI executable omitted or changed actual password vector counts")
    for case in cases:
        if case["id"] in VECTOR_CASES:
            case.update(vector_ids=[vector["id"] for vector in definition[VECTOR_CASES[case["id"]]]],
                        vectors_checked=len(definition[VECTOR_CASES[case["id"]]]),
                        fixture_sha256=digest(PASSWORD_VECTORS))
    return cases


class Runner:
    def __init__(self, directory: Path):
        self.directory = directory
        self.counter = 0
        self.commands: list[dict] = []

    def run(self, command: list[str]) -> str:
        self.counter += 1
        log = self.directory / f"{self.counter:02d}-{Path(command[0]).name}.log"
        started = time.perf_counter()
        entry = {"command": command, "executed": False, "log": str(log)}
        self.commands.append(entry)
        if shutil.which(command[0]) is None:
            entry.update(status="unavailable", reason="required executable unavailable")
            raise FileNotFoundError(command[0])
        print("mobile-probe: " + " ".join(command), file=sys.stderr, flush=True)
        completed = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, check=False,
                                   env={**os.environ, "CARGO_TERM_COLOR": "never"})
        log.write_text(completed.stdout)
        entry.update(executed=True, exit_code=completed.returncode,
                     elapsed_seconds=time.perf_counter() - started,
                     status="pass" if completed.returncode == 0 else "fail")
        if completed.returncode:
            raise RuntimeError(f"command failed ({completed.returncode}); see {log}")
        return completed.stdout


def target(runner: Runner, identity: str, operation) -> dict:
    start = len(runner.commands)
    try:
        detail = operation()
        return {"id": identity, "status": "pass", "executed": True,
                "commands": runner.commands[start:], **(detail or {})}
    except FileNotFoundError as error:
        return {"id": identity, "status": "unavailable", "executed": False,
                "reason": str(error), "commands": runner.commands[start:]}
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        return {"id": identity, "status": "fail", "executed": True,
                "reason": str(error), "commands": runner.commands[start:]}


def artifact(path: Path) -> dict:
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    output = options.output.resolve()
    if output.exists():
        parser.error("output exists; select a fresh evidence path")
    output.parent.mkdir(parents=True, exist_ok=True)
    directory = output.with_suffix(".artifacts")
    directory.mkdir(exist_ok=False)
    runner = Runner(directory)
    vectors = password_vectors()
    vector_header = password_header(directory, vectors)
    identity = source_identity()
    started = time.perf_counter()
    base = ["--locked", "--manifest-path", str(MANIFEST)]
    checks = [
        target(runner, "mobile-format", lambda: runner.run(["cargo", "fmt", "--manifest-path", str(MANIFEST), "--check"]) and {}),
        target(runner, "mobile-clippy", lambda: runner.run(["cargo", "clippy", *base, "--all-targets", "--", "-D", "warnings"]) and {}),
    ]
    # The command text is retained; build output is not treated as runtime evidence.
    metadata = json.loads(runner.run(["cargo", "metadata", *base, "--no-deps", "--format-version", "1"]))
    target_directory = Path(metadata["target_directory"])

    def native():
        runner.run(["cargo", "build", *base, "--release"])
        library = target_directory / "release/libfogvault_mobile_feasibility.a"
        binary = directory / "native-probe"
        runner.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(directory), str(CRATE / "probe.c"),
                    str(library), "-framework", "Security", "-framework", "CoreFoundation", "-liconv", "-lresolv", "-lpthread", "-o", str(binary)])
        cases = cases_from_output(runner.run([str(binary)]))
        return {"cases": cases, "artifacts": [artifact(library), artifact(binary), artifact(vector_header)],
                "scope": "desktop C-to-Rust ABI runtime; in-memory single-record P2 codec"}

    targets = [target(runner, "native-abi-runtime", native)]
    simulator_details = {}

    def simulator():
        runner.run(["cargo", "build", *base, "--release", "--target", "aarch64-apple-ios-sim"])
        library = target_directory / "aarch64-apple-ios-sim/release/libfogvault_mobile_feasibility.a"
        sdk = runner.run(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"]).strip()
        runtimes = json.loads(runner.run(["xcrun", "simctl", "list", "runtimes", "-j"]))["runtimes"]
        available = [runtime for runtime in runtimes if runtime.get("isAvailable") and runtime.get("platform") == "iOS" and "arm64" in runtime.get("supportedArchitectures", [])]
        if not available:
            raise FileNotFoundError("an installed arm64 iOS simulator runtime")
        runtime = sorted(available, key=lambda item: [int(part) for part in item["version"].split(".")])[-1]
        device_types = [kind for kind in runtime.get("supportedDeviceTypes", []) if kind.get("productFamily") == "iPhone"]
        if not device_types:
            raise FileNotFoundError("an iPhone device type supported by the installed runtime")
        binary = directory / "ios-simulator-probe"
        deployment = runtime["version"]
        runner.run(["xcrun", "--sdk", "iphonesimulator", "clang", "-target", f"arm64-apple-ios{deployment}-simulator",
                    "-isysroot", sdk, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(directory), str(CRATE / "probe.c"), str(library),
                    "-framework", "Security", "-framework", "CoreFoundation", "-liconv", "-lresolv", "-lpthread", "-o", str(binary)])
        runner.run(["codesign", "--force", "--sign", "-", str(binary)])
        device = runner.run(["xcrun", "simctl", "create", "FogVault disposable ABI probe", device_types[0]["identifier"], runtime["identifier"]]).strip()
        simulator_details.update(runtime=runtime["name"], runtime_build=runtime["buildversion"],
                                 device_type=device_types[0]["name"], ephemeral_device=device,
                                 sdk_path=sdk, deployment_target=deployment)
        try:
            runner.run(["xcrun", "simctl", "boot", device])
            runner.run(["xcrun", "simctl", "bootstatus", device, "-b"])
            cases = cases_from_output(runner.run(["xcrun", "simctl", "spawn", device, str(binary)]))
        finally:
            # Only a newly created task-owned device is ever shut down/deleted.
            runner.run(["xcrun", "simctl", "shutdown", device])
            runner.run(["xcrun", "simctl", "delete", device])
            simulator_details["cleanup"] = "created simulator shut down and deleted"
        return {"cases": cases, "artifacts": [artifact(library), artifact(binary), artifact(vector_header)],
                "environment": simulator_details,
                "scope": "actual iOS simulator C-to-Rust executable, not physical-device or app-sandbox qualification"}

    targets.append(target(runner, "ios-simulator-abi-runtime", simulator))

    def device_build():
        runner.run(["cargo", "build", *base, "--release", "--target", "aarch64-apple-ios"])
        library = target_directory / "aarch64-apple-ios/release/libfogvault_mobile_feasibility.a"
        architecture = runner.run(["xcrun", "lipo", "-info", str(library)]).strip()
        return {"artifacts": [artifact(library)], "architecture": architecture,
                "scope": "arm64 iOS device-target static library compilation; no device execution/signing"}

    targets.append(target(runner, "ios-device-static-library", device_build))
    targets.append(target(runner, "android-rust-check", lambda: {
        "output": runner.run(["cargo", "check", *base, "--target", "aarch64-linux-android"]),
        "scope": "Android arm64 Rust type check and metadata build; no NDK final link or runtime"
    }))
    unchanged = source_identity() == identity
    checks.append({"id": "source-stability", "status": "pass" if unchanged else "fail", "executed": True})
    report = {
        "schema": "fogvault-mobile-feasibility/v1",
        "pass": all(item["status"] == "pass" for item in targets + checks),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": time.perf_counter() - started,
        "source_identity": identity,
        "password_vectors": {"fixture": PASSWORD_VECTORS.relative_to(ROOT).as_posix(), "sha256": digest(PASSWORD_VECTORS),
                             "generated_header": artifact(vector_header),
                             "groups": {case: [vector["id"] for vector in vectors[group]] for case, group in VECTOR_CASES.items()}},
        "targets": targets,
        "checks": checks,
        "environment": {"platform": platform.platform(), "machine": platform.machine(),
                        "simulator": simulator_details},
        "unqualified_scopes": [
            {"id": "ios-device-runtime", "status": "unavailable", "executed": False,
             "reason": "no physical iOS device selected or used; simulator resources are the Mac's"},
            {"id": "android-ndk-link", "status": "unavailable", "executed": False,
             "reason": "no Android NDK installed in inspected SDK locations; only Rust target check executed"},
            {"id": "android-runtime", "status": "unavailable", "executed": False,
             "reason": "adb inventory contained no physical devices; no Android emulator runtime was available"},
            {"id": "mobile-app-lifecycle-storage", "status": "not-run", "executed": False,
             "reason": "no Swift/Kotlin app, Keychain/Keystore, app sandbox persistence, background snapshot, or OS eviction test"},
        ],
        "limitations": [
            "All pointer validity, alignment and accessible-length obligations remain with the C caller; null/size checks do not validate arbitrary addresses.",
            "The registry serializes synchronous operations. Lock cannot preempt an in-flight KDF; a future asynchronous binding needs separate revocation/cancellation fencing.",
            "The ABI probe keeps one synthetic encrypted P2 record in memory and does not implement mobile durable storage or the whole native Vault API.",
            "Caller-owned passwords, tokens and returned plaintext require caller cleanup; Rust clears its guarded key/plaintext owners on ordinary drop.",
            "Caught Rust unwinds map to a fixed error; allocation abort and external pointer undefined behavior cannot be recovered by catch_unwind.",
            "Deployment target in this experiment follows the installed simulator runtime, not a product minimum OS declaration.",
        ],
    }
    with output.open("x") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(f"Mobile feasibility {'PASS' if report['pass'] else 'FAIL'}: {output}", file=sys.stderr)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"mobile-probe failed: {error}", file=sys.stderr)
        raise SystemExit(1)
