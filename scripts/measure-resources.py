#!/usr/bin/env python3
"""Measure synthetic native resource workloads without selecting production budgets."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources

MANIFEST = ROOT / "experiments/vault-prototype/Cargo.toml"
CORE = ROOT / "crates/fogvault"
CONSUMER_SOURCE = ROOT / "research/consumer/datafog-core-0.5.0-beta.3/published-source/src/workspace.rs"
PAYLOAD_OPERATIONS = ("create", "unlock_empty", "save", "read", "update", "audit", "unlock", "payload_rejected")
KDF_OPERATIONS = ("kdf", "kdf_concurrent", "kdf_rejected")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity() -> dict[str, str]:
    paths = [MANIFEST, MANIFEST.parent / "Cargo.lock", Path(__file__).resolve(),
             *sorted((MANIFEST.parent / "src").rglob("*.rs")),
             CORE / "Cargo.toml", CORE / "Cargo.lock", *sorted((CORE / "src").rglob("*.rs")),
             *sorted((CORE / "tests").rglob("*.rs")), *sorted((CORE / "examples").rglob("*.rs"))]
    paths.extend(maintained_sources(ROOT))
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in sorted(paths)}


def consumer_limit() -> dict:
    source = CONSUMER_SOURCE.read_text()
    match = re.search(r"^pub const MAX_BUNDLE_BYTES: usize = (\d+) \* (\d+) \* (\d+);$", source, re.MULTILINE)
    if match is None:
        raise ValueError("the reviewed exact consumer bundle constant was not found")
    size = math.prod(int(value) for value in match.groups())
    if size != 16 * 1024 * 1024:
        raise ValueError("the consumer bundle bound differs from the benchmark's reviewed mirror")
    return {"bytes": size, "expression": " * ".join(match.groups()),
            "source": CONSUMER_SOURCE.relative_to(ROOT).as_posix(),
            "source_line": source[:match.start()].count("\n") + 1,
            "source_sha256": digest(CONSUMER_SOURCE), "version": "0.5.0-beta.3"}


def command_output(command: list[str]) -> str:
    return subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, check=True).stdout.strip()


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def time_command(command: list[str]) -> tuple[list[str], str]:
    timer = Path("/usr/bin/time")
    if timer.is_file() and sys.platform == "darwin":
        return [str(timer), "-l", *command], "macOS /usr/bin/time -l: child process lifetime high-water resident bytes"
    if timer.is_file() and sys.platform.startswith("linux"):
        return [str(timer), "-v", *command], "Linux /usr/bin/time -v: child process lifetime maximum resident KiB converted to bytes"
    return command, "unavailable: platform has no configured process-lifetime RSS observer"


def peak_rss(stderr: str, method: str) -> dict:
    if sys.platform == "darwin":
        match = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", stderr, re.MULTILINE)
        value = int(match.group(1)) if match else None
    elif sys.platform.startswith("linux"):
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
        value = int(match.group(1)) * 1024 if match else None
    else:
        value = None
    return {"status": "measured" if value is not None else "unavailable",
            "peak_rss_bytes": value, "scope": "entire child process, not per-operation",
            "method": method}


def validate_run(run: dict, kind: str, payload: int, repetitions: int) -> None:
    if run.get("schema") != "fogvault-resource-budgets/v1" or run.get("kind") != kind:
        raise ValueError("resource executable did not report the requested workload")
    if run.get("payload_bytes") != payload or run.get("repetitions") != repetitions or run.get("release_profile") is not True:
        raise ValueError("resource workload/profile identity differs from the request")
    if run.get("kdf") != {"memory_kib": 65536, "passes": 3, "lanes": 1}:
        raise ValueError("resource executable changed the reviewed KDF tuple")
    expected_operations = KDF_OPERATIONS if kind == "kdf" else PAYLOAD_OPERATIONS
    samples = run.get("samples")
    if not isinstance(samples, list):
        raise ValueError("resource samples are missing")
    actual = [(sample.get("operation"), sample.get("repetition")) for sample in samples]
    expected = {(operation, repetition) for operation in expected_operations for repetition in range(repetitions)}
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("resource workload omitted or duplicated a required operation/repetition")
    for sample in samples:
        if sample.get("correctness") is not True:
            raise ValueError("resource workload failed its correctness check")
        for field in ("elapsed_ns", "baseline_allocated_bytes", "peak_allocated_bytes", "peak_live_allocated_bytes", "ending_allocated_bytes"):
            if type(sample.get(field)) is not int or sample[field] < 0:
                raise ValueError("resource measurement is not a nonnegative integer: " + field)
        if sample["peak_live_allocated_bytes"] != sample["baseline_allocated_bytes"] + sample["peak_allocated_bytes"]:
            raise ValueError("Rust requested-allocation baseline/peak values are inconsistent")
        if sample["ending_allocated_bytes"] > sample["peak_live_allocated_bytes"]:
            raise ValueError("Rust ending requested allocation exceeds the measured peak")
        operation = sample["operation"]
        sample["case_id"] = f"{kind}/{payload}/{operation}" if kind == "payload" else f"kdf/{operation}"
        m = sample["metrics"]
        if operation in {"kdf_rejected", "payload_rejected"} and sample["peak_allocated_bytes"] != 0:
            raise ValueError("rejected parameters/input allocated Rust work memory")
        if kind == "payload":
            if run.get("content_format") != 3 or run.get("root_epoch") != 0 or run.get("registered_control") is not False:
                raise ValueError("resource workload is not the unregistered current-format epoch-zero fixture")
            if run["metadata_bytes"] != 32 or run["records"] != 1 or run["envelope_bytes"] != payload + 32 + 176:
                raise ValueError("resource workload changed record framing or fixture shape")
            if operation not in {"create", "payload_rejected"} and m["head_bytes"] != 129:
                raise ValueError("resource workload head is not the fixed current head length")
            if operation in {"read", "save", "update"} and m["records_scanned"] != 0:
                raise ValueError("resource point operation performed a full inventory scan")
            if operation in {"save", "update"} and m["record_bytes_written"] != run["envelope_bytes"]:
                raise ValueError("accepted payload was not saved with exact framing overhead")
            if operation == "read" and (m["record_bytes_read"] != run["envelope_bytes"] or m["nodes_read"] != 1):
                raise ValueError("selected payload read has inconsistent byte/node counters")
            if operation in {"unlock", "audit"} and (m["records_scanned"] != 1 or m["nodes_read"] != 1):
                raise ValueError("full inventory operation did not visit the exact one-record tree")
            if operation in {"unlock", "unlock_empty"} and m["record_bytes_read"] != 0:
                raise ValueError("metadata-only unlock unexpectedly fetched payload bytes")
            if operation == "audit" and m["record_bytes_read"] != run["envelope_bytes"]:
                raise ValueError("explicit audit did not hash the full encrypted record")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="fresh output JSON evidence path")
    parser.add_argument("--repetitions", type=positive_integer, default=3,
                        help="experimental observations per operation; default3 is the smallest odd repeated sample for min/median/max, not a production limit")
    parser.add_argument("--payload-bytes", nargs="+", type=int,
                        help="explicit subset for smoke measurements; complete profile uses 0,4096,1048576 and the exact beta.3 bundle cap")
    options = parser.parse_args()
    if options.output.exists():
        parser.error("output already exists; use a fresh evidence path")
    limit = consumer_limit()
    payloads = options.payload_bytes if options.payload_bytes is not None else [0, 4096, 1024 * 1024, limit["bytes"]]
    if len(payloads) != len(set(payloads)) or any(payload < 0 or payload > limit["bytes"] for payload in payloads):
        parser.error("payload workloads must be distinct nonnegative sizes fitting the reviewed consumer cap")
    identity = source_identity()
    started = time.perf_counter()
    build_command = ["cargo", "build", "--locked", "--release", "--manifest-path", str(MANIFEST), "--bin", "resource-budget"]
    subprocess.run(build_command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=sys.stderr,
                   stderr=sys.stderr, check=True, env={**os.environ, "CARGO_TERM_COLOR": "never"})
    metadata = json.loads(command_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", str(MANIFEST)]))
    binary = Path(metadata["target_directory"]) / "release" / ("resource-budget.exe" if os.name == "nt" else "resource-budget")
    if source_identity() != identity:
        raise ValueError("resource sources changed during build; rerun with stable inputs")
    runs = []
    with tempfile.TemporaryDirectory(prefix="fogvault-resource-SYNTHETIC-") as scratch:
        workloads = [("kdf", 0), *(("payload", size) for size in payloads)]
        for kind, size in workloads:
            arguments = [str(binary), "kdf", str(options.repetitions)]
            if kind == "payload":
                directory = Path(scratch) / str(size)
                directory.mkdir()
                arguments = [str(binary), kind, str(size), str(options.repetitions), str(directory)]
            command, rss_method = time_command(arguments)
            print(f"Measuring {kind}, payload_bytes={size}, repetitions={options.repetitions}", file=sys.stderr, flush=True)
            completed = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, check=True)
            run = json.loads(completed.stdout)
            validate_run(run, kind, size, options.repetitions)
            run["process_memory"] = peak_rss(completed.stderr, rss_method)
            run["command"] = arguments
            run["summaries"] = {}
            for operation in (KDF_OPERATIONS if kind == "kdf" else PAYLOAD_OPERATIONS):
                observations = [sample for sample in run["samples"] if sample["operation"] == operation]
                run["summaries"][operation] = {field: {"min": min(values), "median": statistics.median(values), "max": max(values)}
                                                for field in ("elapsed_ns", "peak_allocated_bytes", "peak_live_allocated_bytes")
                                                for values in [[sample[field] for sample in observations]]}
            runs.append(run)
    if source_identity() != identity or consumer_limit() != limit:
        raise ValueError("resource sources or consumer limit changed during measurement")
    report = {
        "schema": "fogvault-resource-budgets/v1", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": time.perf_counter() - started, "source_identity": identity,
        "consumer_limit": limit, "repetitions": options.repetitions,
        "payload_populations": payloads, "runs": runs,
        "samples": [sample for run in runs for sample in run["samples"]],
        "build": {"command": build_command, "profile": "release", "locked": True, "binary_sha256": digest(binary)},
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(),
                        "rustc": command_output(["rustc", "--version"]), "cargo": command_output(["cargo", "--version"]), "python": sys.version},
        "method": {
            "storage": "unregistered current-format diagnostic Vault (P3/content3 epoch0), SQLite DELETE journal, synchronous FULL, one record per payload workload; trusted-control journal overhead is not measured",
            "payloads": "empty,4KiB,1MiB,and exact published beta.3 MAX_BUNDLE_BYTES; synthetic opaque bytes, not a fabricated valid Core bundle",
            "repetitions": "3 is the smallest odd repeated sample permitting distinct min/median/max; workload choice, not statistical qualification or a product limit",
            "processes": "fresh OS process per KDF/payload workload; fresh DB per payload repetition; process peak RSS covers the whole child lifetime",
            "kdf_concurrency": "serial1 and simultaneous2 (smallest more-than-one workload); no production concurrency quota is selected",
            "allocation": "requested live Rust heap bytes, baseline, peak increase, absolute peak and ending values; caller-owned input is already live at baseline",
            "allocation_exclusions": "SQLite C allocations, process RSS, allocator metadata and transient internal System realloc copies; OS RSS is reported separately",
            "create_counters": "Vault::diagnostic_create_current exposes default logical OperationMetrics; its resource timing/allocation is measured, and following operations validate the fixed head and stored bytes",
            "rejected_input": "oversized caller input exists before measurement; rejection itself must allocate no Rust work memory and preserve generation",
            "unlock": "KDF plus streaming index/row metadata admission; no ciphertext-body fetches",
            "timing": "single-process repeated observations with ordinary caches; report min/median/max, impose no SLO or latency gate",
            "budgets": "measurements inform policy shape; total host memory, scheduler limits, queue admission and lowest-supported device measurements remain needed before production numerical defaults",
        },
    }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    with options.output.open("x") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(f"Resource evidence: {options.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"resource measurement failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1)
