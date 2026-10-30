#!/usr/bin/env python3
"""Measure synthetic native index growth in independent release-profile processes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "experiments/vault-prototype/Cargo.toml"
CORE = ROOT / "crates/fogvault"


def source_identity() -> dict[str, str]:
    sources = [MANIFEST, MANIFEST.parent / "Cargo.lock", Path(__file__).resolve(),
               *sorted((MANIFEST.parent / "src").rglob("*.rs")),
               CORE / "Cargo.toml", CORE / "Cargo.lock", *sorted((CORE / "src").rglob("*.rs")),
               *sorted((CORE / "tests").rglob("*.rs")), *sorted((CORE / "examples").rglob("*.rs"))]
    result = {}
    for path in sources:
        with path.open("rb") as stream:
            result[str(path.relative_to(ROOT))] = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(sorted(result.items()))


def command_output(command: list[str]) -> str:
    return subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, check=True).stdout.strip()


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("record populations must be positive")
    return parsed


def validate_record_operations(run: dict, records: int) -> None:
    """Reject missing work/correctness observations; these are format bounds, not SLOs."""
    operations = run.get("record_operations", {})
    if set(operations) != {"delete", "enumeration"}:
        raise ValueError("benchmark omitted measured deletion/paged enumeration")
    deletion, enumeration = operations["delete"], operations["enumeration"]
    for result, operation in ((deletion["sample"], "delete"),
                              (enumeration["sample"], "enumerate"),
                              (enumeration["begin"], "begin_records")):
        if result.get("operation") != operation or result.get("records") != records or result.get("correctness") is not True:
            raise ValueError("record growth operation did not report exact fixture correctness")
    page_size = 2  # Explicit caller-sized page, shared with the browser experiment.
    page_count = (records + page_size - 1) // page_size
    metrics = enumeration["sample"]["metrics"]
    if (enumeration.get("page_size") != page_size or enumeration.get("page_count") != page_count
            or enumeration.get("last_page_records") != (records - 1) % page_size + 1
            or metrics.get("nodes_read") != 2 * records - 1
            or metrics.get("node_bytes_read") != 139 * records - 82
            or metrics.get("record_rows_read") != records or metrics.get("records_scanned") != records
            or metrics.get("head_bytes") != 129 * (page_count + 1)
            or metrics.get("record_bytes_read") != records * (176 + 32 + 256)
            or not 1 <= enumeration.get("frontier_nodes_max", 0) <= 129
            or not 1 <= enumeration.get("retained_proofs_max", 0) <= page_size
            or not 1 <= enumeration.get("nodes_read_per_page_max", 0) <= page_size * 129
            or enumeration.get("records_returned_max") != min(page_size, records)
            or enumeration.get("record_rows_per_page_max") != min(page_size, records)
            or enumeration.get("complete_only_final_page") is not True
            or enumeration.get("member_identity_revision_digest_matches") is not True
            or enumeration.get("whole_inventory_materialized") is not False):
        raise ValueError("paged enumeration omitted bounded work or complete inventory evidence")
    remaining = records - 1
    if (deletion.get("remaining_records") != remaining
            or deletion.get("logical_nodes_before") != 2 * records - 1
            or deletion.get("logical_nodes_after") != max(0, 2 * remaining - 1)
            or deletion.get("logical_node_bytes_after") != (139 * remaining - 82 if remaining else 0)
            or deletion.get("target_absence_verified") is not True
            or deletion.get("remaining_inventory_audited") is not True):
        raise ValueError("deletion did not prove exact canonical remaining membership")
    measured = deletion["sample"]["metrics"]
    if (not 1 <= measured.get("nodes_read", 0) <= 259
            or not 0 <= measured.get("nodes_written", -1) <= 127
            or not 1 <= measured.get("index_nodes_deleted", 0) <= 129
            or measured.get("record_rows_read") != 1
            or measured.get("record_bytes_read") != 176 + 32 + 256
            or measured.get("records_scanned") != 0 or measured.get("full_audits") != 0):
        raise ValueError("deletion exceeded point work or omitted predecessor verification")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="write a fresh JSON evidence file")
    parser.add_argument("--records", nargs="+", type=positive_integer,
                        default=[1, 16, 256, 4096], help="synthetic record populations")
    options = parser.parse_args()
    if len(options.records) != len(set(options.records)):
        parser.error("record populations must be distinct")
    if options.output.exists():
        parser.error("output already exists; use a fresh evidence path")
    identity = source_identity()
    started = time.perf_counter()
    environment = {**os.environ, "CARGO_TERM_COLOR": "never"}
    build_command = ["cargo", "build", "--locked", "--release", "--manifest-path",
                     str(MANIFEST), "--bin", "index-growth"]
    subprocess.run(build_command, cwd=ROOT, stdin=subprocess.DEVNULL, check=True,
                   stdout=sys.stderr, stderr=sys.stderr, env=environment)
    metadata = json.loads(command_output(["cargo", "metadata", "--locked", "--no-deps",
                                          "--format-version", "1", "--manifest-path", str(MANIFEST)]))
    binary = Path(metadata["target_directory"]) / "release" / ("index-growth.exe" if os.name == "nt" else "index-growth")
    if source_identity() != identity:
        raise ValueError("benchmark sources changed during the build; rerun after edits finish")
    runs = []
    with tempfile.TemporaryDirectory(prefix="fogvault-index-growth-synthetic-") as scratch:
        for records in options.records:
            print(f"Measuring {records} synthetic records", file=sys.stderr, flush=True)
            completed = subprocess.run([str(binary), str(records), str(Path(scratch) / f"{records}.sqlite")],
                                       cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, check=True)
            run = json.loads(completed.stdout)
            if run.get("schema") != "fogvault-index-growth/v1" or run.get("records") != records or run.get("release_profile") is not True:
                raise ValueError("benchmark did not report the requested release-profile fixture")
            if (run.get("credential_format") != 3 or run.get("content_format") != 3
                    or run.get("root_epoch") != 0 or run.get("registered_control") is not False):
                raise ValueError("benchmark did not report the unregistered current-format epoch-zero fixture")
            operations = [sample.get("operation") for sample in run.get("samples", [])]
            if operations != ["read", "save", "audit", "unlock"]:
                raise ValueError("benchmark omitted a required measured operation")
            if any(sample.get("correctness") is not True for sample in run["samples"]):
                raise ValueError("a benchmark operation failed its correctness check")
            validate_record_operations(run, records)
            runs.append(run)
    if source_identity() != identity:
        raise ValueError("benchmark sources changed during measurement; rerun after edits finish")
    with binary.open("rb") as stream:
        binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    report = {
        "schema": "fogvault-index-growth/v1",
        "key_bits": 128,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": time.perf_counter() - started,
        "samples": [sample for run in runs for sample in run["samples"]],
        "runs": runs,
        "record_operations": {
            "schema": "fogvault-record-growth/v1",
            "page_size": 2,
            "deletions": [run["record_operations"]["delete"] for run in runs],
            "enumerations": [run["record_operations"]["enumeration"] for run in runs],
        },
        "source_identity": identity,
        "build": {"command": build_command, "profile": "release", "locked": True,
                  "binary_sha256": binary_sha256},
        "environment": {"platform": platform.platform(), "python": sys.version,
                        "machine": platform.machine(), "processor": platform.processor(),
                        "cpu_count": os.cpu_count(), "pointer_bits": struct.calcsize("P") * 8,
                        "rustc": command_output(["rustc", "--version"]),
                        "cargo": command_output(["cargo", "--version"])},
        "method": {
            "storage": "unregistered current-format diagnostic Vault (P3/content3 epoch0), real SQLite; synchronous=FULL; DELETE journal; no trusted-control journal overhead is measured",
            "processes": "one fresh OS process and scratch database per record population",
            "record_ids": "first 16 bytes of SHA256(record-number as u64 big endian)",
            "fixture": {"metadata_bytes": 32, "payload_bytes": 256,
                        "host_max_records": "exactly the selected record population"},
            "point_target": "record-number floor(N/2); one read and one revision-2 update per population",
            "deletion": "after the original four observations, delete_at removes that revision-2 target using its exact source head; measured work excludes the subsequent absence, unrelated-record and complete remaining-inventory checks",
            "enumeration": "before deletion, one fresh accepted cursor and repeated explicit two-record native pages enumerate all N records; each page hashes its admitted envelopes, and finality includes exact physical cardinality. Original N-record logical/file sizes precede deletion; post-delete sizes are separate",
            "enumeration_correctness": "independent fixture IDs are sorted and hashed with their expected revisions before timing, then the O(N) oracle is dropped. Timed traversal checks the same ordered transcript using constant space and only one page of proofs; no whole-inventory or per-page-observation arrays are retained by the measured loop",
            "enumeration_totals": "aggregate metrics include begin_records and every page: exactly 2N-1 index nodes, N admitted/hash-verified envelopes and129*(page_count+1) head bytes. Each page retains at most the caller-requested two proofs plus the128-bit index's129-frame frontier; whole enumeration remains O(N) work",
            "timing": "single observation after fixture population; warm caches; no cache flush or latency threshold",
            "unlock": "includes Argon2id and full streaming membership audit; does not hash every record body",
            "audit": "full streaming index and record-envelope digest check",
            "allocation": "peak_allocated_bytes is the peak live requested Rust allocation increase above baseline_allocated_bytes; peak_live_allocated_bytes is absolute live Rust bytes",
            "allocation_exclusions": "SQLite C allocations, process RSS, allocator metadata, and transient internal System realloc copies; successful realloc changes are counted by their net requested size",
            "enumeration_allocation": "separate allocator peak counters observe the entire enumeration and each individual begin/page without resetting the overall peak. Per-page maxima aggregate in constant space; caller-page retention and cursor frontier remain live in the whole-operation peak",
            "logical_size": "observed live node rows and sum(length(bytes)); for N>0 expect 2N-1 nodes and 139N-82 canonical node bytes",
            "physical_db_size": "SQLite main-file bytes after closing all vault connections; includes pages, indexes and free space; not just canonical index nodes",
        },
    }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    with options.output.open("x") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(f"Growth evidence: {options.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"index-growth measurement failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1)
