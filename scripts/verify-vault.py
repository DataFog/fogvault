#!/usr/bin/env python3
"""Run the vault behavior contract; emit evidence, never rewrite expected results."""

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
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources
from evidence import artifact_identity, git_identity, validate_browser_cases, write_report

CONTRACT = ROOT / "conformance/vault-contract.json"
CORE = ROOT / "crates/fogvault"
PROFILE = "disposable-vault-native-and-portable-compile"


class Unavailable(ValueError):
    """A required capability exists in the plan but not in this environment."""


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def required_integer(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def load_contract(path: Path = CONTRACT) -> dict:
    contract = json.loads(path.read_text())
    if contract.get("schema") != "fogvault-behavior-contract/v1":
        raise ValueError("unsupported behavior-contract schema")
    if contract.get("profile") != PROFILE:
        raise ValueError("unsupported behavior-contract profile")
    fields = ("required_core_cases", "required_native_cases", "required_fixture_cases", "required_backup_cases")
    for field in fields:
        names = contract.get(field)
        if not isinstance(names, list) or not names or any(not isinstance(name, str) or not name for name in names):
            raise ValueError(f"{field} must name the behavior cases to execute")
        if len(names) != len(set(names)):
            raise ValueError(f"{field} contains duplicate names")
    manifest = (ROOT / contract["manifest"]).resolve()
    manifest.relative_to(ROOT)
    core_manifest = (ROOT / contract["core_manifest"]).resolve()
    if core_manifest != CORE / "Cargo.toml":
        raise ValueError("portable core manifest differs from the reviewed package boundary")
    names = [name for field in fields for name in contract[field]]
    if len(set(names)) != len(names):
        raise ValueError("core, native and fixture behavior names must be distinct")
    access = contract.get("access_paths", {})
    if access.get("definition") != "conformance/access-paths.json" or access.get("report_schema") != "fogvault-access-path-model/v1":
        raise ValueError("the candidate access-path definition/report must be explicitly named")
    if type(access.get("truth_table_combinations")) is not int or access["truth_table_combinations"] != 96:
        raise ValueError("the candidate access model must retain all 96 credential combinations")
    cases = access.get("required_cases")
    if not isinstance(cases, list) or not cases or any(not isinstance(name, str) or not name for name in cases) or len(set(cases)) != len(cases):
        raise ValueError("the access model must require distinct named executed cases")
    if access.get("command") != ["{python}", "scripts/verify-access-paths.py", "--output", "{output}"]:
        raise ValueError("the access-path runner must remain the reviewed symbolic checker")
    passwords = contract.get("password_vectors", {})
    if passwords.get("fixture") != "conformance/password-vectors.json" or passwords.get("rust_projection") != "conformance/password-vectors.tsv":
        raise ValueError("the shared password fixture and Rust projection must be explicitly named")
    for group in ("text", "invalid_utf16", "invalid_utf8", "raw_bytes"):
        ids = passwords.get("groups", {}).get(group)
        if not isinstance(ids, list) or not ids or any(not isinstance(identity, str) for identity in ids) or len(ids) != len(set(ids)):
            raise ValueError("the password-vector contract must retain its named groups")
    return contract


def check_consumer_pin(contract: dict, manifest: Path) -> dict:
    package = contract["consumer"]
    manifest_data = tomllib.loads(manifest.read_text())
    name = package["package"]
    dependency_scopes = [manifest_data, *manifest_data.get("target", {}).values()]
    if any(name in scope.get(kind, {}) for scope in dependency_scopes for kind in ("dependencies", "build-dependencies")):
        raise ValueError("the consumer must not become a normal or build-time vault dependency")
    dependency = manifest_data.get("dev-dependencies", {}).get(name)
    if not isinstance(dependency, dict) or dependency.get("version") != "=" + package["version"]:
        raise ValueError("consumer dev-dependency must be pinned to the reviewed exact release")
    lock_path = manifest.parent / "Cargo.lock"
    lock = tomllib.loads(lock_path.read_text())
    matches = [entry for entry in lock["package"] if entry["name"] == name]
    if len(matches) != 1:
        raise ValueError("consumer package must resolve once in Cargo.lock")
    resolved = matches[0]
    if resolved.get("version") != package["version"] or resolved.get("checksum") != package["checksum"]:
        raise ValueError("consumer version/checksum differs from the reviewed contract")
    if not resolved.get("source", "").startswith("registry+"):
        raise ValueError("consumer proof must use the reviewed published registry package")
    return {"package": name, "version": resolved["version"], "checksum": resolved["checksum"], "lock_sha256": sha256(lock_path)}


def check_core_boundary(manifest: Path) -> dict:
    """The reusable engine must not acquire adapter or consumer dependencies."""
    data = tomllib.loads(manifest.read_text())
    forbidden = {"datafog-core", "rusqlite", "libsqlite3-sys", "sqlite", "sqlx", "wasm-bindgen", "wasm-bindgen-futures", "js-sys", "web-sys"}
    scopes = [data, *data.get("target", {}).values()]
    dependencies = []
    for scope in scopes:
        for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
            for alias, definition in scope.get(kind, {}).items():
                package = definition.get("package", alias) if isinstance(definition, dict) else alias
                if package in forbidden:
                    raise ValueError("portable core contains a consumer, storage or host-binding dependency: " + package)
                dependencies.append(package)
    if data.get("features", {}).get("default", []):
        raise ValueError("the portable core default API must not opt into experimental codecs or host capabilities")
    return {"package": data["package"]["name"], "dependencies": sorted(set(dependencies)), "adapter_and_consumer_dependencies_absent": True, "default_features": []}


def successful_cases(output: str) -> set[str]:
    return set(re.findall(r"^test ([^\s]+) \.\.\. ok$", output, re.MULTILINE))


def require_cases(output: str, expected: list[str]) -> dict:
    executed = successful_cases(output)
    missing = sorted(set(expected) - executed)
    if missing:
        raise ValueError("required behavior cases did not execute successfully: " + ", ".join(missing))
    return {"required_cases": expected, "executed_cases": sorted(executed), "observed_test_cases": len(executed)}


def require_private_api_doctests(output: str) -> dict:
    cases = re.findall(r"^test (.+) - compile fail \.\.\. ok$", output, re.MULTILINE)
    if len(cases) != 4 or len(set(cases)) != 4:
        raise ValueError("the four default-API compile-fail proofs must execute: private crypto/format/index and no root-key accessor")
    return {"compile_fail_cases": cases, "protected_boundaries": ["crypto", "format", "index", "root_key"]}


def behavior_evidence(checks: list[dict], contract: dict) -> dict:
    """Retain every named behavior when primitive tests move to their own crate."""
    by_id = {check["id"]: check for check in checks}
    groups = {"core-tests": contract["required_core_cases"], "native-tests": contract["required_native_cases"] + contract["required_fixture_cases"]}
    if contract.get("required_backup_cases"):
        groups["maintained-backup-tests"] = contract["required_backup_cases"]
    evidence = {}
    for identity, required in groups.items():
        observed = set(by_id.get(identity, {}).get("evidence", {}).get("executed_cases", []))
        evidence[identity] = {"required_cases": required, "executed_required_cases": sorted(set(required) & observed), "missing_cases": sorted(set(required) - observed)}
    return {"required_case_count": sum(map(len, groups.values())), "groups": evidence}


def complete_results(checks: list[dict], expected: list[str]) -> bool:
    if (not isinstance(checks, list) or not isinstance(expected, list) or not expected
            or any(not isinstance(name, str) or not name for name in expected)
            or len(expected) != len(set(expected))
            or any(not isinstance(check, dict) or not isinstance(check.get("id"), str)
                   or not check["id"] for check in checks)):
        return False
    return (
        len(checks) == len(expected)
        and {check["id"] for check in checks} == set(expected)
        and all(check.get("required") is True and check.get("executed") is True and check.get("status") == "pass" for check in checks)
    )


def validate_format_vectors(path: Path) -> dict:
    vectors = json.loads(path.read_text())
    if vectors.get("schema") != "fogvault-format-vectors/v1":
        raise ValueError("unsupported format-vector schema")
    cases = vectors.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("format vectors must contain explicit cases")
    identities = set()
    for case in cases:
        identity = case.get("id")
        if not isinstance(identity, str) or not identity or identity in identities:
            raise ValueError("format-vector IDs must be present and unique")
        identities.add(identity)
        if case.get("kind") not in {"descriptor", "hmac-sha256", "index-node", "index-head"}:
            raise ValueError(f"unsupported format-vector kind for {identity}")
        for field, value in case.items():
            if field.endswith("_hex"):
                if not isinstance(value, str) or len(value) % 2 or not re.fullmatch(r"[0-9a-f]*", value):
                    raise ValueError(f"{identity}.{field} must be canonical lowercase hex")
        fixture = (path.parent / case["fixture"]).resolve()
        fixture.relative_to(path.parent.resolve())
        if fixture.read_bytes().hex() != case["bytes_hex"]:
            raise ValueError(f"{identity} binary fixture differs from its reviewed byte vector")
        if sha256(fixture) != case["sha256_hex"]:
            raise ValueError(f"{identity} binary fixture digest differs from its reviewed digest")
    # Rust's independent fixture consumer must also execute in native-tests.
    return {"file": path.relative_to(ROOT).as_posix(), "sha256": sha256(path), "case_ids": sorted(identities), "scope": "fixture structure and identity; implementation comparison is a required Rust behavior case"}


def validate_epoch_vectors(path: Path) -> dict:
    data = json.loads(path.read_text())
    if (data.get("schema"), data.get("credential_format"), data.get("content_format"), data.get("suite")) != (1, 3, 3, 1):
        raise ValueError("explicit epoch fixture profile changed")
    files = data.get("files", {})
    expected = {"content-key.bin", "descriptor.bin", "head.bin", "record.bin", "recovery-kit.bin", "root-key.bin", data.get("node_file")}
    if set(files) != expected or len(files) != 7:
        raise ValueError("epoch fixture corpus changed")
    for name, identity in files.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("noncanonical epoch fixture path")
        target = path.parent / "epoch-vectors" / name
        if target.is_symlink() or target.stat().st_size != required_integer(identity["bytes"], "fixture length") or sha256(target) != identity["sha256"]:
            raise ValueError("fixed epoch fixture bytes differ: " + name)
    descriptor = (path.parent / "epoch-vectors/descriptor.bin").read_bytes()
    record = (path.parent / "epoch-vectors/record.bin").read_bytes()
    if (descriptor[:8] != b"FGVP0003" or descriptor[12:14] != b"\x00\x03"
        or record[:8] != b"FGVR0003" or record[8:24].hex() != data["record_id_hex"]
        or int.from_bytes(record[24:32], "big") != data["record_revision"]
        or int.from_bytes(record[32:40], "big") != data["root_epoch"]):
        raise ValueError("epoch fixture header/manifest mismatch")
    return {"file": path.relative_to(ROOT).as_posix(), "sha256": sha256(path), "files": len(files),
            "scope": "fixed fixture identity/header; real decoding and rejection required in core-tests; not independent cryptographic approval"}


def validate_access_vectors(path: Path, projection: Path, settings: dict) -> dict:
    """Fixed P3 identities; real parsing/unlock/audit is separately required Rust proof."""
    data = json.loads(path.read_text())
    if data.get("schema") != settings["schema"] or data.get("capture", {}).get("never_auto_regenerate") is not True:
        raise ValueError("P3 fixtures must be fixed captured inputs")
    cases, files = data.get("cases", []), data.get("files", [])
    ids = [row.get("id") for row in cases]
    if ids != settings["case_ids"] or len(set(ids)) != len(ids):
        raise ValueError("P3 fixture case inventory changed")
    if {boundary: sum(row.get("expected_boundary") == boundary for row in cases) for boundary in settings["boundary_counts"]} != settings["boundary_counts"]:
        raise ValueError("P3 fixture rejection boundaries changed")
    names = [row.get("path") for row in files]
    if len(files) != settings["file_count"] or len(set(names)) != len(names):
        raise ValueError("P3 fixture file inventory changed")
    for row in files:
        relative = row["path"]
        fixture = (path.parent / relative).resolve()
        if Path(relative).is_absolute() or fixture.relative_to(path.parent.resolve()).as_posix() != relative:
            raise ValueError("P3 fixture path must be canonical and local")
        if fixture.stat().st_size != required_integer(row.get("length"), "fixture length") or sha256(fixture) != row["sha256_hex"]:
            raise ValueError("P3 fixed bytes differ from their manifest")
    fields = ("id", "descriptor", "head", "recovery", "provider_key", "mode", "expected_boundary")
    expected = "# " + "\t".join(fields) + "\n"
    for row in cases:
        if row.get("mode") not in {"password", "wrong_password", "device", "device_without_password", "recovery"}:
            raise ValueError("unknown P3 fixture credential mode")
        if any(row.get(field) not in names for field in fields[1:5]):
            raise ValueError("P3 case references an undeclared fixed file")
        expected += "\t".join(row[field] for field in fields) + "\n"
    if projection.read_text() != expected:
        raise ValueError("P3 Rust projection differs from the fixed manifest")
    return {"case_ids": ids, "boundary_counts": settings["boundary_counts"], "files": len(files), "manifest_sha256": sha256(path), "projection_sha256": sha256(projection), "scope": "fixed fixture identity; parsing and cryptography execute in required core case"}


def validate_proof_file(path: Path, settings: dict) -> dict:
    """Require named actual cases and every selected proof input at current hashes."""
    report = json.loads(path.read_text())
    if report.get("schema") != settings["report_schema"] or report.get("pass") is not True or report.get("executed") is not True:
        raise ValueError("focused proof did not execute and pass")
    identity = validate_feasibility_identity(report, set(settings["source_files"]))
    evidence = validate_status_cases(report.get("cases"), settings["required_cases"])
    if {row["id"] for row in report["cases"]} != set(settings["required_cases"]) or any(row.get("executed") is not True for row in report["cases"]):
        raise ValueError("focused proof case inventory differs from contract")
    if "age_archive_sha256" in settings and report.get("tool", {}).get("archive_sha256") != settings["age_archive_sha256"]:
        raise ValueError("age interoperability proof used a different pinned tool archive")
    return {**identity, **evidence, "report": str(path), "sha256": sha256(path), "scope": report.get("scope")}


def validate_password_vectors(path: Path, projection: Path, settings: dict) -> dict:
    """Validate fixed Unicode vectors and their dependency-free Rust projection."""
    data = json.loads(path.read_text())
    if data.get("schema") != "fogvault-password-vectors/v1" or data.get("encoding") != "strict-utf8-no-normalization":
        raise ValueError("password vectors changed encoding/schema")
    rows = ["# kind\tid\tUTF-16 code units (hex, comma separated) or raw hex\texpected UTF-8 hex\n"]
    groups = {}
    encoded_text = {}
    all_ids = []

    def octets(value):
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
            raise ValueError("password bytes must be canonical lowercase hex")
        return bytes.fromhex(value)

    for kind in ("text", "invalid_utf16", "invalid_utf8", "raw_bytes"):
        vectors = data.get(kind)
        if not isinstance(vectors, list) or not vectors:
            raise ValueError("password vector group omitted: " + kind)
        ids = [row.get("id") for row in vectors]
        if ids != settings["groups"][kind] or any(not isinstance(name, str) or not name for name in ids):
            raise ValueError("password vector inventory differs: " + kind)
        groups[kind] = ids
        all_ids.extend(ids)
        for row in vectors:
            if kind in ("text", "invalid_utf16"):
                units = row.get("utf16_units")
                if not isinstance(units, list) or any(type(unit) is not int or not 0 <= unit <= 0xffff for unit in units):
                    raise ValueError("invalid UTF-16 code-unit fixture")
                raw = b"".join(unit.to_bytes(2, "little") for unit in units)
                try:
                    text = raw.decode("utf-16-le", "strict")
                except UnicodeDecodeError:
                    if kind != "invalid_utf16":
                        raise ValueError("valid-text fixture contains malformed UTF-16") from None
                else:
                    if kind == "invalid_utf16":
                        raise ValueError("invalid-text fixture is valid UTF-16")
                    expected = octets(row.get("utf8_hex"))
                    if text.encode("utf-8", "strict") != expected:
                        raise ValueError("text fixture does not match fixed UTF-8 bytes")
                    encoded_text[row["id"]] = expected
                value = ",".join(f"{unit:04x}" for unit in units)
            else:
                expected = octets(row.get("bytes_hex"))
                if kind == "invalid_utf8":
                    try:
                        expected.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        pass
                    else:
                        raise ValueError("invalid UTF-8 fixture is valid text")
                value = row["bytes_hex"]
            rows.append("\t".join([kind, row["id"], value, row.get("utf8_hex", "")]) + "\n")
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("password vector IDs must be unique across groups")
    pairs = data.get("distinct_text_pairs")
    if pairs != settings["distinct_text_pairs"] or any(len(pair) != 2 or pair[0] not in encoded_text or pair[1] not in encoded_text or encoded_text[pair[0]] == encoded_text[pair[1]] for pair in pairs):
        raise ValueError("password distinctions were removed or normalized")
    if data.get("lifecycle") != settings["lifecycle"]:
        raise ValueError("cross-host password lifecycle vectors changed")
    if projection.read_text() != "".join(rows):
        raise ValueError("Rust password-vector projection differs from shared JSON")
    return {"fixture": path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path), "sha256": sha256(path), "projection_sha256": sha256(projection), "groups": groups, "distinct_text_pairs": pairs, "scope": "exact credential encoding; no password-strength or platform qualification"}


def validate_growth_report(report: dict, contract: dict) -> dict:
    """The committed contract supplies reviewed mathematical bounds, never timings."""
    if report.get("schema") != "fogvault-index-growth/v1":
        raise ValueError("unsupported growth-report schema")
    index_contract = contract.get("index_growth")
    if not isinstance(index_contract, dict):
        raise ValueError("reviewed index growth contract is missing")
    key_bits = required_integer(report.get("key_bits"), "key_bits")
    if key_bits != index_contract["key_bits"]:
        raise ValueError("measured key width differs from the reviewed index contract")
    samples = report.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("growth report has no executed samples")
    populations = set()
    executed_pairs = set()
    head_sizes = set()
    operations = set()
    for sample in samples:
        records = required_integer(sample.get("records"), "records")
        operation = sample.get("operation")
        if operation not in index_contract["operations"]:
            raise ValueError(f"unexpected measured operation: {operation!r}")
        operations.add(operation)
        pair = (records, operation)
        if pair in executed_pairs:
            raise ValueError("growth report duplicated a population/operation sample")
        executed_pairs.add(pair)
        populations.add(records)
        metrics = sample.get("metrics")
        if not isinstance(metrics, dict):
            raise ValueError("sample metrics are missing")
        for field in ("nodes_read", "nodes_written", "node_bytes_read", "node_bytes_written", "max_path_depth", "records_scanned", "head_bytes"):
            required_integer(metrics.get(field), field)
        if metrics["max_path_depth"] > key_bits:
            raise ValueError("tree path exceeded the fixed key-space depth")
        head_sizes.add(metrics["head_bytes"])
        if metrics["head_bytes"] != index_contract["head_bytes"]:
            raise ValueError("measured head length differs from the committed format")
        bounds = index_contract["operations"][operation]
        if bounds.get("full_scan") is True:
            expected_nodes = 2 * records - 1 if records else 0
            expected_bytes = 57 * records + 82 * max(records - 1, 0)
            if metrics["records_scanned"] != records or metrics["nodes_read"] != expected_nodes:
                raise ValueError(f"{operation} did not audit exactly the committed tree and records")
            if metrics["node_bytes_read"] != expected_bytes or metrics["nodes_written"] != 0 or metrics["node_bytes_written"] != 0:
                raise ValueError(f"{operation} full-tree node byte volume or write count is inconsistent")
        else:
            if metrics["records_scanned"] != 0:
                raise ValueError("point operation scanned records")
            for field in ("nodes_read", "nodes_written"):
                if metrics[field] > bounds[field]:
                    raise ValueError(f"{operation} exceeded the reviewed {field} bound")
            if records and metrics["nodes_read"] == 0:
                raise ValueError("point operation reported no authenticated path reads")
        for count_field, bytes_field in (("nodes_read", "node_bytes_read"), ("nodes_written", "node_bytes_written")):
            if not 57 * metrics[count_field] <= metrics[bytes_field] <= 82 * metrics[count_field]:
                raise ValueError("node byte volume is inconsistent with canonical node widths")
        if sample.get("correctness") is not True:
            raise ValueError("measured operation has no successful correctness result")
    if len(populations) < 2:
        raise ValueError("growth comparison requires at least two distinct record populations")
    if operations != set(index_contract["operations"]):
        raise ValueError("growth report omitted required measured operation classes")
    required_populations = set(index_contract.get("record_populations", populations))
    if not required_populations <= populations:
        raise ValueError("growth report omitted required record populations")
    if executed_pairs != {(population, operation) for population in populations for operation in index_contract["operations"]}:
        raise ValueError("every measured population must execute all required operation classes")
    if len(head_sizes) != 1:
        raise ValueError("head storage grew with the measured population")
    return {"samples": len(samples), "record_populations": sorted(populations), "operations": sorted(operations), "head_bytes": next(iter(head_sizes)), "timing_policy": "observational only; no latency threshold"}


def validate_record_growth(report: dict, settings: dict, populations: list[int]) -> dict:
    if not isinstance(report, dict) or not isinstance(settings, dict) or report.get("schema") != settings["schema"] or report.get("page_size") != settings["page_size"]:
        raise ValueError("record growth report/contract is missing or changed")
    def sample(value, population, operation):
        if value.get("records") != population or value.get("operation") != operation or value.get("correctness") is not True:
            raise ValueError("record growth sample lacks exact executed correctness")
        for field in ("elapsed_ns", "baseline_allocated_bytes", "peak_allocated_bytes", "peak_live_allocated_bytes"):
            required_integer(value.get(field), field)
        metrics = value.get("metrics", {})
        for field in ("full_audits", "head_bytes", "head_bytes_written", "index_nodes_deleted", "max_path_depth", "node_bytes_read", "node_bytes_written", "nodes_read", "nodes_written", "record_bytes_read", "record_bytes_written", "record_rows_read", "records_scanned"):
            required_integer(metrics.get(field), field)
        if metrics["max_path_depth"] > 128:
            raise ValueError("record operation exceeded the key-space depth")
        for count, volume in (("nodes_read", "node_bytes_read"), ("nodes_written", "node_bytes_written")):
            if not 57 * metrics[count] <= metrics[volume] <= 82 * metrics[count]:
                raise ValueError("record operation canonical node volume differs")
        return metrics
    for section, operation in (("deletions", "delete"), ("enumerations", "enumerate")):
        rows = report.get(section)
        if not isinstance(rows, list) or sorted(row.get("sample", {}).get("records", -1) for row in rows) != populations:
            raise ValueError("record growth omitted or duplicated a required population")
        for row in rows:
            count = row["sample"]["records"]
            metrics = sample(row["sample"], count, operation)
            if section == "deletions":
                bounds = settings["deletion"]
                for field in ("nodes_read", "nodes_written", "index_nodes_deleted"):
                    if metrics[field] > bounds[field + "_max"]:
                        raise ValueError("deletion exceeded its authenticated-path work bound")
                if metrics["nodes_read"] < 2 or metrics["index_nodes_deleted"] < 1:
                    raise ValueError("deletion omitted authenticated membership/removal work")
                for field in ("record_rows_read", "record_bytes_written", "records_scanned", "full_audits", "head_bytes_written"):
                    if metrics[field] != bounds[field]:
                        raise ValueError("deletion unexpectedly scanned/rewrote record content")
                remaining = count - 1
                expected = {"remaining_records": remaining, "logical_nodes_before": 2 * count - 1, "logical_nodes_after": max(2 * remaining - 1, 0), "logical_node_bytes_after": 57 * remaining + 82 * max(remaining - 1, 0), "unrelated_record_checks": int(count > 1)}
                if any(row.get(field) != value for field, value in expected.items()) or any(row.get(field) is not True for field in bounds["required_flags"]):
                    raise ValueError("deletion failed exact remaining membership/content proof")
                if metrics["head_bytes"] != 129 or metrics["record_bytes_read"] != settings["fixture_envelope_bytes"] or required_integer(row.get("physical_db_bytes_after"), "physical database bytes") == 0:
                    raise ValueError("deletion omitted storage/selected-envelope observation")
            else:
                bounds = settings["enumeration"]
                page_size = settings["page_size"]
                pages = (count + page_size - 1) // page_size
                if row.get("page_size") != page_size or row.get("page_count") != pages or row.get("last_page_records") != (count - (pages - 1) * page_size):
                    raise ValueError("enumeration page completion count differs")
                expected = {"head_bytes": 129 * (pages + 1), "nodes_read": 2 * count - 1, "node_bytes_read": 57 * count + 82 * (count - 1), "record_rows_read": count, "records_scanned": count, "record_bytes_read": count * settings["fixture_envelope_bytes"], "nodes_written": 0, **{field: bounds[field] for field in ("node_bytes_written", "record_bytes_written", "head_bytes_written", "index_nodes_deleted", "full_audits")}}
                if any(metrics[field] != value for field, value in expected.items()):
                    raise ValueError("enumeration omitted or duplicated full snapshot work")
                begin = sample(row.get("begin", {}), count, "begin_records")
                if any(value != (129 if field == "head_bytes" else 0) for field, value in begin.items()):
                    raise ValueError("enumeration cursor creation performed unexpected work")
                limits = {"records_returned_max": min(page_size, count), "retained_proofs_max": min(page_size, count), "record_rows_per_page_max": min(page_size, count), "nodes_read_per_page_max": bounds["nodes_read_per_page_max"], "node_bytes_read_per_page_max": 82 * bounds["nodes_read_per_page_max"], "record_bytes_per_page_max": settings["fixture_envelope_bytes"] * min(page_size, count), "frontier_nodes_max": bounds["frontier_nodes_max"]}
                if any(not 0 < required_integer(row.get(field), field) <= maximum for field, maximum in limits.items()) or row.get("head_bytes_per_page") != 129:
                    raise ValueError("enumeration lost bounded page/frontier work")
                if any(row[field] != min(page_size, count) for field in ("records_returned_max", "retained_proofs_max", "record_rows_per_page_max")):
                    raise ValueError("enumeration omitted a full caller-sized page")
                for field in ("peak_allocated_bytes_per_page_max", "peak_live_allocated_bytes_per_page_max"):
                    required_integer(row.get(field), field)
                if any(row.get(field) is not True for field in bounds["required_true"]) or any(row.get(field) is not False for field in bounds["required_false"]):
                    raise ValueError("enumeration lost completion/identity or bounded-materialization proof")
    return {"deletions": len(report["deletions"]), "enumerations": len(report["enumerations"]), "page_size": settings["page_size"], "complete_enumeration_cost": "linear", "timing_policy": "observational only"}


def core_source_paths() -> list[Path]:
    return [CORE / "Cargo.toml", CORE / "Cargo.lock", *sorted((CORE / "src").rglob("*.rs")), *sorted((CORE / "tests").rglob("*.rs")), *sorted((CORE / "examples").rglob("*.rs"))]


def growth_source_identity(manifest: Path) -> dict[str, str]:
    paths = [manifest, manifest.parent / "Cargo.lock", ROOT / "scripts/measure-index.py", *core_source_paths(), *maintained_sources(ROOT)]
    for directory in ("src", "examples", "benches"):
        paths.extend(sorted((manifest.parent / directory).rglob("*.rs")))
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in paths}


def verification_source_identity(manifest: Path, with_feasibility: bool = False) -> dict[str, str]:
    paths = [CONTRACT, manifest, manifest.parent / "Cargo.lock", Path(__file__), ROOT / "tests/verifier_checks.py", ROOT / "scripts/playwright-cli.sh", *core_source_paths(), *maintained_sources(ROOT)]
    paths.extend(sorted((ROOT / "conformance").rglob("*")))
    paths.extend(sorted((ROOT / "scripts").glob("*.py")))
    paths.extend(sorted((ROOT / "tests").glob("*.py")))
    # The legacy-rejection test reads this retained synthetic database at runtime.
    # It is a fixed input, even though its historical path is under evidence/.
    paths.append(ROOT / "experiments/vault-prototype/evidence/PROTOTYPE-WIPE-ME.sqlite")
    if "epoch_vectors" in json.loads(CONTRACT.read_text()):
        epoch = json.loads((ROOT / json.loads(CONTRACT.read_text())["epoch_vectors"]).read_text())
        paths.append(ROOT / epoch["capture_recipe"])
    for section in ("export_payload", "dependency_audit", "rust_export_screening", "trusted_control_host", "independent_epoch", "fresh_epoch"):
        paths.extend(ROOT / relative for relative in json.loads(CONTRACT.read_text()).get(section, {}).get("source_files", []))
    for directory in ("src", "tests", "examples", "benches"):
        paths.extend(sorted((manifest.parent / directory).rglob("*.rs")))
    if with_feasibility:
        for name in ("browser-prototype", "mobile-prototype"):
            paths.extend(host_source_paths(ROOT / "experiments" / name))
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in sorted(set(paths)) if path.is_file()}


def host_source_paths(directory: Path) -> list[Path]:
    paths = []
    for parent, directories, files in os.walk(directory):
        directories[:] = [name for name in directories if name not in {"target", "pkg", "evidence", "node_modules", "__pycache__", ".playwright-cli", "output"}]
        for name in files:
            path = Path(parent) / name
            if path.suffix in {".rs", ".js", ".mjs", ".html", ".c", ".h", ".swift", ".py"} or name in {"Cargo.toml", "Cargo.lock", "package.json", "package-lock.json"}:
                paths.append(path)
    return paths


def validate_extension_file(path: Path) -> dict:
    report = json.loads(path.read_text())
    if report.get("schema") != "fogvault-extension-proof/v1" or report.get("pass") is not True or report.get("executed") is not True:
        raise ValueError("packaged browser extension acceptance failed")
    stats = report["stats"]
    if stats.get("expected") != 2 or any(stats.get(key, 1) for key in ("unexpected", "skipped", "flaky")):
        raise ValueError("extension proof omitted, skipped or failed a required host")
    raw = Path(report["playwright_report"])
    if sha256(raw) != report["playwright_sha256"]:
        raise ValueError("extension raw evidence changed")
    return validate_feasibility_identity(report, {p.relative_to(ROOT).as_posix() for p in maintained_sources(ROOT)})


def validate_sdk_file(path: Path, engines: list[str] | None = None) -> dict:
    report = json.loads(path.read_text())
    settings = json.loads((ROOT / "conformance/maintained-contract.json").read_text())["browser_sdk"]
    if (not isinstance(report, dict) or report.get("schema") != "fogvault-browser-sdk-proof/v1"
            or report.get("pass") is not True or report.get("executed") is not True):
        raise ValueError("maintained browser SDK did not execute successfully")
    expected_engines = settings["required_engines"] if engines is None else engines
    allowed_engines = set(settings["required_engines"] + settings.get("ci_additional_engines", []))
    if (not isinstance(expected_engines, list) or not expected_engines
            or any(not isinstance(name, str) for name in expected_engines)
            or len(expected_engines) != len(set(expected_engines))
            or not set(expected_engines) <= allowed_engines):
        raise ValueError("SDK profile must name distinct supported browser engines")
    identity = validate_feasibility_identity(report, {p.relative_to(ROOT).as_posix() for p in maintained_sources(ROOT)})
    reported_engines = report.get("engines")
    if (not isinstance(reported_engines, list) or any(not isinstance(engine, dict) for engine in reported_engines)
            or [engine.get("name") for engine in reported_engines] != expected_engines):
        raise ValueError("maintained SDK omitted a required browser engine")
    for engine in reported_engines:
        validate_browser_cases(engine.get("result"), settings)
    candidate = report.get("candidate")
    if (not isinstance(candidate, dict)
            or candidate.get("schema") != "fogvault-installed-browser-candidate/v1"
            or candidate.get("typecheck_executed") is not True
            or candidate.get("import_smoke_executed") is not True):
        raise ValueError("maintained SDK must test the installed packed candidate and public types")
    package = candidate.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("path"), str):
        raise ValueError("maintained SDK omitted its packed artifact identity")
    artifact = Path(package["path"])
    if not artifact.is_absolute():
        artifact = ROOT / artifact
    actual = artifact_identity(artifact)
    if (package.get("bytes") != actual["bytes"] or package.get("sha256") != actual["sha256"]
            or candidate.get("package_sha256") != actual["sha256"]):
        raise ValueError("maintained SDK packed artifact changed")
    assets = candidate.get("installed_assets")
    required_assets = {"dist/client.mjs", "dist/worker.mjs", "dist/index.d.ts",
                       "dist/wasm/fogvault_wasm.js", "dist/wasm/fogvault_wasm_bg.wasm"}
    if not isinstance(assets, dict) or not required_assets.issubset(assets):
        raise ValueError("maintained SDK omitted installed entry/Worker/WASM/type assets")
    try:
        with tarfile.open(artifact, "r:gz") as archive:
            names = [entry.name for entry in archive.getmembers()]
            if len(names) != len(set(names)):
                raise ValueError("packed SDK contains duplicate paths")
            for relative in required_assets:
                member = archive.getmember("package/" + relative)
                if not member.isfile():
                    raise ValueError("packed SDK asset is not an ordinary file")
                with archive.extractfile(member) as source:
                    if hashlib.file_digest(source, "sha256").hexdigest() != assets[relative]:
                        raise ValueError("installed SDK asset does not match the packed candidate")
    except (tarfile.TarError, KeyError, EOFError, OSError) as error:
        raise ValueError("maintained SDK packed candidate is missing or malformed") from error
    return {**identity, "engines": list(expected_engines), "cases": settings["required_cases"],
            "candidate": actual}


def require_stable_sources(before: dict[str, str], after: dict[str, str]) -> dict:
    if before != after:
        changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
        raise ValueError("verification inputs changed while checks ran; rerun against stable sources: " + ", ".join(changed))
    return {"source_files": len(before), "unchanged_during_run": True}


def validate_growth_file(path: Path, contract: dict, manifest: Path) -> dict:
    report = json.loads(path.read_text())
    if report.get("source_identity") != growth_source_identity(manifest):
        raise ValueError("growth report source identity differs from the current implementation/runner/lockfile")
    result = validate_growth_report(report, contract)
    records = validate_record_growth(report.get("record_operations"), contract["index_growth"]["record_operations"], result["record_populations"])
    return {**result, "record_operations": records, "report": str(path), "sha256": sha256(path), "source_identity": report["source_identity"]}


def validate_access_file(path: Path, contract: dict) -> dict:
    """Check executed policy-model evidence without treating it as real unlock proof."""
    report = json.loads(path.read_text())
    expected = contract["access_paths"]
    if report.get("schema") != expected["report_schema"] or report.get("pass") is not True or report.get("executed") is not True:
        raise ValueError("the access-path model did not execute successfully")
    if report.get("scope") != "symbolic-policy-only" or report.get("crypto_or_provider_execution") is not False:
        raise ValueError("the access-path model must not claim cryptographic/provider execution")
    count = report.get("truth_table_combinations")
    if type(count) is not int or count != expected["truth_table_combinations"]:
        raise ValueError("the access-path model omitted credential combinations")
    cases = report.get("cases")
    required = expected["required_cases"]
    if type(report.get("case_count")) is not int or report["case_count"] != len(required):
        raise ValueError("the access-path case count differs from the required inventory")
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        raise ValueError("the access-path model omitted executed cases")
    if len(cases) != len(required) or {case.get("id") for case in cases} != set(required):
        raise ValueError("the access-path model omitted or duplicated a required case")
    if any(case.get("status") != "pass" or case.get("executed") is not True for case in cases):
        raise ValueError("a required access-path case did not execute successfully")
    ids = report.get("executed_case_ids")
    if not isinstance(ids, list) or len(ids) != len(required) or set(ids) != set(required):
        raise ValueError("the access-path case inventory differs from executed evidence")
    sources = [ROOT / expected["definition"], ROOT / "scripts/verify-access-paths.py"]
    identity = {source.relative_to(ROOT).as_posix(): sha256(source) for source in sources}
    if report.get("source_identity") != identity:
        raise ValueError("the access-path model inputs differ from the current definition/checker")
    return {"report": str(path), "sha256": sha256(path), "scope": report["scope"], "crypto_or_provider_execution": False, "truth_table_combinations": count, "executed_cases": required, "source_identity": identity}


def validate_feasibility_identity(report: dict, required: set[str]) -> dict:
    identity = report.get("source_identity")
    if not isinstance(identity, dict) or not required <= identity.keys():
        raise ValueError("feasibility report omitted required source/lock identities")
    for relative, digest in identity.items():
        if not isinstance(relative, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("feasibility source identity is malformed")
        path = (ROOT / relative).resolve()
        canonical = path.relative_to(ROOT).as_posix()
        if Path(relative).is_absolute() or relative != canonical:
            raise ValueError("feasibility identities must use canonical repository-relative paths")
        if not path.is_file() or sha256(path) != digest:
            raise ValueError("feasibility source differs from the measured input: " + relative)
    return {"source_files": len(identity), "current_sources_match": True}


def portable_identity_paths(manifest: Path) -> set[str]:
    paths = [manifest, manifest.parent / "Cargo.lock", *sorted((manifest.parent / "src").rglob("*.rs")), *core_source_paths(), *maintained_sources(ROOT)]
    return {path.relative_to(ROOT).as_posix() for path in paths}


def validate_status_cases(cases: list[dict], required: list[str]) -> dict:
    if not isinstance(cases, list) or len({case.get("id") for case in cases}) != len(cases):
        raise ValueError("feasibility cases are missing or duplicate")
    by_id = {case.get("id"): case for case in cases}
    if not set(required) <= by_id.keys():
        raise ValueError("required feasibility cases did not execute")
    if any(by_id[name].get("status") != "pass" or by_id[name].get("executed") is False for name in required):
        raise ValueError("required feasibility case failed or was unavailable")
    if any(case.get("status") != "pass" for case in cases):
        raise ValueError("reported feasibility case failed or was unavailable")
    return {"executed_cases": sorted(by_id)}


def validate_resource_report(report: dict, contract: dict, manifest: Path) -> dict:
    if report.get("schema") != "fogvault-resource-budgets/v1":
        raise ValueError("unsupported resource report schema")
    expected = contract["resources"]
    identity = validate_feasibility_identity(report, portable_identity_paths(manifest) | {"scripts/measure-resources.py"})
    if report.get("repetitions") != expected["repetitions"] or set(report.get("payload_populations", [])) != set(expected["payload_bytes"]):
        raise ValueError("resource report omitted required workload/repetition coverage")
    consumer = report.get("consumer_limit", {})
    source = ROOT / "research/consumer/datafog-core-0.5.0-beta.3/published-source/src/workspace.rs"
    if consumer.get("bytes") != expected["consumer_payload_bytes"] or consumer.get("source_sha256") != sha256(source) or consumer.get("version") != "0.5.0-beta.3":
        raise ValueError("resource consumer bound/provenance differs from the exact reviewed consumer")
    runs = report.get("runs", [])
    workload_ids = [(run.get("kind"), run.get("payload_bytes")) for run in runs]
    required_workloads = {("kdf", 0)} | {("payload", payload) for payload in expected["payload_bytes"]}
    if len(workload_ids) != len(required_workloads) or set(workload_ids) != required_workloads:
        raise ValueError("resource report omitted or duplicated required workloads")
    observed_cases = set()
    for run in runs:
        if run.get("release_profile") is not True or run.get("kdf") != expected["kdf"]:
            raise ValueError("resource report changed the release profile or pinned KDF")
        rss = run.get("process_memory", {})
        if rss.get("status") != "measured" or required_integer(rss.get("peak_rss_bytes"), "peak_rss_bytes") == 0:
            raise ValueError("required process-lifetime RSS measurement is unavailable")
        kind, payload = run["kind"], run["payload_bytes"]
        operations = expected["kdf_operations"] if kind == "kdf" else expected["payload_operations"]
        samples = run.get("samples", [])
        pairs = [(sample.get("operation"), sample.get("repetition")) for sample in samples]
        required_pairs = {(operation, repetition) for operation in operations for repetition in range(expected["repetitions"])}
        if len(pairs) != len(required_pairs) or set(pairs) != required_pairs:
            raise ValueError("required resource operation/repetition did not execute")
        for sample in samples:
            if sample.get("correctness") is not True:
                raise ValueError("resource operation did not pass correctness")
            for field in ("elapsed_ns", "baseline_allocated_bytes", "peak_allocated_bytes", "peak_live_allocated_bytes", "ending_allocated_bytes"):
                required_integer(sample.get(field), field)
            if sample["peak_live_allocated_bytes"] != sample["baseline_allocated_bytes"] + sample["peak_allocated_bytes"] or sample["ending_allocated_bytes"] > sample["peak_live_allocated_bytes"]:
                raise ValueError("resource allocation accounting is inconsistent")
            operation = sample["operation"]
            case_id = f"payload/{payload}/{operation}" if kind == "payload" else f"kdf/{operation}"
            if sample.get("case_id") != case_id:
                raise ValueError("resource stable case identity changed")
            observed_cases.add(case_id)
            if operation in {"kdf_rejected", "payload_rejected"} and sample["peak_allocated_bytes"] != 0:
                raise ValueError("rejected input allocated measured Rust work memory")
            if operation == "kdf" and sample["peak_allocated_bytes"] < expected["kdf"]["memory_kib"] * 1024:
                raise ValueError("KDF measurement omitted its required work memory")
            if sample.get("concurrency") != (2 if operation == "kdf_concurrent" else 1):
                raise ValueError("resource concurrency workload identity changed")
            if sample.get("payload_bytes") != payload or sample.get("input_payload_bytes") != payload + (1 if operation == "payload_rejected" else 0):
                raise ValueError("resource sample input differs from the admitted/rejected payload workload")
            if kind == "payload":
                envelope = payload + 32 + 176
                metrics = sample.get("metrics", {})
                if run.get("metadata_bytes") != 32 or run.get("records") != 1 or run.get("envelope_bytes") != envelope:
                    raise ValueError("resource record framing differs from current content 3")
                if operation not in {"create", "payload_rejected"} and metrics.get("head_bytes") != 129:
                    raise ValueError("resource measured head is not fixed width")
                if operation in {"read", "save", "update"} and metrics.get("records_scanned") != 0:
                    raise ValueError("resource point operation scanned record inventory")
                if operation in {"save", "update"} and metrics.get("record_bytes_written") != envelope:
                    raise ValueError("resource save did not write the complete bounded envelope")
                if operation == "read" and (metrics.get("record_bytes_read") != envelope or metrics.get("nodes_read") != 1):
                    raise ValueError("resource selected read byte/path work is inconsistent")
                if operation in {"unlock", "audit"} and (metrics.get("records_scanned") != 1 or metrics.get("nodes_read") != 1):
                    raise ValueError("resource inventory operation omitted committed membership")
                if operation in {"unlock", "unlock_empty"} and metrics.get("record_bytes_read") != 0:
                    raise ValueError("metadata unlock fetched ciphertext bodies")
                if operation == "audit" and metrics.get("record_bytes_read") != envelope:
                    raise ValueError("resource full audit omitted ciphertext hashing")
    if report.get("samples") != [sample for run in runs for sample in run["samples"]]:
        raise ValueError("flattened resource samples differ from executed workload evidence")
    return {**identity, "workloads": len(runs), "cases": len(observed_cases), "samples": len(report["samples"]), "timing_policy": "observations only; no SLO or product quota selected"}


def validate_browser_growth(growth: list[dict], settings: dict, storage_profile: str) -> dict:
    if not isinstance(growth, list):
        raise ValueError("browser omitted streaming startup growth evidence")
    populations = [sample.get("records") for sample in growth]
    if len(populations) != len(set(populations)) or set(populations) != set(settings["record_populations"]):
        raise ValueError("browser startup growth omitted or duplicated required populations")
    for sample in growth:
        if sample.get("correctness") is not True:
            raise ValueError("browser startup growth did not pass correctness")
        records = required_integer(sample.get("records"), "records")
        for field in ("nodes_read", "records_checked", "node_bytes", "max_stack_nodes", "max_cached_nodes", "max_record_rows", "get_all_calls", "transactions", "header_transactions", "head_bytes", "record_bodies_materialized", "memory_bytes"):
            required_integer(sample.get(field), field)
        if sample["nodes_read"] != 2 * records - 1 or sample["records_checked"] != records or sample["node_bytes"] != 139 * records - 82:
            raise ValueError("streamed startup did not visit the exact committed tree/records")
        if not 1 <= sample["max_stack_nodes"] <= settings["key_bits"] + 1:
            raise ValueError("streaming audit frontier exceeded the key-width bound")
        if sample["max_cached_nodes"] != 1 or sample["max_record_rows"] != 1 or sample["get_all_calls"] != 0:
            raise ValueError("startup materialized more than one fetched node/row or used getAll")
        if sample["transactions"] != 1 or sample["header_transactions"] != 1:
            raise ValueError("startup failed to use one audit snapshot plus its separate pre-KDF header read")
        if sample["head_bytes"] != settings["head_bytes"]:
            raise ValueError("browser startup head width drifted")
        if sample["record_bodies_materialized"] != (records if storage_profile == "arraybuffer" else 0):
            raise ValueError("browser startup omitted its storage-profile body-cloning cost")
        if sample["memory_bytes"] == 0 or sample["memory_bytes"] % 65536:
            raise ValueError("startup WASM extent is not page aligned")
        elapsed = sample.get("elapsed_ms")
        if type(elapsed) not in (int, float) or elapsed < 0 or not math.isfinite(elapsed):
            raise ValueError("startup timing observation is malformed")
    return {"record_populations": sorted(populations), "snapshot_transactions": 1, "whole_inventory_materialized": False, "frontier_bound": settings["key_bits"] + 1, "timing_policy": "observation only; no latency or process-memory gate"}


def validate_browser_passwords(result: dict, settings: dict) -> dict:
    if settings.get("fixture") != "conformance/password-vectors.json":
        raise ValueError("browser password fixture changed")
    fixture = json.loads((ROOT / settings["fixture"]).read_text())
    by_id = {case["id"]: case for case in result["cases"]}
    text = by_id[settings["text_case"]]
    if text.get("vectors") != [{"id": row["id"], "utf8_hex": row["utf8_hex"]} for row in fixture["text"]] or text.get("invalid_utf16_ids") != [row["id"] for row in fixture["invalid_utf16"]]:
        raise ValueError("browser omitted or changed exact password vectors")
    lifecycle = by_id[settings["lifecycle_case"]]
    for field in ("old_password", "new_password", "raw_password"):
        if lifecycle.get(field + "_id") != fixture["lifecycle"][field]:
            raise ValueError("browser password lifecycle used different shared credentials")
    boundary = by_id[settings["byte_boundary_case"]]
    available = boundary.get("shared_array_buffer_available")
    if type(available) is not bool or boundary.get("shared_binding_rejection_executed") is not available or boundary.get("shared_worker_rejection_executed") is not available:
        raise ValueError("browser shared-buffer evidence overstated or omitted execution")
    count = boundary.get("shared_binding_rejections")
    if type(count) is not int or count != (7 if available else 0):
        raise ValueError("browser shared-buffer rejection count differs from its executed scope")
    return {"text_vectors": len(fixture["text"]), "malformed_utf16_vectors": len(fixture["invalid_utf16"])}


def validate_password_adapter_node(report: dict, settings: dict) -> dict:
    evidence = report.get("password_adapter_node", {})
    if evidence.get("schema") != settings["schema"] or evidence.get("scope") != settings["scope"] or evidence.get("pass") is not True or evidence.get("executed") is not True:
        raise ValueError("Node password-helper checks did not execute in their declared scope")
    if not isinstance(evidence.get("node"), str) or not evidence["node"].startswith("v") or evidence.get("shared_array_buffer_available") is not True:
        raise ValueError("Node helper omitted its actual runtime/shared-buffer capability")
    cases = evidence.get("cases", [])
    if len(cases) != len(settings["cases"]) or [case.get("id") for case in cases] != settings["cases"] or any(case.get("executed") is not True or case.get("status") != "pass" for case in cases):
        raise ValueError("Node password-helper cases are missing, failed or unexecuted")
    identity = {relative: sha256(ROOT / relative) for relative in settings["source_files"]}
    if evidence.get("source_identity") != identity:
        raise ValueError("Node password-helper source identity changed")
    return {"scope": evidence["scope"], "executed_cases": settings["cases"], "source_identity": identity}


def validate_mobile_passwords(report: dict, settings: dict) -> dict:
    if settings.get("fixture") != "conformance/password-vectors.json":
        raise ValueError("mobile password fixture changed")
    fixture_path = ROOT / settings["fixture"]
    fixture = json.loads(fixture_path.read_text())
    digest = sha256(fixture_path)
    expected = {case: [row["id"] for row in fixture[group]] for case, group in settings["groups"].items()}
    evidence = report.get("password_vectors", {})
    if evidence.get("fixture") != settings["fixture"] or evidence.get("sha256") != digest or evidence.get("groups") != expected:
        raise ValueError("mobile omitted current password fixture provenance/groups")
    header = evidence.get("generated_header", {})
    path = Path(header.get("path", ""))
    if not path.is_file() or type(header.get("bytes")) is not int or header["bytes"] != path.stat().st_size or header.get("sha256") != sha256(path):
        raise ValueError("mobile generated password header is absent or changed")
    for target in report["targets"]:
        if target["id"] not in {"native-abi-runtime", "ios-simulator-abi-runtime"}:
            continue
        if header not in target.get("artifacts", []):
            raise ValueError("mobile runtime omitted its compiled password header artifact")
        by_id = {case["id"]: case for case in target["cases"]}
        for case_id, ids in expected.items():
            case = by_id[case_id]
            if case.get("executed") is not True or case.get("fixture_sha256") != digest or case.get("vector_ids") != ids or type(case.get("vectors_checked")) is not int or case["vectors_checked"] != len(ids):
                raise ValueError("mobile password case omitted or changed executed vectors")
    return {case: len(ids) for case, ids in expected.items()}


def validate_browser_records(cases: dict, settings: dict, storage_profile: str) -> dict:
    sample = cases.get(settings["page_case"], {})
    for field in ("page_size", "source_records", "source_nodes", "page_lengths"):
        if sample.get(field) != settings[field]:
            raise ValueError("browser record-page inventory changed: " + field)
    pages = sample.get("pages")
    if not isinstance(pages, list) or len(pages) != len(settings["page_lengths"]):
        raise ValueError("browser omitted page work observations")
    total_nodes = total_bytes = total_records = 0
    for length, page in zip(settings["page_lengths"], pages):
        for field in ("nodes_read", "node_bytes", "records_checked", "max_stack_nodes", "transactions", "get_all_calls", "max_cached_nodes", "max_record_rows", "retained_page_records", "record_bodies_materialized", "arraybuffer_row_clones"):
            required_integer(page.get(field), field)
        if page["records_checked"] != length or page["record_bodies_materialized"] != length or page["retained_page_records"] != length:
            raise ValueError("browser page omitted per-envelope authentication/materialization")
        if page["arraybuffer_row_clones"] != (length if storage_profile == "arraybuffer" else 0):
            raise ValueError("browser page omitted the storage-profile row clone cost")
        if page["transactions"] != 1 or page["get_all_calls"] != 0 or page["max_cached_nodes"] != 1 or page["max_record_rows"] != 1:
            raise ValueError("browser page lost its single-transaction bounded fetch contract")
        if not 0 < page["max_stack_nodes"] <= settings["maximum_frontier_nodes"] or page["retained_page_records"] > settings["page_size"]:
            raise ValueError("browser record cursor/page exceeded its declared bound")
        if not 57 * page["nodes_read"] <= page["node_bytes"] <= 82 * page["nodes_read"]:
            raise ValueError("browser record-page canonical node bytes differ")
        total_nodes += page["nodes_read"]
        total_bytes += page["node_bytes"]
        total_records += page["records_checked"]
    count = settings["source_records"]
    if total_records != count or total_nodes != 2 * count - 1 or total_nodes != settings["source_nodes"] or total_bytes != 57 * count + 82 * (count - 1):
        raise ValueError("browser paged traversal omitted or duplicated committed membership")
    return {"pages": len(pages), "records_checked": total_records, "nodes_read": total_nodes}


def validate_browser_report(report: dict, contract: dict, manifest: Path) -> dict:
    if report.get("schema") != "fogvault-browser-feasibility/v1" or report.get("pass") is not True:
        raise ValueError("browser feasibility did not pass its declared scope")
    project = ROOT / "experiments/browser-prototype"
    required = portable_identity_paths(manifest) | {path.relative_to(ROOT).as_posix() for path in host_source_paths(project)} | {"scripts/verify-browser.py", "conformance/password-vectors.json"}
    identity = validate_feasibility_identity(report, required)
    engines = report.get("engines", [])
    names = [engine.get("name") for engine in engines]
    expected = contract["browser"]
    validate_password_adapter_node(report, expected["password_adapter_node"])
    if len(names) != len(set(names)) or set(names) != set(expected["engines"]):
        raise ValueError("required browser engine did not execute")
    cases = {}
    for engine in engines:
        result = engine.get("result", {})
        if result.get("pass") is not True or result.get("schema") != "fogvault-browser-feasibility/v1":
            raise ValueError("browser engine did not report a passing fixture")
        cases[engine["name"]] = validate_status_cases(result.get("cases"), expected["cases"])
        if result.get("scope", {}).get("storage_profile") != expected["storage_profiles"][engine["name"]]:
            raise ValueError("browser adapter profile changed without an explicit contract change")
        if result.get("scope", {}).get("storage_schema_version") != expected["streaming_startup"]["storage_schema_version"]:
            raise ValueError("browser storage schema changed without an explicit contract change")
        validate_browser_growth(result.get("growth"), expected["streaming_startup"], expected["storage_profiles"][engine["name"]])
        environment = result.get("environment", {})
        if any(environment.get(key) is not True for key in ("secure_context", "indexeddb", "webassembly", "worker")) or not environment.get("user_agent"):
            raise ValueError("browser runtime capabilities/environment were not observed")
        by_id = {case["id"]: case for case in result["cases"]}
        validate_browser_passwords(result, expected["password_vector_cases"])
        validate_browser_records(by_id, expected["record_operations"], expected["storage_profiles"][engine["name"]])
        for case_id, fields in expected["required_evidence"].items():
            if any(by_id[case_id].get(field) is not True for field in fields):
                raise ValueError("browser omitted a required transaction regression: " + case_id)
        for case_id, fields in expected.get("required_counts", {}).items():
            for field, value in fields.items():
                observed = required_integer(by_id[case_id].get(field), case_id + "." + field)
                if observed != required_integer(value, "contract " + case_id + "." + field):
                    raise ValueError("browser credential work/admission count differs from its required evidence: " + case_id + "." + field)
        if by_id["core_16mib_opaque_payload_roundtrip"].get("payload_bytes") != expected["payload_bytes"]:
            raise ValueError("browser omitted the exact consumer-sized payload crossing")
        if required_integer(by_id["worker_kdf_keeps_main_event_loop_running"].get("timer_callbacks"), "timer_callbacks") == 0:
            raise ValueError("main-thread progress was not observed during Worker KDF")
        crossings = by_id["u64_revision_crossing_preserves_all_bits"]
        if crossings.get("values") != ["9007199254740993", "9223372036854775807"] or crossings.get("number_input_rejected") is not True:
            raise ValueError("browser integer boundary omitted exact large revisions")
        admission = by_id["oversized_input_rejected_before_wasm_copy"]
        if admission.get("head_unchanged") is not True or admission.get("wasm_extent_unchanged") is not True:
            raise ValueError("browser rejected-input admission changed state/memory extent")
        samples = result.get("samples", [])
        if not samples:
            raise ValueError("browser omitted resource observations")
        for sample in samples:
            elapsed = sample.get("elapsed_ms")
            if type(elapsed) not in (int, float) or elapsed < 0 or not math.isfinite(elapsed):
                raise ValueError("browser elapsed observation is malformed")
            memory = required_integer(sample.get("memory_bytes"), "memory_bytes")
            if memory == 0 or memory % 65536:
                raise ValueError("browser linear memory extent is not page aligned")
        if max(sample["memory_bytes"] for sample in samples) < 65536 * 1024:
            raise ValueError("browser measurement omitted the pinned KDF work memory")
    return {**identity, "engines": names, "cases": cases, "scope": "desktop engine Worker/IndexedDB experiment; runtime and memory observations, no product qualification"}


def validate_mobile_report(report: dict, contract: dict, manifest: Path) -> dict:
    # The runner names exact runtime/build/check scopes; unavailable targets cannot
    # be silently counted as successful executions in this explicitly local profile.
    if report.get("schema") != "fogvault-mobile-feasibility/v1" or report.get("pass") is not True:
        raise ValueError("mobile feasibility did not pass its declared scope")
    project = ROOT / "experiments/mobile-prototype"
    required = portable_identity_paths(manifest) | {path.relative_to(ROOT).as_posix() for path in host_source_paths(project)} | {"scripts/verify-mobile.py", "conformance/password-vectors.json"}
    identity = validate_feasibility_identity(report, required)
    validate_status_cases(report.get("checks"), contract["mobile"]["checks"])
    targets = report.get("targets", [])
    target_evidence = validate_status_cases(targets, contract["mobile"]["targets"])
    for target in targets:
        if target.get("executed") is not True:
            raise ValueError("mobile target was not actually executed")
        if target["id"] in {"native-abi-runtime", "ios-simulator-abi-runtime"}:
            validate_status_cases(target.get("cases"), contract["mobile"]["runtime_cases"])
    validate_mobile_passwords(report, contract["mobile"]["password_vector_cases"])
    return {**identity, **target_evidence, "scope": contract["scope"]}


def validate_host_file(path: Path, kind: str, contract: dict, manifest: Path) -> dict:
    report = json.loads(path.read_text())
    validators = {"resource-budgets": validate_resource_report, "browser-feasibility": validate_browser_report, "mobile-feasibility": validate_mobile_report}
    evidence = validators[kind](report, contract, manifest)
    return {**evidence, "report": str(path), "sha256": sha256(path)}


class Verifier:
    def __init__(self, run_dir: Path, contract: dict, json_output: bool):
        self.run_dir = run_dir
        self.contract = contract
        self.json_output = json_output
        self.checks: list[dict] = []

    def record(self, identity: str, status: str, **details) -> dict:
        result = {"id": identity, "required": True, "status": status, **details}
        self.checks.append(result)
        if not self.json_output:
            print(f"{status.upper():11} {identity}" + (f": {result['message']}" if result.get("message") else ""), flush=True)
        return result

    def builtin(self, identity: str, function) -> dict:
        started = time.perf_counter()
        try:
            evidence = function()
            return self.record(identity, "pass", executed=True, duration_seconds=time.perf_counter() - started, evidence=evidence)
        except (OSError, ValueError, KeyError, TypeError) as error:
            return self.record(identity, "fail", executed=True, duration_seconds=time.perf_counter() - started, message=str(error))

    def command(self, identity: str, command: list[str], validator=None) -> dict:
        started = time.perf_counter()
        log = self.run_dir / f"{identity}.log"
        if shutil.which(command[0]) is None:
            return self.record(identity, "unavailable", executed=False, command=command, message=f"required executable unavailable: {command[0]}")
        try:
            with log.open("w") as output:
                process = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, check=False, env={**os.environ, "CARGO_TERM_COLOR": "never"})
            details = {"executed": True, "command": command, "exit_code": process.returncode, "duration_seconds": time.perf_counter() - started, "log": str(log)}
            if process.returncode != 0:
                return self.record(identity, "fail", **details, message="required command failed; inspect retained log")
            evidence = validator(log.read_text()) if validator else None
            return self.record(identity, "pass", **details, evidence=evidence)
        except Unavailable as error:
            return self.record(identity, "unavailable", executed=True, command=command, duration_seconds=time.perf_counter() - started, log=str(log), message=str(error))
        except (OSError, ValueError, KeyError, TypeError) as error:
            return self.record(identity, "fail", executed=True, command=command, duration_seconds=time.perf_counter() - started, log=str(log), message=str(error))


def tool_version(command: list[str]) -> dict:
    if shutil.which(command[0]) is None:
        return {"available": False}
    process = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return {"available": process.returncode == 0, "exit_code": process.returncode, "output": process.stdout.strip()}


def required_checks(with_feasibility: bool = False) -> list[str]:
    """The exact stage inventory consumed by the runner and its parent gate."""
    expected_checks = ["verifier-tests", "consumer-pin", "core-boundary", "format-fixtures", "epoch-format-fixtures", "independent-epoch-decoder", "fresh-epoch-decoder", "access-format-fixtures", "password-vectors", "access-path-model", "export-payload", "export-backend-screening", "dependency-audit", "core-format", "format", "core-clippy", "clippy", "core-tests", "core-public-api", "native-tests", "maintained-native-format", "maintained-native-clippy", "maintained-native-api", "maintained-backup-format", "maintained-backup-clippy", "maintained-backup-tests", "maintained-wasm-format", "wasm-target", "maintained-wasm-clippy", "core-wasm-compile", "wasm-compile", "index-growth", "source-stability"]
    if with_feasibility:
        expected_checks = expected_checks[:-1] + ["resource-budgets", "browser-feasibility", "browser-sdk", "browser-extensions", "mobile-feasibility", "trusted-control-host", "source-stability"]
    return expected_checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print one machine-readable result instead of progress lines")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments/vault-prototype/evidence/verifier-runs", help="parent for a fresh immutable run directory")
    parser.add_argument("--with-feasibility", action="store_true", help="also require the local browser/mobile/resource experiment profile; unavailable required targets fail explicitly")
    parser.add_argument("--benchmark-report", type=Path, help="validate a separately executed growth report instead of running the configured benchmark")
    options = parser.parse_args()
    options.output_dir = options.output_dir.expanduser().resolve()
    if options.benchmark_report:
        options.benchmark_report = options.benchmark_report.expanduser().resolve()
    options.output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=options.output_dir))
    started = time.perf_counter()
    source_context = git_identity(ROOT)
    try:
        contract = load_contract()
        host_contract = None
        if options.with_feasibility:
            host_contract = json.loads((ROOT / "conformance/host-feasibility-contract.json").read_text())
            if host_contract.get("schema") != "fogvault-host-feasibility-contract/v1":
                raise ValueError("unsupported host feasibility contract")
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"schema": "fogvault-verifier/v1", "pass": False, "executed": False, "checks": [{"id": "behavior-contract", "required": True, "status": "fail", "message": str(error)}], "run_directory": str(run_dir), "git": source_context}
        write_report(run_dir / "report.json", result)
        print(json.dumps(result, indent=2) if options.json else f"FAIL behavior-contract: {error}\nReport: {run_dir / 'report.json'}")
        return 1
    verifier = Verifier(run_dir, contract, options.json)
    manifest = ROOT / contract["manifest"]
    core_manifest = ROOT / contract["core_manifest"]
    expected_checks = required_checks(options.with_feasibility)
    interrupted = None
    source_identity = verification_source_identity(manifest, options.with_feasibility)
    try:
        verifier.command("verifier-tests", [sys.executable, str(ROOT / "tests/verifier_checks.py")])
        verifier.builtin("consumer-pin", lambda: check_consumer_pin(contract, manifest))
        verifier.builtin("core-boundary", lambda: check_core_boundary(core_manifest))
        verifier.builtin("format-fixtures", lambda: validate_format_vectors(ROOT / contract["format_vectors"]))
        verifier.builtin("epoch-format-fixtures", lambda: validate_epoch_vectors(ROOT / contract["epoch_vectors"]))
        access_vectors = contract["access_format_vectors"]
        verifier.builtin("access-format-fixtures", lambda: validate_access_vectors(ROOT / access_vectors["fixture"], ROOT / access_vectors["rust_projection"], access_vectors))
        password_vectors = contract["password_vectors"]
        verifier.builtin("password-vectors", lambda: validate_password_vectors(ROOT / password_vectors["fixture"], ROOT / password_vectors["rust_projection"], password_vectors))
        access_output = run_dir / "access-paths.json"
        access_command = [argument.replace("{python}", sys.executable).replace("{output}", str(access_output)) for argument in contract["access_paths"]["command"]]
        verifier.command("access-path-model", access_command, lambda _: validate_access_file(access_output, contract))
        for identity, section in (("independent-epoch-decoder", "independent_epoch"), ("fresh-epoch-decoder", "fresh_epoch"), ("export-payload", "export_payload"), ("export-backend-screening", "rust_export_screening"), ("dependency-audit", "dependency_audit")):
            output = run_dir / (identity + ".json")
            settings = contract[section]
            command = [argument.replace("{python}", sys.executable).replace("{output}", str(output)) for argument in settings["command"]]
            verifier.command(identity, command, lambda _, output=output, settings=settings: validate_proof_file(output, settings))
        base = ["--locked", "--manifest-path", str(manifest)]
        core_base = ["--locked", "--manifest-path", str(core_manifest), "--no-default-features"]
        verifier.command("core-format", ["cargo", "fmt", "--manifest-path", str(core_manifest), "--check"])
        verifier.command("format", ["cargo", "fmt", "--manifest-path", str(manifest), "--check"])
        verifier.command("core-clippy", ["cargo", "clippy", *core_base, "--all-targets", "--", "-D", "warnings"])
        verifier.command("clippy", ["cargo", "clippy", *base, "--all-targets", "--all-features", "--", "-D", "warnings"])
        verifier.command("core-tests", ["cargo", "test", *core_base, "--tests", "--", "--test-threads=1"], lambda output: require_cases(output, contract["required_core_cases"]))
        verifier.command("core-public-api", ["cargo", "test", *core_base, "--doc"], require_private_api_doctests)
        required_cases = contract["required_native_cases"] + contract["required_fixture_cases"]
        verifier.command("native-tests", [sys.executable, str(ROOT / "scripts/run-native-tests.py")], lambda output: require_cases(output, required_cases))
        native_manifest = ROOT / "crates/fogvault-native/Cargo.toml"
        verifier.command("maintained-native-format", ["cargo", "fmt", "--manifest-path", str(native_manifest), "--check"])
        verifier.command("maintained-native-clippy", ["cargo", "clippy", "--locked", "--manifest-path", str(native_manifest), "--all-targets", "--all-features", "--", "-D", "warnings"])
        verifier.command("maintained-native-api", [sys.executable, str(ROOT / "scripts/verify-maintained-api.py")])
        backup_manifest = ROOT / "crates/fogvault-backup/Cargo.toml"
        wasm_manifest = ROOT / "crates/fogvault-wasm/Cargo.toml"
        verifier.command("maintained-backup-format", ["cargo", "fmt", "--manifest-path", str(backup_manifest), "--check"])
        verifier.command("maintained-backup-clippy", ["cargo", "clippy", "--locked", "--manifest-path", str(backup_manifest), "--all-targets", "--all-features", "--", "-D", "warnings"])
        verifier.command("maintained-backup-tests", ["cargo", "test", "--locked", "--manifest-path", str(backup_manifest), "--", "--test-threads=1"], lambda output: require_cases(output, contract["required_backup_cases"]))
        verifier.command("maintained-wasm-format", ["cargo", "fmt", "--manifest-path", str(wasm_manifest), "--check"])
        target = contract["wasm_target"]
        target_check = verifier.command("wasm-target", ["rustup", "target", "list", "--installed"], lambda output: {"target": target} if target in output.splitlines() else (_ for _ in ()).throw(Unavailable(f"required compilation target not installed: {target}")))
        if target_check["status"] == "pass":
            verifier.command("maintained-wasm-clippy", ["cargo", "clippy", "--locked", "--manifest-path", str(wasm_manifest), "--all-targets", "--all-features", "--target", target, "--", "-D", "warnings"])
            verifier.command("core-wasm-compile", ["cargo", "check", *core_base, "--lib", "--features", "web", "--target", target])
            verifier.command("wasm-compile", ["cargo", "check", *base, "--lib", "--no-default-features", "--features", "web", "--target", target])
        else:
            verifier.record("maintained-wasm-clippy", "not-run", executed=False, message="required target unavailable; no automatic installation or silent skip")
            verifier.record("core-wasm-compile", "not-run", executed=False, message="required target unavailable; no automatic installation or silent skip")
            verifier.record("wasm-compile", "not-run", executed=False, message="required target unavailable; no automatic installation or silent skip")
        if options.benchmark_report:
            verifier.builtin("index-growth", lambda: validate_growth_file(options.benchmark_report, contract, manifest))
        else:
            configured = contract.get("growth_command")
            if not isinstance(configured, list) or not configured:
                verifier.record("index-growth", "not-run", executed=False, message="required growth runner is not configured")
            else:
                command = [argument.replace("{python}", sys.executable).replace("{manifest}", str(manifest)).replace("{output}", str(run_dir / "index-growth.json")) for argument in configured]
                verifier.command("index-growth", command, lambda _: validate_growth_file(run_dir / "index-growth.json", contract, manifest))
        if host_contract:
            for identity, section in (("resource-budgets", "resources"), ("browser-feasibility", "browser"), ("mobile-feasibility", "mobile")):
                output = run_dir / (identity + ".json")
                command = [argument.replace("{python}", sys.executable).replace("{output}", str(output)) for argument in host_contract[section]["command"]]
                verifier.command(identity, command, lambda _, identity=identity, output=output: validate_host_file(output, identity, host_contract, manifest))
            sdk_output = run_dir / "browser-sdk.json"
            verifier.command("browser-sdk", [sys.executable, str(ROOT / "scripts/verify-browser-sdk.py"), "--output", str(sdk_output)],
                             lambda _: validate_sdk_file(sdk_output))
            extension_output = run_dir / "browser-extensions.json"
            verifier.command("browser-extensions", [sys.executable, str(ROOT / "scripts/verify-extensions.py"), "--output", str(extension_output)],
                             lambda _: validate_extension_file(extension_output))
            settings = contract["trusted_control_host"]
            output = run_dir / "trusted-control-host.json"
            command = [argument.replace("{python}", sys.executable).replace("{output}", str(output)) for argument in settings["command"]]
            verifier.command("trusted-control-host", command,
                             lambda _, output=output, settings=settings: validate_proof_file(output, settings))
        verifier.builtin("source-stability", lambda: require_stable_sources(source_identity, verification_source_identity(manifest, options.with_feasibility)))
    except KeyboardInterrupt:
        interrupted = "verification interrupted; remaining checks did not run"
    except (OSError, ValueError, KeyError, TypeError) as error:
        interrupted = str(error)
    present = {check["id"] for check in verifier.checks}
    for identity in expected_checks:
        if identity not in present:
            verifier.record(identity, "not-run", executed=False, message=interrupted or "required check did not run")
    result = {"schema": "fogvault-verifier/v1", "profile": host_contract["profile"] if host_contract else contract["profile"], "pass": complete_results(verifier.checks, expected_checks), "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "duration_seconds": time.perf_counter() - started, "run_directory": str(run_dir), "environment": {"platform": platform.platform(), "python": sys.version, "rustc": tool_version(["rustc", "--version"]), "cargo": tool_version(["cargo", "--version"])}, "git": source_context, "source_identity": source_identity, "behavior_evidence": behavior_evidence(verifier.checks, contract), "checks": verifier.checks, "unqualified_scopes": (host_contract or contract)["unqualified_scopes"]}
    report_path = run_dir / "report.json"
    write_report(report_path, result)
    if options.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'PASS' if result['pass'] else 'FAIL'} {result['profile']}\nReport: {report_path}")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
