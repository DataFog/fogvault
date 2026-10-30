#!/usr/bin/env python3
"""Decode frozen current-default, epoch-zero bytes using independent primitives.

No Rust execution, fixture generation, package installation or network access.
Uses the existing independent Python/OpenSSL/libsodium implementation for this
separate portable/no-recovery corpus. The older epoch-seven corpus is unchanged.
"""
from __future__ import annotations

import argparse
import ctypes.util
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance/fresh-epoch-vectors.json"
FIXTURES = ROOT / "conformance/fresh-epoch-vectors"
HELPER = ROOT / "scripts/verify-epoch-independent.py"
PROVENANCE = ROOT / "research/remediation-dependencies/independent-epoch/provenance.json"
RECIPE = ROOT / "artifacts/current-format/fresh-epoch-capture.rs.txt"
CAPTURE = ROOT / "artifacts/current-format/fresh-epoch-capture-inputs.json"
CASES = (
    "fresh_fixed_fixture_identity_and_zero_epoch_admission",
    "fresh_portable_password_unwrap_without_device_provider",
    "fresh_initial_empty_head_authentication",
    "fresh_first_save_head_and_leaf_authentication",
    "fresh_epoch_zero_record_wrap_and_body_decode",
    "fresh_wrong_password_rejected",
    "fresh_record_epoch_mismatch_rejected_before_work",
    "fresh_changed_descriptor_epoch_rejects_password_wrapper",
    "fresh_zero_to_one_same_key_rejects_record_wrap",
    "fresh_wrong_version_lengths_and_trailing_bytes_rejected_before_work",
    "fresh_record_head_and_leaf_byte_tampering_rejected",
    "fresh_runtime_dependency_identity",
    "fresh_source_stability",
)


def load_helper():
    spec = importlib.util.spec_from_file_location("fogvault_independent_epoch", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sodium-library")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be a fresh path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    h = load_helper()
    report = {
        "schema": "fogvault-independent-fresh-epoch-proof/v1", "pass": False,
        "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "cases": [], "executed_case_ids": [], "source_identity": {}, "external_runtime": {},
        "scope": "Independent decode of frozen actual default-creation C3/epoch0 bytes; not a maintained reader or security approval",
        "limitations": [
            "Portable password-only/no-recovery corpus; no device/provider or hardware qualification.",
            "Shares the existing independently implemented Python framing/OpenSSL/libsodium primitive helper, not Rust codecs.",
            "One local installed runtime with pinned RECORD/binary identity, not a reproducible-build/wheel-origin attestation.",
            "Public synthetic credentials and content; no secret-memory zeroization claim for Python/ctypes.",
            "No fixture generation or automatic expected-output update occurs in this command.",
        ],
    }
    files = []
    before = None

    def identity():
        paths = [Path(__file__), MANIFEST, HELPER, RECIPE, CAPTURE, PROVENANCE, *files]
        paths.extend(path for path in PROVENANCE.parent.rglob("*") if path.is_file())
        return {path.relative_to(ROOT).as_posix(): h.file_sha(path) for path in sorted(set(paths))}

    def check(name, action):
        try:
            value = action()
            row = {"id": name, "status": "pass", "executed": True}
            if isinstance(value, dict):
                row.update(value)
            report["cases"].append(row)
        except Exception as error:
            report["cases"].append({"id": name, "status": "fail", "executed": True, "error": f"{type(error).__name__}: {error}"})
            raise

    try:
        manifest = json.loads(h.bounded_read(MANIFEST, 32768))
        node_name = manifest["node_file"]
        h.require(isinstance(node_name, str) and len(node_name) == 73 and node_name.startswith("node-") and node_name.endswith(".bin"), "noncanonical node filename")
        h.require(all(c in "0123456789abcdef" for c in node_name[5:-4]), "noncanonical node hash")
        bounds = {"descriptor.bin": 180, "initial-head.bin": 129, "head.bin": 129, "record.bin": h.MAX_RECORD, node_name: 57}
        h.require(set(manifest["files"]) == set(bounds), "unexpected fixture inventory")
        files = [FIXTURES / name for name in bounds]
        before = identity()
        report["source_identity"] = before
        inputs = {name: h.bounded_read(FIXTURES / name, maximum) for name, maximum in bounds.items()}
        library = args.sodium_library or ctypes.util.find_library("sodium")
        h.require(library is not None, "libsodium is unavailable")
        p = h.Primitives(library)

        def admit(candidate):
            descriptor = h.parse_descriptor(candidate["descriptor.bin"])
            h.require(len(descriptor.raw) == 180 and descriptor.epoch == 0 and descriptor.policy_epoch == 1 and descriptor.recovery_id is None, "not fresh portable/no-recovery state")
            head = h.parse_head(candidate["head.bin"])
            h.require(head.generation == 1, "first save generation")
            record = h.parse_record(candidate["record.bin"], descriptor)
            h.require(record.revision == 1, "first record revision")
            leaf = h.parse_leaf(candidate[node_name])
            initial = candidate["initial-head.bin"]
            h.require(len(initial) == 129 and initial[:8] == bytes(8) and initial[24:97] == bytes(73), "noncanonical empty initial head")
            return descriptor, head, record, leaf, h.Head(initial, 0, 0, bytes(32))

        def fixed_identity():
            h.require((manifest["credential_format"], manifest["content_format"], manifest["suite"], manifest["root_epoch"]) == (3, 3, 1, 0), "manifest profile mismatch")
            capture = json.loads(h.bounded_read(CAPTURE, 131072))
            h.require(capture["exit_code"] == 0 and capture["source_inputs_unchanged_during_capture"] is True and capture["source_identity"] == capture["source_identity_observed_after_execution"], "capture did not preserve stable source inputs")
            h.require(capture["recipe_sha256"] == h.file_sha(RECIPE), "capture recipe identity mismatch")
            for name, data in inputs.items():
                h.require(manifest["files"][name] == {"bytes": len(data), "sha256": h.sha(data).hex()}, "fixture identity mismatch: " + name)
            admit(inputs)
            h.require(p.counts() == (0, 0), "credential work preceded admission")
            return {"files": len(inputs), "root_epoch": 0, "device_slots": 0, "credential_derivations": 0, "aead_openings": 0}

        check(CASES[0], fixed_identity)
        d, head, record, leaf, initial = admit(inputs)
        password = manifest["password_utf8"].encode("utf-8", errors="strict")
        root = h.unlock_password(p, d, password)
        check(CASES[1], lambda: h.require(len(root) == 32, "root width"))
        check(CASES[2], lambda: h.verify_head(p, root, d, initial))

        def first_save():
            h.verify_head(p, root, d, head)
            h.verify_membership(head, inputs[node_name], leaf, record)
            h.require(record.identity.hex() == manifest["record_id_hex"], "record identity")
        check(CASES[3], first_save)
        cek = h.unwrap_content_key(p, root, d, record)

        def body():
            metadata, payload = h.decode_body(p, cek, d, record)
            h.require(metadata == manifest["metadata_utf8"].encode() and payload == manifest["payload_utf8"].encode(), "body plaintext mismatch")
            return {"metadata_bytes": len(metadata), "payload_bytes": len(payload), "envelope_bytes": len(record.raw), "wrapping_epoch": 0}
        check(CASES[4], body)
        check(CASES[5], lambda: h.rejects(lambda: h.unlock_password(p, d, b"SYNTHETIC-wrong-current-password")))

        def no_work(candidate):
            counts = p.counts()
            h.rejects(lambda: admit(candidate))
            h.require(p.counts() == counts, "malformed frame caused primitive work")
        changed_record = record.raw[:32] + h.u64(1) + record.raw[40:]
        check(CASES[6], lambda: no_work({**inputs, "record.bin": changed_record}))
        changed_descriptor = h.parse_descriptor(d.raw[:30] + h.u64(1) + d.raw[38:])
        check(CASES[7], lambda: h.rejects(lambda: h.unlock_password(p, changed_descriptor, password)))

        def wrap_epoch():
            changed = h.parse_record(changed_record, changed_descriptor)
            h.require(h.context(d) == h.context(changed_descriptor), "body context unexpectedly varies with wrap epoch")
            h.rejects(lambda: h.unwrap_content_key(p, root, changed_descriptor, changed))
            h.require(h.decode_body(p, cek, changed_descriptor, changed) == h.decode_body(p, cek, d, record), "immutable body changed with wrapping epoch")
        check(CASES[8], wrap_epoch)

        def malformed():
            variants = 0
            no_work({**inputs, "descriptor.bin": d.raw[:12] + struct.pack(">H", 2) + d.raw[14:]})
            variants += 1
            for name, data in inputs.items():
                for end in range(len(data)):
                    no_work({**inputs, name: data[:end]})
                    variants += 1
                no_work({**inputs, name: data + b"\0"})
                variants += 1
            return {"rejected_variants": variants, "credential_derivations": 0, "aead_openings": 0}
        check(CASES[9], malformed)

        def tamper():
            variants = 0
            for position in range(len(record.raw)):
                h.rejects(lambda position=position: h.verify_membership(head, inputs[node_name], leaf, h.parse_record(h.flip(record.raw, position), d)))
                variants += 1
            for position in range(len(head.raw)):
                h.rejects(lambda position=position: h.verify_head(p, root, d, h.parse_head(h.flip(head.raw, position))))
                variants += 1
            for position in range(len(inputs[node_name])):
                h.rejects(lambda position=position: h.verify_membership(head, h.flip(inputs[node_name], position), h.parse_leaf(h.flip(inputs[node_name], position)), record))
                variants += 1
            return {"rejected_variants": variants, "mutation": "one XOR-01 at every byte"}
        check(CASES[10], tamper)

        def runtime():
            actual = h.external_runtime(p)
            expected = json.loads(h.bounded_read(PROVENANCE, 131072))["external_runtime"]
            h.require(actual == expected, "runtime differs from captured dependency provenance")
            report["external_runtime"] = actual
        check(CASES[11], runtime)
        check(CASES[12], lambda: h.require(identity() == before, "inputs changed during decode"))
        h.require(tuple(row["id"] for row in report["cases"]) == CASES, "case inventory mismatch")
        report["primitive_operations"] = {"password_derivations": p.credential_derivations, "aead_openings": p.aead_openings}
        report["pass"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report["executed_case_ids"] = [row["id"] for row in report["cases"]]
    with args.output.open("x") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    print(("PASS" if report["pass"] else "FAIL") + " independent fresh epoch diagnostic: " + str(args.output))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
