#!/usr/bin/env python3
"""Check fixed FogVault export frames and a pinned age/v1 X25519 tool proof.

Synthetic fixture evidence only. This is not a Rust age backend, live export,
encrypted import staging, source signature or publication/restore authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/export-vectors.json"
TOOL = ROOT / "research/review-dependencies/age-v1.3.2"
ARCHIVE_SHA = "e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5"
BIN_SHA = {"age": "4012dfc2725883beafb710894af4f599b7a94f8c8e0f51f02cc96ab8df33915e", "age-keygen": "c16e229245123d0ad27442317461d63915416cad0294395cd19ca93feb3211ea"}
MAGIC = b"FVEXP001"
DOMAIN = b"fogvault/export/payload/v1\0"
HEADER = struct.Struct(">8s16s32s32sQQ")
RECORD = struct.Struct(">B16sQIQQ")
FOOTER_BYTES = 41
U64_MAX = (1 << 64) - 1
VALID_VECTOR_IDS = ("empty", "records")
INVALID_VECTOR_IDS = ("unknown_version", "unknown_record_tag", "zero_revision", "duplicate_id", "out_of_order", "footer_count_mismatch", "header_count_mismatch", "wrong_transcript_digest", "trailing_byte", "oversized_payload_length")
REQUIRED_CASE_IDS = (
    "payload-golden-empty", "payload-golden-records", "payload-fixed-invalid-vectors",
    "payload-every-truncation-rejects", "payload-policy-before-body-read",
    "payload-checked-length-overflow", "payload-source-registration-mismatch",
    "snapshot-page-head-and-completion", "age-tool-identity",
    "age-x25519-recipient-a-roundtrip", "age-x25519-recipient-b-roundtrip",
    "age-wrong-identity-rejects", "age-final-chunk-truncation-rejects",
    "age-incomplete-outer-even-if-inner-completes",
    "age-modified-ciphertext-rejects", "age-trailing-ciphertext-rejects",
    "age-profile-and-header-admission", "age-trusted-receipt-rejects-valid-replacement",
)


class PayloadError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def require(condition: bool, message: str, code: str = "InvalidFormat") -> None:
    if not condition:
        raise PayloadError(code, message)


def checked_sum(*values: int) -> int:
    require(all(type(value) is int and 0 <= value <= U64_MAX for value in values), "unrepresentable length", "ResourceLimit")
    total = sum(values)
    require(total <= U64_MAX, "encoded length overflow", "ResourceLimit")
    return total


def validate_policy(policy: dict) -> None:
    require(set(policy) == {"max_total_bytes", "max_records", "max_schema_bytes", "max_metadata_bytes", "max_payload_bytes"}, "explicit payload policy required", "InvalidInput")
    require(all(type(value) is int and 0 <= value <= U64_MAX for value in policy.values()), "invalid payload policy", "InvalidInput")


class Reader:
    def __init__(self, stream, policy):
        self.stream, self.policy, self.consumed = stream, policy, 0
        self.transcript = hashlib.sha256(DOMAIN)

    def take(self, count: int, hashed: bool = True) -> bytes:
        total = checked_sum(self.consumed, count)
        require(total <= self.policy["max_total_bytes"] and count <= sys.maxsize, "encoded-byte policy rejected", "ResourceLimit")
        value = self.stream.read(count)
        require(isinstance(value, bytes) and len(value) == count, "truncated payload")
        self.consumed = total
        if hashed:
            self.transcript.update(value)
        return value


def parse_payload(stream, policy: dict, expected_source: dict | None = None) -> dict:
    """Return a complete candidate only after footer/digest/EOF; never activate it."""
    validate_policy(policy)
    reader = Reader(stream, policy)
    magic, vault, descriptor, head, generation, count = HEADER.unpack(reader.take(HEADER.size))
    require(magic == MAGIC, "unsupported payload version")
    require(count <= policy["max_records"], "record-count policy rejected", "ResourceLimit")
    require(count <= U64_MAX // RECORD.size, "record-count multiplication overflow", "ResourceLimit")
    require(checked_sum(HEADER.size, count * RECORD.size, FOOTER_BYTES) <= policy["max_total_bytes"], "minimum frame size rejected", "ResourceLimit")
    source = {"vault_id": vault.hex(), "descriptor_sha256": descriptor.hex(), "head_sha256": head.hex(), "generation": generation, "record_count": count}
    if expected_source is not None:
        require(source == expected_source, "source registration mismatch", "IdentityMismatch")
    records, previous = [], None
    for _ in range(count):
        tag, identity, revision, schema_len, metadata_len, payload_len = RECORD.unpack(reader.take(RECORD.size))
        require(tag == 1 and revision != 0, "invalid record tag/revision")
        require(previous is None or identity > previous, "duplicate or unordered record ID")
        require(schema_len <= policy["max_schema_bytes"] and metadata_len <= policy["max_metadata_bytes"] and payload_len <= policy["max_payload_bytes"], "record-length policy rejected", "ResourceLimit")
        body = checked_sum(schema_len, metadata_len, payload_len)
        require(checked_sum(reader.consumed, body, FOOTER_BYTES) <= policy["max_total_bytes"], "record body exceeds total policy", "ResourceLimit")
        records.append({"id": identity.hex(), "revision": revision, "schema_hex": reader.take(schema_len).hex(), "metadata_hex": reader.take(metadata_len).hex(), "payload_hex": reader.take(payload_len).hex()})
        previous = identity
    tag, final_count = struct.unpack(">BQ", reader.take(9))
    require(tag == 255 and final_count == count, "footer count/finality mismatch")
    actual = reader.take(32, hashed=False)
    require(hmac.compare_digest(actual, reader.transcript.digest()), "transcript digest mismatch", "Integrity")
    require(reader.stream.read(1) == b"", "trailing payload bytes")
    return {"source": source, "records": records, "complete": True, "origin_authenticated": False, "activation_authority": False}


def encode_payload(source: dict, records: list[dict]) -> bytes:
    """Small synthetic producer; fixed expected files are never regenerated here."""
    require(source.get("record_count") == len(records), "snapshot record count mismatch")
    ids = [bytes.fromhex(row["id"]) for row in records]
    require(all(len(identity) == 16 for identity in ids) and all(left < right for left, right in zip(ids, ids[1:])), "snapshot record order/identity mismatch")
    data = bytearray(HEADER.pack(MAGIC, bytes.fromhex(source["vault_id"]), bytes.fromhex(source["descriptor_sha256"]), bytes.fromhex(source["head_sha256"]), source["generation"], len(records)))
    for row in records:
        schema, metadata, payload = (bytes.fromhex(row[field]) for field in ("schema_hex", "metadata_hex", "payload_hex"))
        data.extend(RECORD.pack(1, bytes.fromhex(row["id"]), row["revision"], len(schema), len(metadata), len(payload)))
        data.extend(schema + metadata + payload)
    data.extend(struct.pack(">BQ", 255, len(records)))
    data.extend(hashlib.sha256(DOMAIN + data).digest())
    return bytes(data)


def snapshot_pages(source: dict, pages: list[dict]) -> bytes:
    """Symbolic page receipt consistency, not a storage snapshot implementation."""
    records = []
    require(bool(pages), "snapshot completion is missing")
    for index, page in enumerate(pages):
        require(page.get("source") == source and page.get("page_index") == index, "snapshot head/page changed", "Conflict")
        require(page.get("complete") is (index == len(pages) - 1), "snapshot completion is missing")
        records.extend(page["records"])
    return encode_payload(source, records)


def admit_age_header(data: bytes, *, max_header_bytes: int, max_stanzas: int) -> dict:
    """Bound/profile-check unauthenticated header; age still verifies its grammar/MAC."""
    require(type(max_header_bytes) is int and max_header_bytes >= 0 and type(max_stanzas) is int and max_stanzas >= 0, "explicit age-header policy required", "InvalidInput")
    stream, consumed, tags = io.BytesIO(data), 0, []
    while True:
        remaining = max_header_bytes - consumed
        line = stream.readline(remaining + 1)
        require(bool(line) and len(line) <= remaining, "age header byte policy rejected", "ResourceLimit")
        consumed += len(line)
        require(line.endswith(b"\n"), "unterminated age header")
        if consumed == len(line):
            require(line == b"age-encryption.org/v1\n", "unsupported age version", "UnsupportedProfile")
        elif line.startswith(b"-> "):
            fields = line[:-1].split(b" ")
            require(len(fields) >= 2 and all(fields), "malformed recipient line")
            tag = fields[1]
            require(tag not in {b"scrypt", b"ssh-rsa", b"ssh-ed25519", b"mlkem768x25519", b"p256tag", b"mlkem768p256tag"}, "recipient profile not enabled", "UnsupportedProfile")
            tags.append(tag.decode("ascii", "strict"))
            require(len(tags) <= max_stanzas, "age stanza policy rejected", "ResourceLimit")
        elif line.startswith(b"--- "):
            require("X25519" in tags, "X25519 profile required", "UnsupportedProfile")
            return {"header_bytes": consumed, "stanzas": len(tags), "recognized_profile": "age/v1-X25519", "unknown_stanzas": [tag for tag in tags if tag != "X25519"]}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_ciphertext_receipt(ciphertext: bytes, trusted_sha256: str) -> None:
    """The expected digest must arrive from independent trusted owner storage."""
    require(isinstance(trusted_sha256, str) and len(trusted_sha256) == 64 and all(char in "0123456789abcdef" for char in trusted_sha256), "trusted completed-ciphertext receipt required", "InvalidInput")
    require(hmac.compare_digest(hashlib.sha256(ciphertext).hexdigest(), trusted_sha256), "completed ciphertext differs from trusted receipt", "IdentityMismatch")


def publication_allowed(*, age_complete: bool, payload_complete: bool, target_authorized: bool, origin_accepted: bool) -> bool:
    """Symbolic condition, not an implemented import or target authorization."""
    return all(value is True for value in (age_complete, payload_complete, target_authorized, origin_accepted))


def verify_tool() -> dict:
    archive = TOOL / "age-v1.3.2-darwin-arm64.tar.gz"
    require(archive.is_file() and sha(archive) == ARCHIVE_SHA, "official age archive digest differs", "ToolUnavailable")
    binaries = {}
    for name, expected in BIN_SHA.items():
        path = TOOL / "bin" / name
        require(path.is_file() and sha(path) == expected, "age executable differs from verified archive", "ToolUnavailable")
        binaries[name] = {"path": str(path), "sha256": expected}
    return {"version": "v1.3.2", "archive_sha256": ARCHIVE_SHA, "binaries": binaries}


def source_identity() -> dict:
    paths = [Path(__file__), VECTORS, TOOL / "provenance.json", TOOL / "LICENSE", TOOL / "age-v1.3.2-darwin-arm64.tar.gz", TOOL / "bin/age", TOOL / "bin/age-keygen", *sorted((ROOT / "conformance").glob("export-vectors-*.bin"))]
    rust = ROOT / "experiments/vault-prototype/tests/export_payload.rs"
    if rust.exists():
        paths.append(rust)
    return {path.relative_to(ROOT).as_posix(): sha(path) for path in paths}


def check_definition(definition: dict) -> tuple[list[tuple[dict, bytes]], dict]:
    require(definition.get("schema") == "fogvault-export-vectors/v1", "unknown vector schema")
    require([row["id"] for row in definition.get("valid", [])] == list(VALID_VECTOR_IDS) and [row["id"] for row in definition.get("invalid", [])] == list(INVALID_VECTOR_IDS), "permanent export vector inventory changed")
    require(definition.get("payload_version") == MAGIC.decode() and definition.get("header_bytes") == HEADER.size and definition.get("record_fixed_bytes") == RECORD.size and definition.get("footer_bytes") == FOOTER_BYTES and definition.get("transcript_domain_hex") == DOMAIN.hex(), "payload layout/domain metadata changed")
    valid, ids = [], []
    for row in definition["valid"]:
        require(row["fixture"] == "conformance/export-vectors-" + row["id"] + ".bin", "noncanonical valid fixture path")
        path = ROOT / row["fixture"]
        require(path.is_relative_to(ROOT) and path.is_file() and sha(path) == row["sha256"] and path.read_bytes().hex() == row["bytes_hex"], "fixed export fixture changed")
        valid.append((row, path.read_bytes()))
        ids.append(row["id"])
    for row in definition["invalid"]:
        require(row["fixture"] == "conformance/export-vectors-invalid-" + row["id"].replace("_", "-") + ".bin", "noncanonical invalid fixture path")
        path = ROOT / row["fixture"]
        require(path.is_relative_to(ROOT) and path.is_file() and sha(path) == row["sha256"] and path.read_bytes().hex() == row["bytes_hex"], "fixed invalid export fixture changed")
        ids.append(row["id"])
    require(len(ids) == len(set(ids)), "duplicate export vector ID")
    records = [record for row in definition["valid"] for record in row["records"]]
    derived_policy = {"max_total_bytes": max(len(data) for _, data in valid), "max_records": max(len(row["records"]) for row in definition["valid"]), "max_schema_bytes": max(len(bytes.fromhex(row["schema_hex"])) for row in records), "max_metadata_bytes": max(len(bytes.fromhex(row["metadata_hex"])) for row in records), "max_payload_bytes": max(len(bytes.fromhex(row["payload_hex"])) for row in records)}
    require(definition.get("proof_policy") == derived_policy, "proof budgets no longer derive from fixed synthetic corpus")
    return valid, definition["proof_policy"]


def run_checks(directory: Path) -> dict:
    definition = json.loads(VECTORS.read_text())
    valid, policy = check_definition(definition)
    before = source_identity()
    cases, commands = [], []
    def case(identity, operation):
        try:
            detail = operation() or {}
            cases.append({"id": identity, "status": "pass", "executed": True, **detail})
        except (OSError, ValueError, TypeError, KeyError, OverflowError, struct.error) as error:
            cases.append({"id": identity, "status": "fail", "executed": True, "error": str(error)})
    def rejected(value, selected=policy, source=None, code=None):
        try:
            parse_payload(io.BytesIO(value), selected, source)
        except PayloadError as error:
            require(code is None or error.code == code, "unexpected rejection category")
            return
        raise PayloadError("TestFailure", "invalid/incomplete payload admitted")
    for (row, data), identity in zip(valid, REQUIRED_CASE_IDS[:2]):
        def golden(row=row, data=data):
            parsed = parse_payload(io.BytesIO(data), policy, row["source"])
            require(parsed["records"] == row["records"] and encode_payload(row["source"], row["records"]) == data, "golden frame differs")
            return {"vector_id": row["id"], "sha256": row["sha256"], "records": len(parsed["records"])}
        case(identity, golden)
    def invalid_vectors():
        for row in definition["invalid"]:
            rejected(bytes.fromhex(row["bytes_hex"]), code=row["error"])
        return {"vector_ids": [row["id"] for row in definition["invalid"]]}
    case("payload-fixed-invalid-vectors", invalid_vectors)
    def truncations():
        count = 0
        for _, data in valid:
            for offset in range(len(data)):
                rejected(data[:offset]); count += 1
        return {"truncated_prefixes": count}
    case("payload-every-truncation-rejects", truncations)
    def policy_before_read():
        row, data = valid[1]
        class Spy(io.BytesIO):
            maximum = 0
            def read(self, count=-1):
                self.maximum = max(self.maximum, count)
                return super().read(count)
        stream = Spy(data)
        lowered = {**policy, "max_payload_bytes": 0}
        try: parse_payload(stream, lowered)
        except PayloadError as error: require(error.code == "ResourceLimit", "wrong length rejection")
        else: raise PayloadError("TestFailure", "payload policy ignored")
        require(stream.tell() == HEADER.size + RECORD.size and stream.maximum == HEADER.size, "record body fetched before admission")
        return {"body_read_before_rejection": False}
    case("payload-policy-before-body-read", policy_before_read)
    def overflow():
        source = valid[0][0]["source"]
        value = HEADER.pack(MAGIC, bytes.fromhex(source["vault_id"]), bytes.fromhex(source["descriptor_sha256"]), bytes.fromhex(source["head_sha256"]), 0, U64_MAX)
        rejected(value, {**policy, "max_total_bytes": U64_MAX, "max_records": U64_MAX}, code="ResourceLimit")
        try: checked_sum(U64_MAX, 1)
        except PayloadError: pass
        else: raise PayloadError("TestFailure", "length overflow accepted")
    case("payload-checked-length-overflow", overflow)
    case("payload-source-registration-mismatch", lambda: rejected(valid[1][1], source={**valid[1][0]["source"], "vault_id": "ff" * 16}, code="IdentityMismatch"))
    def pages():
        row, data = valid[1]
        pages = [{"source": row["source"], "page_index": 0, "records": row["records"][:1], "complete": False}, {"source": row["source"], "page_index": 1, "records": row["records"][1:], "complete": True}]
        require(snapshot_pages(row["source"], pages) == data, "snapshot framing differs")
        for changed in ([pages[0]], [pages[0], {**pages[1], "source": {**row["source"], "generation": 99}}], [{**pages[0], "complete": True}]):
            try: snapshot_pages(row["source"], changed)
            except PayloadError: pass
            else: raise PayloadError("TestFailure", "incomplete/changed-head pages accepted")
        return {"scope": "symbolic page-receipt consistency; no persistent export adapter"}
    case("snapshot-page-head-and-completion", pages)
    tool = verify_tool()
    def command(name, args, succeeds=True):
        verify_tool()
        result = subprocess.run([str(TOOL / "bin" / name), *map(str, args)], cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={key:value for key,value in os.environ.items() if not key.startswith("AGE_")}, check=False)
        commands.append({"command": [str(TOOL / "bin" / name), *map(str, args)], "executed": True, "exit_code": result.returncode, "stdout": result.stdout.decode("utf-8", "replace"), "stderr": result.stderr.decode("utf-8", "replace")})
        require((result.returncode == 0) is succeeds, "unexpected age command outcome", "ToolFailure")
        return result
    def tool_identity():
        observed = command("age", ["--version"]).stdout.decode().strip()
        require(observed == tool["version"], "age version output differs from pinned tool", "ToolFailure")
        return {"observed_version": observed, **tool}
    case("age-tool-identity", tool_identity)
    identities, recipients = [], []
    for name in ("a", "b", "wrong"):
        path = directory / (name + ".identity")
        command("age-keygen", ["-o", path])
        recipient = command("age-keygen", ["-y", path]).stdout.decode().strip()
        require(recipient.startswith("age1") and not recipient.startswith("age1pq"), "keygen did not choose X25519")
        identities.append(path); recipients.append(recipient)
    plain = directory / "synthetic-payload.bin"; plain.write_bytes(valid[1][1])
    encrypted = directory / "synthetic-payload.age"
    command("age", ["-r", recipients[0], "-r", recipients[1], "-o", encrypted, plain])
    ciphertext = encrypted.read_bytes()
    admitted = admit_age_header(ciphertext, max_header_bytes=2*1024*1024, max_stanzas=1024)
    for index, identity in enumerate(REQUIRED_CASE_IDS[9:11]):
        def roundtrip(index=index):
            output = directory / (f"restored-{index}.bin")
            command("age", ["-d", "-i", identities[index], "-o", output, encrypted])
            require(output.read_bytes() == valid[1][1], "external age output differs")
            parse_payload(io.BytesIO(output.read_bytes()), policy, valid[1][0]["source"])
            return {"independent_recipient": index, "payload_sha256": sha(output), "container": admitted}
        case(identity, roundtrip)
    case("age-wrong-identity-rejects", lambda: command("age", ["-d", "-i", identities[2], "-o", directory / "wrong.bin", encrypted], False) and {})
    def final_chunk():
        # 64KiB + one byte is derived from age's chunk boundary, not a product cap.
        row = {"id": "01" * 16, "revision": 1, "schema_hex": "", "metadata_hex": "", "payload_hex": (b"x" * (65536 + 1)).hex()}
        large = encode_payload({**valid[1][0]["source"], "record_count": 1}, [row])
        source = directory / "multichunk.bin"; source.write_bytes(large)
        envelope = directory / "multichunk.age"; command("age", ["-r", recipients[0], "-o", envelope, source])
        truncated = directory / "multichunk-truncated.age"; truncated.write_bytes(envelope.read_bytes()[:-1])
        output = directory / "partial-must-not-activate.bin"
        command("age", ["-d", "-i", identities[0], "-o", output, truncated], False)
        partial = output.read_bytes() if output.exists() else b""
        rejected(partial, {**policy, "max_total_bytes": len(large), "max_payload_bytes": 65536 + 1})
        return {"authenticated_eof": False, "partial_plaintext_bytes_observed": len(partial), "activated": False}
    case("age-final-chunk-truncation-rejects", final_chunk)
    def complete_inner_without_final():
        # Place the whole inner frame in one authenticated nonfinal age chunk.
        payload_bytes = 65536 - HEADER.size - RECORD.size - FOOTER_BYTES
        row = {"id": "02" * 16, "revision": 1, "schema_hex": "", "metadata_hex": "", "payload_hex": (b"z" * payload_bytes).hex()}
        inner = encode_payload({**valid[1][0]["source"], "record_count": 1}, [row])
        require(len(inner) == 65536, "chunk-boundary fixture differs")
        source = directory / "complete-inner-then-extra.bin"; source.write_bytes(inner + b"x")
        envelope = directory / "complete-inner-then-extra.age"; command("age", ["-r", recipients[0], "-o", envelope, source])
        encoded = envelope.read_bytes()
        header = admit_age_header(encoded, max_header_bytes=2*1024*1024, max_stanzas=1024)
        truncated = directory / "complete-inner-missing-final.age"
        truncated.write_bytes(encoded[:header["header_bytes"] + 16 + 65536 + 16])
        output = directory / "complete-inner-still-must-not-activate.bin"
        command("age", ["-d", "-i", identities[0], "-o", output, truncated], False)
        recovered = output.read_bytes()
        require(recovered == inner, "tool did not expose the authenticated nonfinal prefix")
        parsed = parse_payload(io.BytesIO(recovered), {**policy, "max_total_bytes": len(inner), "max_payload_bytes": payload_bytes})
        allowed = publication_allowed(age_complete=False, payload_complete=parsed["complete"], target_authorized=True, origin_accepted=True)
        require(not allowed, "inner completion bypassed missing age finality")
        return {"inner_payload_complete": True, "authenticated_age_eof": False, "publication_allowed": allowed, "scope": "actual CLI prefix plus symbolic publication condition; no maintained import"}
    case("age-incomplete-outer-even-if-inner-completes", complete_inner_without_final)
    def bad_cipher(kind):
        value = bytearray(ciphertext)
        if kind == "modified": value[-1] ^= 1
        else: value.extend(b"\0")
        source = directory / (kind + ".age"); source.write_bytes(value)
        command("age", ["-d", "-i", identities[0], "-o", directory / (kind + ".bin"), source], False)
        return {"activated": False}
    case("age-modified-ciphertext-rejects", lambda: bad_cipher("modified"))
    case("age-trailing-ciphertext-rejects", lambda: bad_cipher("trailing"))
    def header_policy():
        for data, budget, count, code in ((ciphertext, admitted["header_bytes"]-1, 1024, "ResourceLimit"), (ciphertext, 2*1024*1024, 0, "ResourceLimit"), (b"age-encryption.org/v1\n-> scrypt untrusted 63\n", 2*1024*1024, 1024, "UnsupportedProfile"), (b"age-encryption.org/v1\n-> ssh-rsa untrusted\n", 2*1024*1024, 1024, "UnsupportedProfile"), (b"age-encryption.org/v1\n-> mlkem768x25519 untrusted\n", 2*1024*1024, 1024, "UnsupportedProfile"), (b"age-encryption.org/v1\n-> p256tag untrusted\n", 2*1024*1024, 1024, "UnsupportedProfile")):
            try: admit_age_header(data, max_header_bytes=budget, max_stanzas=count)
            except PayloadError as error: require(error.code == code, "wrong header admission error")
            else: raise PayloadError("TestFailure", "unsupported/over-budget age header admitted")
        return {"scrypt_executed": False, "native_argon2_policy_reused": False, "known_nonbaseline_recipients_enabled": False}
    case("age-profile-and-header-admission", header_policy)
    def valid_replacement():
        trusted = hashlib.sha256(ciphertext).hexdigest()
        verify_ciphertext_receipt(ciphertext, trusted)
        try: verify_ciphertext_receipt(ciphertext, None)
        except PayloadError as error: require(error.code == "InvalidInput", "missing receipt did not reject")
        else: raise PayloadError("TestFailure", "missing trusted receipt admitted")
        require(not publication_allowed(age_complete=True, payload_complete=True, target_authorized=True, origin_accepted=False), "missing origin authority permitted publication")
        # A public recipient lets another sender copy all source claims and
        # produce a fully valid age envelope containing different record data.
        rows = [dict(row) for row in valid[1][0]["records"]]
        rows[0]["payload_hex"] = b"impostor".hex()
        replacement = encode_payload(valid[1][0]["source"], rows)
        source = directory / "valid-replacement.bin"; source.write_bytes(replacement)
        envelope = directory / "valid-replacement.age"
        command("age", ["-r", recipients[0], "-r", recipients[1], "-o", envelope, source])
        output = directory / "valid-replacement-decrypted.bin"
        command("age", ["-d", "-i", identities[0], "-o", output, envelope])
        parsed = parse_payload(io.BytesIO(output.read_bytes()), policy, valid[1][0]["source"])
        require(parsed["complete"] and parsed["records"] != valid[1][0]["records"], "replacement did not demonstrate unverified source claims")
        try: verify_ciphertext_receipt(envelope.read_bytes(), trusted)
        except PayloadError as error: require(error.code == "IdentityMismatch", "wrong receipt rejection")
        else: raise PayloadError("TestFailure", "valid replacement bypassed trusted receipt")
        return {"matching_source_claims_authenticate_origin": False, "valid_age_replacement_detected_by_receipt": True, "receipt_storage": "independent trusted owner input assumed; adjacent attacker-controlled sidecar is insufficient", "activated": False}
    case("age-trusted-receipt-rejects-valid-replacement", valid_replacement)
    require([row["id"] for row in cases] == list(REQUIRED_CASE_IDS), "export proof case inventory changed")
    require(source_identity() == before, "export proof inputs changed while running")
    return {"schema": "fogvault-export-payload-proof/v1", "pass": all(row["status"] == "pass" for row in cases), "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "scope": "fixed payload framing and pinned external age/v1 X25519 interoperability; no Rust age backend or maintained export/import", "cases": cases, "executed_case_ids": list(REQUIRED_CASE_IDS), "source_identity": before, "commands": commands, "tool": tool, "environment": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version}, "limitations": ["Only synthetic plaintext and ephemeral test identities; keys are deleted after the proof.", "age success plus payload completion is not source authenticity, recency or restore authorization.", "Snapshot page check is symbolic; maintained snapshot export/encrypted import staging remain FVW-041/042.", "Optional scrypt profile is not enabled; hostile scrypt admission is separate from native Argon2.", "The Go CLI tool proof is not a selected Rust runtime dependency or all-host backend qualification."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    output = options.output.expanduser().resolve()
    if output.exists(): parser.error("output must be fresh")
    try:
        with tempfile.TemporaryDirectory(prefix="fogvault-age-proof-") as temporary:
            result = run_checks(Path(temporary))
    except (OSError, ValueError, TypeError, KeyError, OverflowError, struct.error) as error:
        result = {"schema": "fogvault-export-payload-proof/v1", "pass": False, "executed": True, "error": str(error), "scope": "synthetic framing/tool proof; incomplete or unavailable proof cannot pass"}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as destination: json.dump(result, destination, indent=2); destination.write("\n")
    print(("PASS" if result["pass"] else "FAIL") + " export payload proof: " + str(output))
    if not result["pass"]: print(result.get("error", [row for row in result.get("cases", []) if row["status"] != "pass"]))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
