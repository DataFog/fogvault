#!/usr/bin/env python3
"""Independently decode the fixed, public synthetic FogVault content-three fixture.

Diagnostic only: Python framing + OpenSSL-backed cryptography Argon2id/HKDF/HMAC
and libsodium XChaCha20-Poly1305. No Rust codec, fixture generation, real secrets,
network access, or production dependency installation is used by this command.
The intentionally narrow admission profile supports the corpus's portable route
with recovery, not device/provider descriptors or a general vault reader.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance/epoch-vectors"
MANIFEST = ROOT / "conformance/epoch-vectors.json"
PROVENANCE = ROOT / "research/remediation-dependencies/independent-epoch/provenance.json"
NODE = "node-37e851f52a18f40dbabf045525f4122bdcddb0dbd685d89f541c6c17b2e8ef8c.bin"
FILE_LIMITS = {"descriptor.bin": 276, "head.bin": 129, "record.bin": 1712,
               NODE: 57, "recovery-kit.bin": 80, "root-key.bin": 32,
               "content-key.bin": 32}
I64_MAX = (1 << 63) - 1
METADATA_LIMIT = 256
PAYLOAD_LIMIT = 1280
MAX_RECORD = 176 + METADATA_LIMIT + PAYLOAD_LIMIT
LABEL = b"fogvault/prototype/"
CASES = (
    "fixed_fixture_identity_and_strict_admission",
    "independent_password_root_unwrap",
    "independent_recovery_root_unwrap",
    "head_hmac_and_complete_descriptor_binding",
    "index_leaf_hash_and_complete_envelope_commitment",
    "wrapped_content_key_and_record_body_decode",
    "wrong_password_rejected",
    "wrong_recovery_secret_rejected",
    "encoded_epoch_mismatch_rejected_before_credential_work",
    "changed_encoded_epoch_same_wrapping_key_rejects_aead",
    "wrong_content_format_rejected_before_credential_work",
    "wrong_content_context_same_keys_rejects_wrap_and_body",
    "malformed_headers_rejected_before_credential_work",
    "every_descriptor_byte_tamper_rejected",
    "every_head_byte_tamper_rejected",
    "every_leaf_byte_tamper_rejected",
    "every_record_byte_tamper_rejected",
    "every_wrapped_key_byte_tamper_rejected_by_aead",
    "every_body_byte_tamper_rejected_by_aead",
    "every_recovery_kit_byte_tamper_rejected",
    "password_wrapper_and_unused_recovery_wrapper_authentication",
    "every_truncated_prefix_and_trailing_byte_rejected_before_work",
    "runtime_dependency_identity",
    "source_stability",
)


class Reject(ValueError):
    """Expected rejection of a non-admitted or unauthenticated candidate."""


def require(condition, message):
    if not condition:
        raise Reject(message)


def sha(data):
    return hashlib.sha256(data).digest()


def file_sha(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def bounded_read(path, maximum):
    require(path.stat().st_size <= maximum, f"input exceeds diagnostic bound: {path.name}")
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    require(len(data) <= maximum, "input grew beyond bound")
    return data


def F(data):
    return struct.pack(">Q", len(data)) + data


def u64(value):
    return struct.pack(">Q", value)


class Reader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, count):
        require(0 <= count <= len(self.data) - self.position, "truncated frame")
        result = self.data[self.position:self.position + count]
        self.position += count
        return result

    def number(self, count):
        return int.from_bytes(self.take(count), "big")

    def end(self):
        require(self.position == len(self.data), "trailing bytes")


@dataclass(frozen=True)
class Descriptor:
    raw: bytes
    vault: bytes
    epoch: int
    policy_epoch: int
    password_id: bytes
    password_revision: int
    salt: bytes
    password_wrapper: bytes
    recovery_id: bytes | None
    recovery_revision: int | None
    recovery_wrapper: bytes | None


def parse_descriptor(data):
    require(108 <= len(data) <= 276, "descriptor width outside portable diagnostic profile")
    r = Reader(data)
    require(r.take(8) == b"FGVP0003", "credential magic")
    require((r.number(2), r.number(2), r.number(2)) == (3, 1, 3), "credential/suite/content ID")
    vault, epoch, policy_epoch = r.take(16), r.number(8), r.number(8)
    require(policy_epoch > 0 and r.number(1) == 0, "policy epoch or unsupported device profile")
    password_id, password_revision = r.take(16), r.number(8)
    require(password_revision > 0, "zero password revision")
    require(r.number(2) == 1, "unknown KDF")
    require((r.number(4), r.number(4), r.number(4)) == (65536, 3, 1), "untrusted KDF parameters")
    salt = r.take(16)
    require(r.number(2) == 72, "password wrapper width")
    wrapper = r.take(72)
    require(r.number(4) == 0, "device count outside trusted portable profile")
    present = r.number(1)
    require(present in (0, 1), "recovery presence flag")
    recovery_id = recovery_revision = recovery_wrapper = None
    if present:
        recovery_id, recovery_revision = r.take(16), r.number(8)
        require(recovery_id != password_id and recovery_revision > 0, "recovery identity/revision")
        recovery_wrapper = r.take(72)
    r.end()
    return Descriptor(data, vault, epoch, policy_epoch, password_id, password_revision,
                      salt, wrapper, recovery_id, recovery_revision, recovery_wrapper)


@dataclass(frozen=True)
class Head:
    raw: bytes
    generation: int
    count: int
    root: bytes


def parse_head(data):
    require(len(data) == 129, "head width")
    r = Reader(data)
    generation = r.number(8)
    r.take(16 + 32)  # request ID and authenticated synthetic operation digest
    count, present, root = r.number(8), r.number(1), r.take(32)
    r.take(32)
    r.end()
    require(0 < generation <= I64_MAX and count == 1 and present == 1,
            "head outside one-live-record fixture profile")
    return Head(data, generation, count, root)


@dataclass(frozen=True)
class Record:
    raw: bytes
    identity: bytes
    revision: int
    epoch: int
    wrapper: bytes
    body: bytes


def parse_record(data, descriptor):
    require(176 <= len(data) <= MAX_RECORD, "record width")
    r = Reader(data)
    require(r.take(8) == b"FGVR0003", "content-three record magic")
    identity, revision, epoch = r.take(16), r.number(8), r.number(8)
    require(0 < revision <= I64_MAX, "record revision")
    require(epoch == descriptor.epoch, "encoded wrapping epoch differs from descriptor")
    wrapper, body_length = r.take(72), r.number(8)
    require(56 <= body_length <= MAX_RECORD - 120, "body ciphertext bound")
    body = r.take(body_length)
    r.end()
    return Record(data, identity, revision, epoch, wrapper, body)


def parse_leaf(data):
    require(len(data) == 57, "leaf width")
    r = Reader(data)
    require(r.number(1) == 0, "only fixed leaf profile admitted")
    identity, revision, commitment = r.take(16), r.number(8), r.take(32)
    require(0 < revision <= I64_MAX, "leaf revision")
    r.end()
    return identity, revision, commitment


def parse_recovery_kit(data, descriptor):
    require(len(data) == 80, "recovery kit width")
    r = Reader(data)
    require(r.take(8) == b"FGVRKEY3", "recovery kit magic")
    require(r.take(16) == descriptor.vault and r.take(16) == descriptor.recovery_id,
            "recovery kit identity")
    require(r.number(8) == descriptor.epoch, "recovery kit epoch")
    secret = r.take(32)
    r.end()
    return secret


def parse_key(data):
    require(len(data) == 32, "synthetic key width")
    return data


def admit(inputs):
    """Every public frame/length and cross-header epoch is admitted before KDF/AEAD."""
    d = parse_descriptor(inputs["descriptor.bin"])
    h = parse_head(inputs["head.bin"])
    record = parse_record(inputs["record.bin"], d)
    leaf = parse_leaf(inputs[NODE])
    recovery_secret = parse_recovery_kit(inputs["recovery-kit.bin"], d)
    root, cek = parse_key(inputs["root-key.bin"]), parse_key(inputs["content-key.bin"])
    return d, h, record, leaf, recovery_secret, root, cek


class Primitives:
    def __init__(self, library):
        self.library_path = Path(library).resolve()
        self.sodium = ctypes.CDLL(str(self.library_path))
        self.sodium.sodium_init.argtypes = []
        self.sodium.sodium_init.restype = ctypes.c_int
        require(self.sodium.sodium_init() >= 0, "libsodium initialization failed")
        self.sodium.sodium_version_string.restype = ctypes.c_char_p
        self.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong,
            ctypes.c_void_p, ctypes.c_void_p]
        self.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = ctypes.c_int
        self.credential_derivations = self.aead_openings = 0

    def counts(self):
        return self.credential_derivations, self.aead_openings

    def derive_password(self, password, salt):
        self.credential_derivations += 1
        return Argon2id(salt=salt, length=32, iterations=3, lanes=1,
                        memory_cost=65536).derive(password)

    @staticmethod
    def derive(secret, vault, purpose):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=vault,
                    info=LABEL + b"key-derivation/v1\0" + F(purpose)).derive(secret)

    def open(self, key, aad, envelope):
        require(len(key) == 32 and 40 <= len(envelope) <= MAX_RECORD, "AEAD bound")
        self.aead_openings += 1
        # Explicit argument types/lengths preserve embedded zero bytes. ctypes
        # references keep each immutable input alive for the complete C call.
        output = ctypes.create_string_buffer(len(envelope) - 40)
        output_length = ctypes.c_ulonglong()
        accepted = self.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            output, ctypes.byref(output_length), None, envelope[24:],
            len(envelope) - 24, aad, len(aad), envelope[:24], key)
        require(accepted == 0, "XChaCha20-Poly1305 authentication rejected")
        require(output_length.value == len(envelope) - 40, "AEAD plaintext width")
        return output.raw[:output_length.value]


def password_aad(d):
    return (F(LABEL + b"password-root/v3") + d.vault + u64(d.epoch) + d.password_id
            + u64(d.password_revision) + struct.pack(">HIII", 1, 65536, 3, 1) + d.salt)


def recovery_aad(d):
    require(d.recovery_id is not None, "no admitted recovery path")
    return F(LABEL + b"owner-recovery/v3") + d.vault + u64(d.epoch) + d.recovery_id + u64(d.recovery_revision)


def unlock_password(p, d, password):
    return parse_key(p.open(p.derive_password(password, d.salt), password_aad(d), d.password_wrapper))


def unlock_recovery(p, d, secret):
    aad = recovery_aad(d)
    return parse_key(p.open(p.derive(secret, d.vault, aad), aad, d.recovery_wrapper))


def verify_head(p, root, d, head):
    mac = hmac.HMAC(p.derive(root, d.vault, b"head-authentication"), hashes.SHA256())
    mac.update(F(LABEL + b"index-head/v2") + sha(d.raw) + head.raw[:97])
    try:
        mac.verify(head.raw[97:])
    except InvalidSignature as error:
        raise Reject("head HMAC rejected") from error


def verify_membership(head, node_bytes, leaf, record):
    require(sha(LABEL + b"index-node/v2\0" + node_bytes) == head.root, "leaf hash differs from head root")
    require(leaf[:2] == (record.identity, record.revision), "leaf record identity/revision mismatch")
    require(leaf[2] == sha(record.raw), "leaf complete-envelope commitment mismatch")


def context(d, content_format=3):
    return sha(F(LABEL + b"context/v1") + struct.pack(">HH", content_format, 1) + d.vault)


def record_aad(d, record, purpose, content_format=3):
    aad = F(LABEL + purpose) + context(d, content_format) + d.vault + record.identity + u64(record.revision)
    return aad + u64(record.epoch) if purpose == b"record-wrap/v1" else aad


def unwrap_content_key(p, root, d, record, content_format=3):
    wrapping = p.derive(root, d.vault, b"record-key-wrapping")
    return parse_key(p.open(wrapping, record_aad(d, record, b"record-wrap/v1", content_format), record.wrapper))


def decode_body(p, cek, d, record, content_format=3):
    plain = p.open(cek, record_aad(d, record, b"record-body/v1", content_format), record.body)
    r = Reader(plain)
    length = r.number(8)
    require(length <= METADATA_LIMIT, "inner metadata bound")
    metadata = r.take(length)
    length = r.number(8)
    require(length <= PAYLOAD_LIMIT, "inner payload bound")
    payload = r.take(length)
    r.end()
    return metadata, payload


def distribution_identity(name):
    distribution = importlib.metadata.distribution(name)
    files = []
    for item in sorted(distribution.files or [], key=str):
        if item.hash is None:
            continue  # RECORD itself and generated bytecode have no RECORD digest.
        path = distribution.locate_file(item).resolve()
        require(item.hash.mode == "sha256", "unrecognized distribution RECORD digest")
        actual = file_sha(path)
        expected = base64.urlsafe_b64decode(item.hash.value + "=" * (-len(item.hash.value) % 4)).hex()
        require(actual == expected, f"installed {name} differs from RECORD: {item}")
        files.append({"path": str(item), "bytes": path.stat().st_size, "sha256": actual})
    require(files, "installed distribution has no verifiable RECORD")
    native = [dict(row, absolute_path=str(distribution.locate_file(row["path"]).resolve()))
              for row in files if row["path"].endswith((".so", ".dylib"))]
    return {"name": name, "version": distribution.version,
            "location": str(distribution.locate_file("").resolve()),
            "project_urls": distribution.metadata.get_all("Project-URL", []),
            "license_expression": distribution.metadata.get("License-Expression"),
            "record_checked_files": len(files), "record_content_sha256": sha(json.dumps(files, sort_keys=True).encode()).hex(),
            "native_modules": native}


def external_runtime(p):
    executable = Path(sys.executable).resolve()
    library = p.library_path
    return {"python": {"version": sys.version, "executable": str(executable), "sha256": file_sha(executable)},
            "platform": platform.platform(),
            "cryptography_backend": backend.openssl_version_text(),
            "distributions": [distribution_identity(name) for name in ("cryptography", "cffi", "pycparser")],
            "libsodium": {"version": p.sodium.sodium_version_string().decode("ascii"),
                          "library": str(library), "bytes": library.stat().st_size, "sha256": file_sha(library)}}


def identities():
    files = [Path(__file__), MANIFEST, PROVENANCE,
             ROOT / "spec/protective-transition.md", ROOT / "spec/format-profile-review.md"]
    files.extend(FIXTURES / name for name in FILE_LIMITS)
    files.extend(path for path in PROVENANCE.parent.rglob("*") if path.is_file())
    return {str(path.relative_to(ROOT)): file_sha(path) for path in sorted(set(files))}


def flip(data, position):
    output = bytearray(data)
    output[position] ^= 1
    return bytes(output)


def rejects(action):
    try:
        action()
    except Reject:
        return
    raise Reject("candidate unexpectedly accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--sodium-library", help="explicit installed libsodium path; default platform loader discovery")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists; choose a fresh evidence path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "fogvault-independent-epoch-proof/v1", "pass": False, "executed": True,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "cases": [],
              "executed_case_ids": [], "source_identity": {}, "external_runtime": {},
              "scope": "Independent diagnostic decode of implementation-captured synthetic content3 bytes; not independent fixture generation, security approval, or a maintained reader",
              "supported_fixture_profile": {"credential_format": 3, "content_format": 3,
                  "suite": 1, "access_profile": "portable", "recovery_enabled": True,
                  "device_slots": 0, "live_records": 1,
                  "kdf": {"argon2_version": 19, "memory_kib": 65536, "iterations": 3, "lanes": 1}},
              "limitations": ["One pinned local Python/OpenSSL/libsodium runtime, no physical-host or all-platform qualification.",
                  "Installed distribution RECORD and native binary identities are checked; this is not a reproducible-build or installed-wheel origin attestation.",
                  "No Rust execution, device-provider path coverage, operation-intent derivation, old-reader admission test, or fixture regeneration occurs here.",
                  "Old default-reader rejection remains covered by the separately executed Rust fixture suite.",
                  "Public synthetic roots/content keys/recovery secret only; Python/ctypes do not claim secret-memory zeroization."]}
    before = None
    def check(identity, action, **evidence):
        try:
            extra = action()
            row = {"id": identity, "status": "pass", "executed": True, **evidence}
            if isinstance(extra, dict):
                row.update(extra)
            report["cases"].append(row)
        except Exception as error:
            report["cases"].append({"id": identity, "status": "fail", "executed": True,
                                    "error": f"{type(error).__name__}: {error}"})
            raise

    try:
        before = identities()
        report["source_identity"] = before
        library = args.sodium_library or ctypes.util.find_library("sodium")
        require(library is not None, "libsodium unavailable; install no production dependency")
        p = Primitives(library)
        inputs = {name: bounded_read(FIXTURES / name, maximum) for name, maximum in FILE_LIMITS.items()}
        manifest = json.loads(bounded_read(MANIFEST, 32768))
        def fixed_admission():
            require(set(manifest["files"]) == set(FILE_LIMITS), "fixed fixture inventory mismatch")
            for name, data in inputs.items():
                require(manifest["files"][name] == {"bytes": len(data), "sha256": sha(data).hex()}, "fixed fixture identity mismatch: " + name)
            require((manifest["credential_format"], manifest["content_format"], manifest["suite"]) == (3, 3, 1), "manifest profile mismatch")
            require(p.counts() == (0, 0), "credential work preceded admission")
            admit(inputs)
            return {"files": len(inputs), "credential_derivations": 0, "aead_openings": 0}
        check(CASES[0], fixed_admission)
        d, head, record, leaf, secret, expected_root, expected_cek = admit(inputs)
        password = manifest["password_utf8"].encode("utf-8", errors="strict")
        require((d.epoch, record.revision, head.generation) == (manifest["root_epoch"], manifest["record_revision"], manifest["generation"]), "manifest epochs/revisions mismatch")
        require(record.identity.hex() == manifest["record_id_hex"], "manifest record identity mismatch")
        root = unlock_password(p, d, password)
        check(CASES[1], lambda: require(root == expected_root, "password root differs from fixed key"))
        check(CASES[2], lambda: require(unlock_recovery(p, d, secret) == expected_root, "recovery root differs from fixed key"))
        check(CASES[3], lambda: verify_head(p, root, d, head))
        check(CASES[4], lambda: verify_membership(head, inputs[NODE], leaf, record))
        cek = unwrap_content_key(p, root, d, record)
        def body_check():
            require(cek == expected_cek, "unwrapped CEK differs from fixed key")
            metadata, payload = decode_body(p, cek, d, record)
            require(metadata == manifest["metadata_utf8"].encode() and payload == manifest["payload_utf8"].encode(), "body differs from fixed plaintext")
            return {"metadata_bytes": len(metadata), "payload_bytes": len(payload), "body_aad_excludes_epoch": True}
        check(CASES[5], body_check)
        check(CASES[6], lambda: rejects(lambda: unlock_password(p, d, b"SYNTHETIC-WRONG-PASSWORD")))
        check(CASES[7], lambda: rejects(lambda: unlock_recovery(p, d, flip(secret, 0))))
        def no_work_rejection(candidate):
            counts = p.counts()
            rejects(lambda: admit(candidate))
            require(p.counts() == counts, "malformed header caused primitive work")
        changed_record = record.raw[:32] + u64(d.epoch + 1) + record.raw[40:]
        check(CASES[8], lambda: no_work_rejection({**inputs, "record.bin": changed_record}), credential_derivations=0, aead_openings=0)
        def epoch_authentication():
            modified_descriptor = d.raw[:30] + u64(d.epoch + 1) + d.raw[38:]
            changed = parse_descriptor(modified_descriptor)
            changed_frame = parse_record(changed_record, changed)
            require(context(d) == context(changed), "immutable context unexpectedly contains mutable epoch")
            require(p.derive(root, d.vault, b"record-key-wrapping") == p.derive(root, changed.vault, b"record-key-wrapping"), "wrapping key changed")
            require(record_aad(d, record, b"record-wrap/v1")[:-8] == record_aad(changed, changed_frame, b"record-wrap/v1")[:-8], "non-epoch AAD changed")
            rejects(lambda: unwrap_content_key(p, root, changed, changed_frame))
            # The body deliberately retains its immutable AAD across this
            # wrapping-only epoch change; this isolates mutable wrap binding.
            require(decode_body(p, cek, changed, changed_frame) == decode_body(p, cek, d, record), "body changed with wrapping epoch")
            return {"same_root": True, "same_wrapping_key": True, "same_immutable_context": True,
                    "encoded_epoch_changed": True, "component_aead_rejected": True, "body_aad_preserved": True}
        check(CASES[9], epoch_authentication)
        wrong_format = d.raw[:12] + struct.pack(">H", 2) + d.raw[14:]
        check(CASES[10], lambda: no_work_rejection({**inputs, "descriptor.bin": wrong_format}), credential_derivations=0, aead_openings=0)
        def content_authentication():
            require(context(d, 2) != context(d, 3), "content context collision")
            rejects(lambda: unwrap_content_key(p, root, d, record, 2))
            rejects(lambda: decode_body(p, cek, d, record, 2))
        check(CASES[11], content_authentication, same_root_and_content_keys=True)
        def malformed_headers():
            candidates = []
            for offset, width, value in [(8, 2, 4), (10, 2, 2), (12, 2, 65535), (38, 8, 0),
                                         (46, 1, 2), (63, 8, 0), (71, 2, 2), (73, 4, 0xffffffff),
                                         (77, 4, 0xffffffff), (81, 4, 0xffffffff), (101, 2, 65535),
                                         (175, 4, 0xffffffff), (179, 1, 2)]:
                candidates.append({**inputs, "descriptor.bin": d.raw[:offset] + value.to_bytes(width, "big") + d.raw[offset + width:]})
            candidates.append({**inputs, "record.bin": record.raw[:112] + u64((1 << 64) - 1) + record.raw[120:]})
            candidates.append({**inputs, "record.bin": record.raw[:24] + u64(0) + record.raw[32:]})
            for candidate in candidates:
                no_work_rejection(candidate)
            return {"rejected_variants": len(candidates), "credential_derivations": 0, "aead_openings": 0}
        check(CASES[12], malformed_headers)
        def tamper_all(name, action):
            for position in range(len(inputs[name])):
                rejects(lambda position=position: action(flip(inputs[name], position)))
            return {"rejected_variants": len(inputs[name]), "mutation": "XOR 01 at each byte independently"}
        check(CASES[13], lambda: tamper_all("descriptor.bin", lambda data: verify_head(p, root, parse_descriptor(data), head)))
        check(CASES[14], lambda: tamper_all("head.bin", lambda data: verify_head(p, root, d, parse_head(data))))
        check(CASES[15], lambda: tamper_all(NODE, lambda data: verify_membership(head, data, parse_leaf(data), record)))
        check(CASES[16], lambda: tamper_all("record.bin", lambda data: verify_membership(head, inputs[NODE], leaf, parse_record(data, d))))
        def wrapper_tamper():
            for position in range(len(record.wrapper)):
                rejects(lambda position=position: unwrap_content_key(p, root, d, replace(record, wrapper=flip(record.wrapper, position))))
            return {"rejected_variants": len(record.wrapper), "rejection_boundary": "independent AEAD"}
        check(CASES[17], wrapper_tamper)
        def body_tamper():
            for position in range(len(record.body)):
                rejects(lambda position=position: decode_body(p, cek, d, replace(record, body=flip(record.body, position))))
            return {"rejected_variants": len(record.body), "rejection_boundary": "independent AEAD"}
        check(CASES[18], body_tamper)
        check(CASES[19], lambda: tamper_all("recovery-kit.bin", lambda data: unlock_recovery(p, d, parse_recovery_kit(data, d))))
        def wrapper_authentication():
            rejects(lambda: unlock_password(p, replace(d, password_wrapper=flip(d.password_wrapper, 71)), password))
            altered = parse_descriptor(flip(d.raw, len(d.raw) - 1))
            require(unlock_password(p, altered, password) == root, "unused recovery wrapper changed password unwrap")
            rejects(lambda: verify_head(p, root, altered, head))
            rejects(lambda: unlock_recovery(p, altered, secret))
        check(CASES[20], wrapper_authentication, unused_recovery_wrapper_rejected_by_head=True)
        def truncate_all():
            variants = 0
            for name, data in inputs.items():
                for end in range(len(data)):
                    no_work_rejection({**inputs, name: data[:end]})
                    variants += 1
                no_work_rejection({**inputs, name: data + b"\0"})
                variants += 1
            return {"rejected_variants": variants, "files": len(inputs), "credential_derivations": 0, "aead_openings": 0}
        check(CASES[21], truncate_all)
        def runtime_check():
            runtime = external_runtime(p)
            report["external_runtime"] = runtime
            provenance = json.loads(bounded_read(PROVENANCE, 131072))
            require(provenance["external_runtime"] == runtime, "runtime differs from exact captured dependency provenance")
            return {"cryptography": runtime["distributions"][0]["version"], "openssl": runtime["cryptography_backend"], "libsodium": runtime["libsodium"]["version"]}
        check(CASES[22], runtime_check)
        check(CASES[23], lambda: require(identities() == before, "proof inputs changed during execution"))
        require(tuple(row["id"] for row in report["cases"]) == CASES, "executed case inventory mismatch")
        report["primitive_operations"] = {"password_derivations": p.credential_derivations, "aead_openings": p.aead_openings}
        report["pass"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        if before is not None and not any(row["id"] == "source_stability" for row in report["cases"]):
            try:
                stable = before == identities()
            except Exception:
                stable = False
            report["cases"].append({"id": "source_stability", "status": "pass" if stable else "fail", "executed": True})
    report["executed_case_ids"] = [row["id"] for row in report["cases"] if row["executed"]]
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(("PASS" if report["pass"] else "FAIL") + " independent epoch diagnostic: " + str(args.output))
    if not report["pass"]:
        print(report.get("error", "unknown failure"), file=sys.stderr)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
