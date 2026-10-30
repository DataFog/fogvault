#!/usr/bin/env python3
"""Check the proposed access graph using symbolic inputs; execute no cryptography.

The JSON graph is the subject under test. Independent Python formulas and fixed
path sets are the oracle. All admission/authentication/provider results below
are assumptions supplied by fixtures, never evidence that a real provider ran.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "conformance/access-paths.json"
REPORT_SCHEMA = "fogvault-access-path-model/v1"
MATERIALS = ("P", "D_A", "D_B", "R")
PROFILES = ("portable", "password_or_device", "password_and_device")
# This allowlist is deliberately independent of the JSON graph under test.
EXPECTED_PATHS = {
    "portable": {"password": ("P",)},
    "password_or_device": {"password": ("P",), "device_a": ("D_A",), "device_b": ("D_B",)},
    "password_and_device": {"password_device_a": ("P", "D_A"), "password_device_b": ("P", "D_B")},
}
EXPECTED_SLOTS = {
    "P": {"id": "password-slot", "role": "passphrase"},
    "D_A": {"id": "device-slot-a", "role": "device-factor", "provider_id": "provider-a",
            "key_id": "device-key-a", "required_capabilities": ["device-local", "nonexportable-operation"]},
    "D_B": {"id": "device-slot-b", "role": "device-factor", "provider_id": "provider-b",
            "key_id": "device-key-b", "required_capabilities": ["device-local", "nonexportable-operation"]},
    "R": {"id": "recovery-slot", "role": "owner-recovery"},
}
EXPECTED_RECOVERY = {"id": "recovery", "requires": ["R"], "output": "restricted_recovery_candidate",
                     "cryptographic_authority": "root", "independent_of_normal_credentials": True}
EXPECTED_ARCHIVES = {
    "native_backup": "retains-original-native-access-policy",
    "age_native_ciphertext": "age-policy-and-original-native-access-policy",
    "age_decoded_records": "separate-data-access-policy-no-native-root-authority",
}
EXPECTED_FRESHNESS = {"unanchored": "authenticated-snapshot-may-be-old",
                      "external_anchor": "reject-snapshot-that-does-not-match-trusted-anchor"}
BINDING_FIELDS = ("vault_id", "profile_id", "policy_epoch", "root_epoch", "recovery_enabled")
GLOBAL_GATES = ("admission_ok", "registration_accepted", "policy_authenticated", "head_authenticated",
                "coherent_snapshot", "audit_complete", "attempt_live", "data_present")
CLAIM_MUTATIONS = ("vault_id", "profile_id", "policy_epoch", "root_epoch", "recovery_enabled", "path_id", "slot_id", "role",
                   "authenticated", "provider_id", "key_id", "capabilities")


def truth_case_id(profile: str, recovery: bool, bits: tuple[bool, ...]) -> str:
    return f"truth/{profile}/recovery-{int(recovery)}/" + "".join(str(int(bit)) for bit in bits)


TRUTH_CASE_IDS = tuple(truth_case_id(profile, recovery, bits) for profile in PROFILES
                       for recovery in (False, True) for bits in itertools.product((False, True), repeat=4))
SCENARIO_CASE_IDS = (
    "contract-exact-paths", "unknown-material-is-not-authority", "session-cache-is-not-unlock",
    "root-cache-is-not-unlock", "export-is-not-native-root", "vendor-reset-is-not-unlock",
    *(f"global-gate/{gate}" for gate in GLOBAL_GATES),
    *(f"factor-binding/{field}" for field in CLAIM_MUTATIONS),
    "registration-vault-pin", "registration-profile-pin", "recovery-choice-cannot-enable-disabled-snapshot",
    "recovery-choice-cannot-disable-enabled-snapshot", "recovery-choice-must-be-boolean", "stale-attempt-after-lock",
    "uncertain-durable-state", "device-unavailable-no-and-fallback", "device-a-cannot-substitute-b",
    "synced-key-is-not-device-bound", "lost-all-devices-and-profile-needs-recovery",
    "lost-all-material-is-unrecoverable", "recovery-cannot-recreate-missing-data",
    "recovery-candidate-is-restricted", "recovery-does-not-require-old-password-or-device",
    "unanchored-old-valid-snapshot-is-possible", "trusted-anchor-rejects-old-snapshot",
    "trusted-anchor-accepts-matching-snapshot", "old-claim-does-not-match-new-policy",
    "enrollment-needs-current-owner-or-recovery", "enrollment-needs-fresh-root-path-proof", "enrollment-needs-recovery-path-proof",
    "enrollment-needs-new-path-proof",
    "enrollment-needs-authenticated-policy-update", "enrollment-needs-live-attempt",
    "enrollment-unknown-outcome-does-not-publish", "enrollment-committed-owner-can-publish",
    "recovery-enrollment-is-not-second-held-factor", "native-backup-retains-original-policy",
    "age-native-container-still-needs-native-credentials", "age-decoded-export-is-separate-data-path",
)
REQUIRED_CASE_IDS = (*TRUTH_CASE_IDS, *SCENARIO_CASE_IDS)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_contract(contract: dict) -> None:
    """Reject changed/extra access edges rather than accepting a weaker policy."""
    require(isinstance(contract, dict), "contract must be an object")
    require(contract.get("schema") == "fogvault-access-path-contract/v1", "unexpected contract schema")
    require(contract.get("scope") == "symbolic-policy-only", "unexpected scope")
    require(contract.get("status") == "proposed-definition-not-production-implementation", "unexpected status")
    require(contract.get("materials") == list(MATERIALS), "material allowlist differs")
    profiles = contract.get("profiles", {})
    require(set(profiles) == set(PROFILES), "profile allowlist differs")
    for profile, expected in EXPECTED_PATHS.items():
        require(set(profiles[profile]) == {"normal_paths"}, "unexpected profile fields")
        paths = profiles[profile]["normal_paths"]
        require(isinstance(paths, list) and len(paths) == len(expected), "missing/extra path")
        require(all(set(path) == {"id", "requires"} for path in paths), "unexpected path fields")
        actual = {path["id"]: tuple(path["requires"]) for path in paths}
        require(len(actual) == len(paths) and actual == expected, "changed or duplicate path")
    require(contract.get("slots") == EXPECTED_SLOTS, "slot identity/capability contract differs")
    require(contract.get("recovery_path") == EXPECTED_RECOVERY, "recovery authority differs")
    require(contract.get("prohibited_implicit_paths") == ["session-cache", "root-cache", "export", "vendor-reset"],
            "implicit-path exclusions differ")
    require(contract.get("archives") == EXPECTED_ARCHIVES, "archive authority differs")
    require(contract.get("freshness") == EXPECTED_FRESHNESS, "freshness claim differs")
    require(isinstance(contract.get("limitations"), list) and len(contract["limitations"]) >= 5,
            "scope limitations missing")
    require(set(contract) == {"schema", "scope", "status", "materials", "profiles", "recovery_path", "slots",
                              "prohibited_implicit_paths", "archives", "freshness", "limitations"},
            "unexpected top-level fields")


def load_contract(path: Path = CONTRACT) -> dict:
    contract = json.loads(path.read_text())
    validate_contract(contract)
    return contract


def make_context(profile_id: str, recovery_enabled: bool = False) -> dict:
    """Trusted-input fixture; accepted profile/registration are not read from JSON."""
    require(profile_id in PROFILES and type(recovery_enabled) is bool, "unaccepted fixture policy")
    return {"snapshot": {"vault_id": "vault-a", "profile_id": profile_id, "policy_epoch": 7,
                         "root_epoch": 3, "head_id": "head-7", "recovery_enabled": recovery_enabled},
            "registration": {"vault_id": "vault-a", "profile_id": profile_id},
            "accepted_profile_id": profile_id,
            "provider_pins": {material: {key: value for key, value in EXPECTED_SLOTS[material].items()
                                         if key in ("provider_id", "key_id")}
                              for material in ("D_A", "D_B")},
            "admitted_device_capabilities": ["device-local", "nonexportable-operation"],
            **{gate: True for gate in GLOBAL_GATES}, "attempt_epoch": 5, "current_attempt_epoch": 5,
            "durable_state": "accepted", "freshness_anchor": None}


def graph_paths(contract: dict, profile_id: str, recovery_enabled: bool) -> list[dict]:
    paths = list(contract["profiles"][profile_id]["normal_paths"])
    return paths + ([contract["recovery_path"]] if recovery_enabled else [])


def make_claims(contract: dict, profile_id: str, materials: set[str], context: dict) -> list[dict]:
    """Create path-bound symbolic evidence for available material, including R."""
    claims = []
    for path in graph_paths(contract, profile_id, True):
        for material in path["requires"]:
            if material not in materials:
                continue
            slot = contract["slots"][material]
            claim = {"material": material, **{field: context["snapshot"][field] for field in BINDING_FIELDS},
                     "path_id": path["id"], "slot_id": slot["id"], "role": slot["role"],
                     "authenticated": True}
            if material in ("D_A", "D_B"):
                claim.update(provider_id=slot["provider_id"], key_id=slot["key_id"],
                             capabilities=list(slot["required_capabilities"]))
            claims.append(claim)
    return claims


def context_admitted(profile_id: str, context: dict, recovery_enabled: bool) -> bool:
    snapshot = context.get("snapshot", {})
    registration = context.get("registration", {})
    if not all(context.get(gate) is True for gate in GLOBAL_GATES):
        return False
    if (context.get("durable_state") != "accepted" or type(context.get("attempt_epoch")) is not int
            or context.get("attempt_epoch") != context.get("current_attempt_epoch")):
        return False
    if not all(field in snapshot for field in (*BINDING_FIELDS, "head_id")):
        return False
    if context.get("accepted_profile_id") != profile_id or snapshot.get("profile_id") != profile_id:
        return False
    if type(snapshot.get("recovery_enabled")) is not bool or snapshot["recovery_enabled"] != recovery_enabled:
        return False
    if registration != {"vault_id": snapshot["vault_id"], "profile_id": profile_id}:
        return False
    anchor = context.get("freshness_anchor")
    return anchor is None or anchor == {field: snapshot[field] for field in (*BINDING_FIELDS, "head_id")}


def claim_admitted(contract: dict, claim: dict, material: str, path_id: str, context: dict) -> bool:
    slot = contract["slots"][material]
    if claim.get("material") != material or claim.get("authenticated") is not True:
        return False
    expected = {**{field: context["snapshot"][field] for field in BINDING_FIELDS},
                "path_id": path_id, "slot_id": slot["id"], "role": slot["role"]}
    if any(claim.get(field) != value for field, value in expected.items()):
        return False
    if material in ("D_A", "D_B"):
        pins = context.get("provider_pins", {}).get(material, {})
        if pins != {key: slot[key] for key in ("provider_id", "key_id")}:
            return False
        if any(claim.get(key) != pins[key] for key in ("provider_id", "key_id")):
            return False
        required = set(slot["required_capabilities"])
        if set(claim.get("capabilities", [])) != required:
            return False
        if not required.issubset(set(context.get("admitted_device_capabilities", []))):
            return False
    return True


def evaluate_access(contract: dict, profile_id: str, claims: list[dict], context: dict,
                    recovery_enabled: bool = False) -> dict:
    """Return candidate paths only, never real keys, sessions, or unlock success."""
    validate_contract(contract)
    require(profile_id in PROFILES and type(recovery_enabled) is bool, "unsupported policy input")
    candidates = []
    if context_admitted(profile_id, context, recovery_enabled):
        for path in graph_paths(contract, profile_id, recovery_enabled):
            if all(any(claim_admitted(contract, claim, material, path["id"], context) for claim in claims)
                   for material in path["requires"]):
                candidates.append(path["id"])
    return {"candidate_paths": candidates, "normal_candidate": any(path != "recovery" for path in candidates),
            "recovery_candidate": "recovery" in candidates, "session_published": False,
            "recovery_output": "restricted_recovery_candidate" if "recovery" in candidates else None,
            "freshness": "externally-anchored" if context.get("freshness_anchor") is not None else "unanchored",
            "scope": "symbolic-policy-only"}


def enrollment_decision(authority: str, *, attempt_live: bool, fresh_root_path_reauthenticated: bool,
                        recovery_path_proven: bool, new_path_proven: bool,
                        policy_update_authenticated: bool, transaction_outcome: str) -> str:
    """Symbolic publication rule; proving new credentials is not an extra old factor."""
    qualified_authority = ((authority == "current-owner-session" and fresh_root_path_reauthenticated is True)
                           or (authority == "approved-recovery-workflow" and recovery_path_proven is True))
    if not (qualified_authority and attempt_live is True and new_path_proven is True
            and policy_update_authenticated is True):
        return "reject"
    if transaction_outcome == "unknown":
        return "reconcile"
    return "publish" if transaction_outcome == "committed" else "reject"


def expected_paths(profile: str, materials: set[str], recovery: bool) -> set[str]:
    """Independent formula oracle, intentionally not traversing JSON edges."""
    password, device_a, device_b, rescue = (material in materials for material in MATERIALS)
    paths = set()
    if profile == "portable":
        if password:
            paths.add("password")
    elif profile == "password_or_device":
        if password:
            paths.add("password")
        if device_a:
            paths.add("device_a")
        if device_b:
            paths.add("device_b")
    elif profile == "password_and_device":
        if password and device_a:
            paths.add("password_device_a")
        if password and device_b:
            paths.add("password_device_b")
    if recovery and rescue:
        paths.add("recovery")
    return paths


def source_identity() -> dict[str, str]:
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (CONTRACT, Path(__file__).resolve())}


def run_checks(contract: dict | None = None) -> dict:
    """Execute all fixed cases and return independently inspectable result rows."""
    definition = json.loads(CONTRACT.read_text()) if contract is None else deepcopy(contract)
    cases = []

    def case(identity, operation):
        try:
            detail = operation()
            cases.append({"id": identity, "status": "pass", "executed": True, **(detail or {})})
        except (ValueError, KeyError, TypeError, AssertionError) as error:
            cases.append({"id": identity, "status": "fail", "executed": True, "reason": str(error)})

    def result(profile="password_and_device", materials=None, recovery=False, context=None, claims=None):
        context = make_context(profile, recovery) if context is None else context
        claims = make_claims(definition, profile, {"P", "D_A"} if materials is None else materials, context) if claims is None else claims
        return evaluate_access(definition, profile, claims, context, recovery)

    def denied(**kwargs):
        require(not result(**kwargs)["candidate_paths"], "unexpected candidate authority")

    for profile in PROFILES:
        for recovery in (False, True):
            for bits in itertools.product((False, True), repeat=4):
                def truth(profile=profile, recovery=recovery, bits=bits):
                    materials = {material for material, present in zip(MATERIALS, bits) if present}
                    actual = result(profile, materials, recovery)
                    expected = expected_paths(profile, materials, recovery)
                    require(set(actual["candidate_paths"]) == expected, "path set differs from independent formula")
                    require(actual["normal_candidate"] == bool(expected - {"recovery"}), "normal result differs")
                    require(actual["recovery_candidate"] == ("recovery" in expected), "recovery result differs")
                    require(actual["session_published"] is False, "symbolic checker published session")
                    return {"materials": sorted(materials), "expected_paths": sorted(expected),
                            "candidate_paths": actual["candidate_paths"]}
                case(truth_case_id(profile, recovery, bits), truth)

    case("contract-exact-paths", lambda: validate_contract(definition))
    for material, identity in (("unknown", "unknown-material-is-not-authority"),
                               ("session-cache", "session-cache-is-not-unlock"),
                               ("root-cache", "root-cache-is-not-unlock"),
                               ("export", "export-is-not-native-root"), ("vendor-reset", "vendor-reset-is-not-unlock")):
        case(identity, lambda material=material: denied(claims=[{"material": material, "authenticated": True}]))
    for gate in GLOBAL_GATES:
        def gate_check(gate=gate):
            context = make_context("password_and_device", True)
            context[gate] = False
            denied(context=context, materials=set(MATERIALS), recovery=True)
        case(f"global-gate/{gate}", gate_check)
    for field in CLAIM_MUTATIONS:
        def binding_check(field=field):
            context = make_context("password_and_device")
            claims = make_claims(definition, "password_and_device", {"P", "D_A"}, context)
            device = next(claim for claim in claims if claim["material"] == "D_A")
            device[field] = False if field == "authenticated" else ([] if field == "capabilities" else "foreign")
            denied(context=context, claims=claims)
        case(f"factor-binding/{field}", binding_check)

    def changed_context(key, value, nested=None):
        context = make_context("password_and_device")
        (context if nested is None else context[nested])[key] = value
        denied(context=context)

    case("registration-vault-pin", lambda: changed_context("vault_id", "foreign", "registration"))
    case("registration-profile-pin", lambda: changed_context("accepted_profile_id", "portable"))

    def recovery_choice_mismatch(snapshot_choice, requested_choice):
        context = make_context("password_and_device", snapshot_choice)
        denied(context=context, materials=set(MATERIALS), recovery=requested_choice)
    case("recovery-choice-cannot-enable-disabled-snapshot", lambda: recovery_choice_mismatch(False, True))
    case("recovery-choice-cannot-disable-enabled-snapshot", lambda: recovery_choice_mismatch(True, False))

    def malformed_recovery_choice():
        context = make_context("password_and_device", True)
        context["snapshot"]["recovery_enabled"] = "true"
        denied(context=context, materials=set(MATERIALS), recovery=True)
    case("recovery-choice-must-be-boolean", malformed_recovery_choice)
    case("stale-attempt-after-lock", lambda: changed_context("current_attempt_epoch", 6))
    case("uncertain-durable-state", lambda: changed_context("durable_state", "unknown"))
    case("device-unavailable-no-and-fallback", lambda: denied(materials={"P"}))

    def wrong_device():
        context = make_context("password_and_device")
        claims = make_claims(definition, "password_and_device", {"P", "D_A"}, context)
        device = next(claim for claim in claims if claim["material"] == "D_A")
        device["material"] = "D_B"
        denied(context=context, claims=claims)
    case("device-a-cannot-substitute-b", wrong_device)

    def synced_device():
        context = make_context("password_and_device")
        claims = make_claims(definition, "password_and_device", {"P", "D_A"}, context)
        next(claim for claim in claims if claim["material"] == "D_A")["capabilities"] = ["synced", "portable"]
        denied(context=context, claims=claims)
    case("synced-key-is-not-device-bound", synced_device)
    case("lost-all-devices-and-profile-needs-recovery", lambda: require(
        result(materials={"P", "R"}, recovery=True)["candidate_paths"] == ["recovery"], "device loss bypassed normal AND"))
    case("lost-all-material-is-unrecoverable", lambda: denied(materials=set(), recovery=True))
    def recovery_without_data():
        context = make_context("password_and_device", True)
        context["data_present"] = False
        denied(context=context, materials={"R"}, recovery=True)
    case("recovery-cannot-recreate-missing-data", recovery_without_data)

    def recovery_restricted():
        actual = result(materials={"R"}, recovery=True)
        require(actual["candidate_paths"] == ["recovery"] and actual["recovery_output"] == "restricted_recovery_candidate"
                and not actual["normal_candidate"] and not actual["session_published"], "recovery output not restricted")
        require(definition["recovery_path"]["cryptographic_authority"] == "root", "recovery root authority hidden")
    case("recovery-candidate-is-restricted", recovery_restricted)
    case("recovery-does-not-require-old-password-or-device", lambda: require(
        result(materials={"R"}, recovery=True)["recovery_candidate"], "recovery incorrectly needs unavailable old factors"))

    def old_context():
        context = make_context("password_and_device")
        context["snapshot"].update(policy_epoch=6, root_epoch=2, head_id="head-6")
        return context

    case("unanchored-old-valid-snapshot-is-possible", lambda: require(
        result(context=old_context())["normal_candidate"], "model invented unanchored freshness guarantee"))

    def anchored_old():
        context = old_context()
        context["freshness_anchor"] = deepcopy(make_context("password_and_device")["snapshot"])
        denied(context=context)
    case("trusted-anchor-rejects-old-snapshot", anchored_old)

    def anchored_current():
        context = make_context("password_and_device")
        context["freshness_anchor"] = deepcopy(context["snapshot"])
        actual = result(context=context)
        require(actual["normal_candidate"] and actual["freshness"] == "externally-anchored", "matching anchor rejected")
    case("trusted-anchor-accepts-matching-snapshot", anchored_current)

    def old_claim():
        claims = make_claims(definition, "password_and_device", {"P", "D_A"}, old_context())
        denied(claims=claims)
    case("old-claim-does-not-match-new-policy", old_claim)

    def enrollment(**changes):
        inputs = {"authority": "current-owner-session", "attempt_live": True, "fresh_root_path_reauthenticated": True,
                  "recovery_path_proven": False, "new_path_proven": True,
                  "policy_update_authenticated": True, "transaction_outcome": "committed", **changes}
        return enrollment_decision(**inputs)

    case("enrollment-needs-current-owner-or-recovery", lambda: require(
        enrollment(authority="device-provider-only") == "reject", "provider self-enrolled"))
    case("enrollment-needs-fresh-root-path-proof", lambda: require(
        enrollment(fresh_root_path_reauthenticated=False) == "reject", "session without fresh root path enrolled"))
    case("enrollment-needs-recovery-path-proof", lambda: require(
        enrollment(authority="approved-recovery-workflow", fresh_root_path_reauthenticated=False) == "reject",
        "recovery workflow without qualified R proof enrolled"))
    case("enrollment-needs-new-path-proof", lambda: require(enrollment(new_path_proven=False) == "reject", "unproved path enrolled"))
    case("enrollment-needs-authenticated-policy-update", lambda: require(
        enrollment(policy_update_authenticated=False) == "reject", "unauthenticated policy published"))
    case("enrollment-needs-live-attempt", lambda: require(enrollment(attempt_live=False) == "reject", "locked enrollment published"))
    case("enrollment-unknown-outcome-does-not-publish", lambda: require(
        enrollment(transaction_outcome="unknown") == "reconcile", "unknown enrollment published"))
    case("enrollment-committed-owner-can-publish", lambda: require(enrollment() == "publish", "committed owner enrollment rejected"))
    case("recovery-enrollment-is-not-second-held-factor", lambda: require(
        result(materials={"R"}, recovery=True)["recovery_candidate"]
        and enrollment(authority="approved-recovery-workflow", fresh_root_path_reauthenticated=False, recovery_path_proven=True)
        == "publish", "new-path proof became another old factor"))
    case("native-backup-retains-original-policy", lambda: require(
        definition["archives"]["native_backup"] == EXPECTED_ARCHIVES["native_backup"]
        and not result(materials=set())["candidate_paths"] and result()["normal_candidate"], "native backup bypassed credentials"))
    case("age-native-container-still-needs-native-credentials", lambda: require(
        definition["archives"]["age_native_ciphertext"] == EXPECTED_ARCHIVES["age_native_ciphertext"]
        and not result(materials={"age-recipient"})["candidate_paths"], "age recipient became native root factor"))
    case("age-decoded-export-is-separate-data-path", lambda: require(
        definition["archives"]["age_decoded_records"] == EXPECTED_ARCHIVES["age_decoded_records"]
        and not result(claims=[{"material": "export", "authenticated": True}])["candidate_paths"],
        "decoded export authority confused with native root"))

    executed_ids = [case["id"] for case in cases]
    require(tuple(executed_ids) == REQUIRED_CASE_IDS and len(set(executed_ids)) == len(executed_ids),
            "checker omitted, duplicated or reordered required cases")
    passed = all(case["executed"] is True and case["status"] == "pass" for case in cases)
    return {"schema": REPORT_SCHEMA, "scope": "symbolic-policy-only", "crypto_or_provider_execution": False,
            "pass": passed, "executed": True, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "truth_table_combinations": len(TRUTH_CASE_IDS), "case_count": len(cases),
            "executed_case_ids": executed_ids, "cases": cases, "source_identity": source_identity(),
            "claim": "Exact proposed access edges and symbolic publication gates match independent formulas and negative cases.",
            "limitations": definition.get("limitations", [])}


def check_policy_contract(contract: dict) -> dict:
    report = run_checks(contract)
    require(report["pass"], "; ".join(case["id"] for case in report["cases"] if case["status"] != "pass"))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    output = options.output.resolve()
    if output.exists():
        parser.error("output must be a fresh path")
    report = run_checks()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"access-path-model: {report['case_count']} cases, {report['truth_table_combinations']} combinations: "
          + ("PASS" if report["pass"] else "FAIL"))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
