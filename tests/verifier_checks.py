"""Verifier-contract checks. No Cargo commands or vault operations run here."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("vault_verifier", ROOT / "scripts/verify-vault.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)
ACCESS_SPEC = importlib.util.spec_from_file_location("access_path_model", ROOT / "scripts/verify-access-paths.py")
access_model = importlib.util.module_from_spec(ACCESS_SPEC)
ACCESS_SPEC.loader.exec_module(access_model)
SCREEN_SPEC = importlib.util.spec_from_file_location("export_screening", ROOT / "scripts/verify-export-screening.py")
export_screening = importlib.util.module_from_spec(SCREEN_SPEC)
SCREEN_SPEC.loader.exec_module(export_screening)


class VerifierChecks(unittest.TestCase):
    def test_fresh_epoch_corpus_and_complete_decoder_case_inventory_are_required(self):
        import ast
        settings = verifier.load_contract()["fresh_epoch"]
        tree = ast.parse((ROOT / "scripts/verify-fresh-epoch.py").read_text())
        declared = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets))
        self.assertEqual(set(settings["required_cases"]), set(declared))
        self.assertEqual(settings["report_schema"], "fogvault-independent-fresh-epoch-proof/v1")
        self.assertIn("conformance/fresh-epoch-vectors.json", settings["source_files"])
        manifest = json.loads((ROOT / "conformance/fresh-epoch-vectors.json").read_text())
        self.assertEqual((manifest["credential_format"], manifest["content_format"], manifest["root_epoch"]), (3, 3, 0))
        self.assertEqual(len(manifest["files"]), 5)
        for name, expected in manifest["files"].items():
            path = ROOT / "conformance/fresh-epoch-vectors" / name
            self.assertEqual(path.stat().st_size, expected["bytes"])
            self.assertEqual(verifier.sha256(path), expected["sha256"])
            self.assertIn(str(path.relative_to(ROOT)), settings["source_files"])

    def test_export_screening_never_promotes_a_failed_backend_to_qualified(self):
        good = {"schema": "fogvault-rust-export-proof/v1", "pass": False,
            "functional_pass": True, "audit_pass": False, "backend_dependency_qualified": False,
            "backend_selected_for_production": False,
            "backend": {"crate": "age", "version": "0.11.5", "default_features": False},
            "dependency_audit": {"vulnerabilities": {"found": False, "count": 0, "list": []},
                "settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None},
                "warnings": {"unmaintained": [{"advisory": {"id": name}} for name in sorted(export_screening.WARNINGS)]}},
            "cases": [{"id": "rust_age_dependency_advisory_and_license_inventory", "status": "fail",
                "executed": True, "suppression_applied": False},
                {"id": "rust_age_source_stability", "status": "pass", "executed": True}]}
        self.assertIs(export_screening.assess(good, 1)["backend_selected_for_production"], False)
        for key in ["pass", "audit_pass", "backend_dependency_qualified", "backend_selected_for_production"]:
            changed = json.loads(json.dumps(good)); changed[key] = True
            with self.assertRaises(ValueError): export_screening.assess(changed, 1)
        for edit in [lambda r: r["dependency_audit"]["settings"].update(ignore=["RUSTSEC-2026-0374"]),
                     lambda r: r["dependency_audit"].update(warnings={}),
                     lambda r: r["cases"][0].update(suppression_applied=True),
                     lambda r: r.update(functional_pass=False)]:
            changed = json.loads(json.dumps(good)); edit(changed)
            with self.assertRaises(ValueError): export_screening.assess(changed, 1)
        with self.assertRaises(ValueError): export_screening.assess(good, 0)

    def test_epoch_corpus_requires_fixed_bytes_and_explicit_profile(self):
        path = ROOT / verifier.load_contract()["epoch_vectors"]
        self.assertEqual(verifier.validate_epoch_vectors(path)["files"], 7)
        original = verifier.sha256
        with mock.patch.object(verifier, "sha256", side_effect=lambda path: "0" * 64 if path.name == "record.bin" else original(path)):
            with self.assertRaises(ValueError): verifier.validate_epoch_vectors(path)

    def test_fixed_access_projection_and_binary_identity_are_required(self):
        settings = verifier.load_contract()["access_format_vectors"]
        fixture, projection = ROOT / settings["fixture"], ROOT / settings["rust_projection"]
        result = verifier.validate_access_vectors(fixture, projection, settings)
        self.assertEqual(result["boundary_counts"], {"accept": 7, "parse": 10, "unlock": 7, "audit": 2})
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "projection.tsv"
            altered.write_text(projection.read_text().replace("\tunlock\n", "\taccept\n", 1))
            with self.assertRaises(ValueError):
                verifier.validate_access_vectors(fixture, altered, settings)
        original = verifier.sha256
        with mock.patch.object(verifier, "sha256", side_effect=lambda path: "0" * 64 if path.name == "strict-descriptor.bin" else original(path)):
            with self.assertRaises(ValueError):
                verifier.validate_access_vectors(fixture, projection, settings)

    def test_focused_proof_requires_cases_execution_and_current_sources(self):
        settings = {"report_schema": "unit-proof/v1", "required_cases": ["proof"], "source_files": ["scripts/verify-export-payload.py"]}
        good = {"schema": settings["report_schema"], "pass": True, "executed": True, "source_identity": {relative: verifier.sha256(ROOT / relative) for relative in settings["source_files"]}, "cases": [{"id": "proof", "status": "pass", "executed": True}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(good))
            verifier.validate_proof_file(path, settings)
            for edit in [lambda r: r.update(executed=False), lambda r: r["source_identity"].clear(), lambda r: r.update(cases=[]), lambda r: r["cases"][0].update(executed=False), lambda r: r["cases"].append({"id": "unexpected", "status": "pass", "executed": True})]:
                changed = json.loads(json.dumps(good)); edit(changed); path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    verifier.validate_proof_file(path, settings)

    def test_node_password_helper_evidence_cannot_claim_browser_qualification(self):
        settings = json.loads((ROOT / "conformance/host-feasibility-contract.json").read_text())["browser"]["password_adapter_node"]
        evidence = {"schema": settings["schema"], "scope": settings["scope"], "pass": True, "executed": True, "node": "v25.8.2", "shared_array_buffer_available": True, "cases": [{"id": identity, "status": "pass", "executed": True} for identity in settings["cases"]], "source_identity": {relative: verifier.sha256(ROOT / relative) for relative in settings["source_files"]}}
        verifier.validate_password_adapter_node({"password_adapter_node": evidence}, settings)
        for change in [{"scope": "browser-SAB-qualified"}, {"executed": False}, {"source_identity": {}}, {"cases": evidence["cases"][:-1]}, {"shared_array_buffer_available": False}]:
            with self.assertRaises(ValueError):
                verifier.validate_password_adapter_node({"password_adapter_node": {**evidence, **change}}, settings)

    def test_password_vectors_reject_lossy_encoding_and_stale_projection(self):
        settings = verifier.load_contract()["password_vectors"]
        original = json.loads((ROOT / settings["fixture"]).read_text())
        projection = ROOT / settings["rust_projection"]
        evidence = verifier.validate_password_vectors(ROOT / settings["fixture"], projection, settings)
        self.assertEqual(len(evidence["groups"]["text"]), 17)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            changed_projection = Path(directory) / "vectors.tsv"
            mutations = []
            changed = json.loads(json.dumps(original))
            next(row for row in changed["text"] if row["id"] == "decomposed")["utf8_hex"] = "c3a9"
            mutations.append(changed)
            changed = json.loads(json.dumps(original))
            changed["invalid_utf16"][0]["utf16_units"] = [65]
            mutations.append(changed)
            changed = json.loads(json.dumps(original))
            changed["invalid_utf8"][0]["bytes_hex"] = "efbfbd"
            mutations.append(changed)
            changed = json.loads(json.dumps(original))
            changed["text"][0]["utf16_units"] = [True]
            mutations.append(changed)
            changed = json.loads(json.dumps(original))
            changed["text"].pop()
            mutations.append(changed)
            for changed in mutations:
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    verifier.validate_password_vectors(path, projection, settings)
            path.write_text(json.dumps(original))
            changed_projection.write_text(projection.read_text().replace("precomposed", "changed"))
            with self.assertRaises(ValueError):
                verifier.validate_password_vectors(path, changed_projection, settings)

    def test_browser_password_evidence_requires_exact_vectors_and_lifecycle_ids(self):
        fixture = json.loads((ROOT / "conformance/password-vectors.json").read_text())
        settings = json.loads((ROOT / "conformance/host-feasibility-contract.json").read_text())["browser"]["password_vector_cases"]
        text = {"id": settings["text_case"], "vectors": [{"id": row["id"], "utf8_hex": row["utf8_hex"]} for row in fixture["text"]], "invalid_utf16_ids": [row["id"] for row in fixture["invalid_utf16"]]}
        lifecycle = {"id": settings["lifecycle_case"], **{field + "_id": identity for field, identity in fixture["lifecycle"].items()}}
        boundary = {"id": settings["byte_boundary_case"], "shared_array_buffer_available": False, "shared_binding_rejection_executed": False, "shared_worker_rejection_executed": False, "shared_binding_rejections": 0}
        report = {"cases": [text, lifecycle, boundary]}
        verifier.validate_browser_passwords(report, settings)
        for mutation in [lambda value: value["cases"][0]["vectors"].pop(), lambda value: value["cases"][0]["vectors"][6].update(utf8_hex="65cc81"), lambda value: value["cases"][0]["invalid_utf16_ids"].pop(), lambda value: value["cases"][1].update(old_password_id="ascii"), lambda value: value["cases"][2].update(shared_binding_rejection_executed=True)]:
            changed = json.loads(json.dumps(report))
            mutation(changed)
            with self.assertRaises(ValueError):
                verifier.validate_browser_passwords(changed, settings)

    def test_mobile_password_evidence_requires_executed_vectors_and_header_provenance(self):
        settings = json.loads((ROOT / "conformance/host-feasibility-contract.json").read_text())["mobile"]["password_vector_cases"]
        fixture_path = ROOT / settings["fixture"]
        fixture = json.loads(fixture_path.read_text())
        groups = {case: [row["id"] for row in fixture[group]] for case, group in settings["groups"].items()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "password_vectors.h"
            path.write_text("structural unit fixture\n")
            header = {"path": str(path), "bytes": path.stat().st_size, "sha256": verifier.sha256(path)}
            cases = [{"id": case, "executed": True, "vector_ids": ids, "vectors_checked": len(ids), "fixture_sha256": verifier.sha256(fixture_path)} for case, ids in groups.items()]
            report = {"password_vectors": {"fixture": settings["fixture"], "sha256": verifier.sha256(fixture_path), "groups": groups, "generated_header": header}, "targets": [{"id": target, "cases": json.loads(json.dumps(cases)), "artifacts": [header]} for target in ["native-abi-runtime", "ios-simulator-abi-runtime"]]}
            verifier.validate_mobile_passwords(report, settings)
            for mutation in [lambda value: value["password_vectors"].update(sha256="0" * 64), lambda value: value["targets"][0]["cases"][0].update(vectors_checked=True), lambda value: value["targets"][1]["cases"][1]["vector_ids"].pop(), lambda value: value["targets"][0]["cases"][0].update(executed=False), lambda value: value["targets"][1].update(artifacts=[])]:
                changed = json.loads(json.dumps(report))
                mutation(changed)
                with self.assertRaises(ValueError):
                    verifier.validate_mobile_passwords(changed, settings)
            path.write_text("changed header\n")
            with self.assertRaises(ValueError):
                verifier.validate_mobile_passwords(report, settings)

    def test_access_model_evidence_requires_complete_execution_and_honest_scope(self):
        contract = verifier.load_contract()
        report = access_model.run_checks()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.json"
            path.write_text(json.dumps(report))
            self.assertEqual(verifier.validate_access_file(path, contract)["truth_table_combinations"], 96)
            changes = [
                {"pass": False}, {"executed": False}, {"truth_table_combinations": True},
                {"truth_table_combinations": 95}, {"case_count": True}, {"case_count": 1},
                {"scope": "cryptographic-unlock-proof"},
                {"crypto_or_provider_execution": True}, {"cases": report["cases"][:-1]},
                {"cases": report["cases"][:-1] + [report["cases"][0]]},
                {"cases": [{**case, "executed": False} for case in report["cases"]]},
                {"cases": [{**case, "status": "unavailable"} for case in report["cases"]]},
                {"executed_case_ids": report["executed_case_ids"][:-1]}, {"source_identity": {}},
            ]
            for change in changes:
                with self.subTest(change=list(change)):
                    path.write_text(json.dumps({**report, **change}))
                    with self.assertRaises(ValueError):
                        verifier.validate_access_file(path, contract)

    def test_access_graph_rejects_bypasses_instead_of_regenerating_expected_policy(self):
        original = access_model.load_contract()
        changes = []
        changed = json.loads(json.dumps(original))
        changed["profiles"]["password_and_device"]["normal_paths"][0]["requires"] = ["D_A"]
        changes.append(changed)
        changed = json.loads(json.dumps(original))
        changed["profiles"]["password_and_device"]["normal_paths"].append({"id": "hidden-password", "requires": ["P"]})
        changes.append(changed)
        changed = json.loads(json.dumps(original))
        changed["recovery_path"]["requires"] = ["R", "P"]
        changes.append(changed)
        changed = json.loads(json.dumps(original))
        changed["slots"]["D_A"]["required_capabilities"] = ["synced"]
        changes.append(changed)
        changed = json.loads(json.dumps(original))
        changed["archives"]["age_decoded_records"] = "native-root-authority"
        changes.append(changed)
        for changed in changes:
            with self.assertRaises(ValueError):
                access_model.validate_contract(changed)

    def test_access_inputs_cannot_turn_on_recovery_or_satisfy_half_an_and_path(self):
        definition = access_model.load_contract()
        profile = "password_and_device"
        for materials, expected in [({"P"}, False), ({"D_A"}, False), ({"P", "D_A"}, True)]:
            context = access_model.make_context(profile)
            claims = access_model.make_claims(definition, profile, materials, context)
            actual = access_model.evaluate_access(definition, profile, claims, context)
            self.assertEqual(actual["normal_candidate"], expected)
            self.assertIs(actual["session_published"], False)
        context = access_model.make_context(profile)
        claims = access_model.make_claims(definition, profile, {"R"}, context)
        actual = access_model.evaluate_access(definition, profile, claims, context, recovery_enabled=True)
        self.assertEqual(actual["candidate_paths"], [])
        context = access_model.make_context(profile, recovery_enabled=True)
        claims = access_model.make_claims(definition, profile, {"P", "D_A", "R"}, context)
        for claim in claims:
            if claim["material"] == "D_A":
                claim["key_id"] = "foreign-key"
        actual = access_model.evaluate_access(definition, profile, claims, context, recovery_enabled=True)
        self.assertEqual(actual["candidate_paths"], ["recovery"])
        self.assertIs(actual["normal_candidate"], False)

    def test_access_enrollment_needs_real_authority_and_explicit_symbolic_proof(self):
        owner = {"authority": "current-owner-session", "attempt_live": True,
                 "fresh_root_path_reauthenticated": True, "recovery_path_proven": False,
                 "new_path_proven": True, "policy_update_authenticated": True,
                 "transaction_outcome": "committed"}
        self.assertEqual(access_model.enrollment_decision(**owner), "publish")
        for field in ["attempt_live", "fresh_root_path_reauthenticated", "new_path_proven", "policy_update_authenticated"]:
            for value in [False, "false", 1, None]:
                self.assertEqual(access_model.enrollment_decision(**{**owner, field: value}), "reject")
        rescue = {**owner, "authority": "approved-recovery-workflow", "fresh_root_path_reauthenticated": False}
        self.assertEqual(access_model.enrollment_decision(**rescue), "reject")
        self.assertEqual(access_model.enrollment_decision(**{**rescue, "recovery_path_proven": True}), "publish")
        self.assertEqual(access_model.enrollment_decision(**{**owner, "transaction_outcome": "unknown"}), "reconcile")

    def test_access_stage_contract_cannot_omit_policy_cases_or_change_runner(self):
        original = json.loads((ROOT / "conformance/vault-contract.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            for field, value in [("definition", "unreviewed.json"), ("truth_table_combinations", True),
                                 ("required_cases", []), ("command", ["python3", "automatic-pass.py"])]:
                changed = json.loads(json.dumps(original))
                changed["access_paths"][field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    verifier.load_contract(path)

    def test_expected_behavior_must_execute_not_just_have_a_pass_slogan(self):
        expected = ["real_case"]
        self.assertEqual(verifier.require_cases("test real_case ... ok\n", expected)["required_cases"], expected)
        for output in ["All tests passed", "test real_case ... ignored", "test renamed_case ... ok", "test real_case ... FAILED"]:
            with self.assertRaises(ValueError):
                verifier.require_cases(output, expected)

    def test_moved_primitive_cases_require_execution_in_the_core_stage(self):
        contract = {"required_core_cases": ["crypto::tests::retained_case"], "required_native_cases": ["adapter_case"], "required_fixture_cases": ["fixture_case"]}
        native = {"id": "native-tests", "evidence": {"executed_cases": ["adapter_case", "fixture_case", "crypto::tests::retained_case"]}}
        result = verifier.behavior_evidence([native], contract)
        self.assertEqual(result["required_case_count"], 3)
        self.assertEqual(result["groups"]["core-tests"]["missing_cases"], ["crypto::tests::retained_case"])
        core = {"id": "core-tests", "evidence": verifier.require_cases("test crypto::tests::retained_case ... ok\n", contract["required_core_cases"])}
        self.assertFalse(verifier.behavior_evidence([core, native], contract)["groups"]["core-tests"]["missing_cases"])

    def test_private_core_api_proofs_must_actually_execute(self):
        output = "\n".join(f"test src/lib.rs - (line {line}) - compile fail ... ok" for line in range(1, 5))
        self.assertEqual(verifier.require_private_api_doctests(output)["protected_boundaries"], ["crypto", "format", "index", "root_key"])
        for changed in ["4 tests passed", output.replace("compile fail", "ignored"), output.rsplit("\n", 1)[0], output + "\n" + output.splitlines()[0]]:
            with self.assertRaises(ValueError):
                verifier.require_private_api_doctests(changed)

    def test_contract_requires_distinct_core_native_and_fixture_cases(self):
        original = json.loads((ROOT / "conformance/vault-contract.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            for changed in [{**original, "required_core_cases": []}, {**original, "required_core_cases": [original["required_native_cases"][0]]}, {**original, "core_manifest": "experiments/vault-prototype/Cargo.toml"}]:
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    verifier.load_contract(path)

    def test_core_dependency_boundary_excludes_adapters_bindings_and_consumer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            prefix = '[package]\nname="fogvault"\n[features]\ndefault=[]\n'
            path.write_text(prefix + '[dependencies]\ngetrandom="=0.4.3"\n')
            self.assertTrue(verifier.check_core_boundary(path)["adapter_and_consumer_dependencies_absent"])
            for dependency in ['[dependencies]\ndatafog-core="=0.5.0-beta.3"\n', '[target.\'cfg(unix)\'.dependencies]\nrusqlite="=0.40.2"\n', '[dependencies]\naliased={package="wasm-bindgen",version="=0.2.127"}\n', '[dev-dependencies]\ndatafog-core="=0.5.0-beta.3"\n']:
                path.write_text(prefix + dependency)
                with self.assertRaises(ValueError):
                    verifier.check_core_boundary(path)
            path.write_text(prefix.replace("default=[]", 'default=["experimental-codecs"]'))
            with self.assertRaises(ValueError):
                verifier.check_core_boundary(path)

    def test_all_report_identities_include_moved_core_and_detect_core_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            core = Path(directory)
            (core / "src").mkdir()
            (core / "tests").mkdir()
            inputs = ["Cargo.toml", "Cargo.lock", "src/lifecycle.rs", "src/kdf.rs", "src/lifecycle/credentials.rs", "tests/lifecycle.rs", "tests/credentials.rs"]
            for relative in inputs:
                (core / relative).parent.mkdir(exist_ok=True, parents=True)
                (core / relative).write_text("proof input\n")
            required = {str((core / relative).relative_to(ROOT)) for relative in inputs}
            manifest = ROOT / "experiments/vault-prototype/Cargo.toml"
            with mock.patch.object(verifier, "CORE", core):
                self.assertTrue(required <= verifier.portable_identity_paths(manifest))
                self.assertTrue(required <= verifier.verification_source_identity(manifest).keys())
                identities = [verifier.growth_source_identity(manifest)]
            for filename in ["measure-index.py", "measure-resources.py", "verify-browser.py", "verify-mobile.py"]:
                spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), ROOT / "scripts" / filename)
                runner = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(runner)
                with mock.patch.object(runner, "CORE", core):
                    identities.append(runner.source_identity())
            for identity in identities:
                self.assertTrue(required <= identity.keys())
                verifier.validate_feasibility_identity({"source_identity": identity}, required)
            for relative in ["src/lifecycle.rs", "src/kdf.rs", "src/lifecycle/credentials.rs", "tests/lifecycle.rs", "tests/credentials.rs"]:
                (core / relative).write_text("changed input\n")
                for identity in identities:
                    with self.assertRaises(ValueError):
                        verifier.validate_feasibility_identity({"source_identity": identity}, required)
                (core / relative).write_text("proof input\n")

    def test_missing_duplicate_not_run_and_unavailable_checks_never_complete(self):
        first = {"id": "native", "required": True, "executed": True, "status": "pass"}
        second = {"id": "wasm", "required": True, "executed": True, "status": "pass"}
        self.assertTrue(verifier.complete_results([first, second], ["native", "wasm"]))
        self.assertFalse(verifier.complete_results([first], ["native", "wasm"]))
        self.assertFalse(verifier.complete_results([first, first], ["native", "wasm"]))
        for changed in [{**second, "status": "not-run"}, {**second, "status": "unavailable"}, {**second, "executed": False}, {**second, "required": False}]:
            self.assertFalse(verifier.complete_results([first, changed], ["native", "wasm"]))

    def test_nonzero_command_is_failure_and_retains_its_log(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = verifier.Verifier(Path(directory), {}, True)
            result = runner.command("failure", [sys.executable, "-c", "print('failure evidence'); raise SystemExit(7)"])
            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["exit_code"], 7)
            self.assertIn("failure evidence", Path(result["log"]).read_text())

    def test_unavailable_tool_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = verifier.Verifier(Path(directory), {}, True)
            with mock.patch.object(verifier.shutil, "which", return_value=None):
                result = runner.command("missing", ["missing-required-tool"])
            self.assertEqual(result["status"], "unavailable")
            self.assertFalse(result["executed"])

    def test_missing_compilation_target_is_unavailable_after_successful_discovery(self):
        def missing_target(_):
            raise verifier.Unavailable("target not installed")

        with tempfile.TemporaryDirectory() as directory:
            runner = verifier.Verifier(Path(directory), {}, True)
            result = runner.command("target", [sys.executable, "-c", "print('host-only-target')"], missing_target)
            self.assertEqual(result["status"], "unavailable")
            self.assertTrue(result["executed"])

    def test_consumer_hash_and_role_are_checked(self):
        contract = {"consumer": {"package": "datafog-core", "version": "0.5.0-beta.3", "checksum": "reviewed-checksum"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text('[dev-dependencies]\ndatafog-core = { version = "=0.5.0-beta.3" }\n')
            lock = Path(directory) / "Cargo.lock"
            lock.write_text('[[package]]\nname="datafog-core"\nversion="0.5.0-beta.3"\nsource="registry+https://example.test"\nchecksum="reviewed-checksum"\n')
            self.assertEqual(verifier.check_consumer_pin(contract, path)["version"], "0.5.0-beta.3")
            lock.write_text(lock.read_text().replace("reviewed-checksum", "wrong-checksum"))
            with self.assertRaises(ValueError):
                verifier.check_consumer_pin(contract, path)
            path.write_text('[dependencies]\ndatafog-core = "0.5.0-beta.3"\n')
            with self.assertRaises(ValueError):
                verifier.check_consumer_pin(contract, path)
            path.write_text('[target.\'cfg(unix)\'.dependencies]\ndatafog-core = "0.5.0-beta.3"\n')
            with self.assertRaises(ValueError):
                verifier.check_consumer_pin(contract, path)

    def test_fixture_hex_is_canonical_and_case_ids_are_unique(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "vectors.json"
            fixture = Path(directory) / "fixture.bin"
            fixture.write_bytes(bytes.fromhex("00ff"))
            case = {"id": "fixture", "kind": "descriptor", "fixture": "fixture.bin", "bytes_hex": "00ff", "sha256_hex": verifier.sha256(fixture)}
            path.write_text(json.dumps({"schema": "fogvault-format-vectors/v1", "cases": [case]}))
            self.assertEqual(verifier.validate_format_vectors(path)["case_ids"], ["fixture"])
            for cases in [[case, case], [{**case, "bytes_hex": "00FF"}], [{**case, "bytes_hex": "0"}]]:
                path.write_text(json.dumps({"schema": "fogvault-format-vectors/v1", "cases": cases}))
                with self.assertRaises(ValueError):
                    verifier.validate_format_vectors(path)

    def growth_fixture(self):
        # This unit fixture supplies illustrative bounds, not product policy.
        contract = {"index_growth": {"key_bits": 128, "head_bytes": 128, "operations": {"lookup": {"nodes_read": 129, "nodes_written": 0}}}}
        metrics = {"nodes_read": 1, "nodes_written": 0, "node_bytes_read": 57, "node_bytes_written": 0, "max_path_depth": 0, "records_scanned": 0, "head_bytes": 128}
        report = {"schema": "fogvault-index-growth/v1", "key_bits": 128, "samples": [{"records": records, "operation": "lookup", "correctness": True, "metrics": dict(metrics)} for records in [1, 2]]}
        return report, contract

    def test_growth_enforces_work_evidence_not_latency(self):
        report, contract = self.growth_fixture()
        report["samples"][0]["elapsed_ns"] = 10**30
        self.assertEqual(verifier.validate_growth_report(report, contract)["record_populations"], [1, 2])
        for field, value in [("nodes_read", 130), ("records_scanned", 1), ("max_path_depth", 129), ("head_bytes", 129)]:
            altered = json.loads(json.dumps(report))
            altered["samples"][0]["metrics"][field] = value
            with self.assertRaises(ValueError):
                verifier.validate_growth_report(altered, contract)

    def test_growth_rejects_missing_unexecuted_and_single_population_evidence(self):
        report, contract = self.growth_fixture()
        for altered in [{**report, "samples": []}, {**report, "samples": [report["samples"][0]]}, {**report, "samples": [{**sample, "correctness": False} for sample in report["samples"]]}]:
            with self.assertRaises(ValueError):
                verifier.validate_growth_report(altered, contract)
        report["samples"][0]["metrics"]["nodes_read"] = True
        with self.assertRaises(ValueError):
            verifier.validate_growth_report(report, contract)

    def test_every_population_requires_each_operation_and_full_scan_work(self):
        report, contract = self.growth_fixture()
        contract["index_growth"]["operations"]["audit"] = {"full_scan": True}
        for records in [1, 2]:
            nodes = 2 * records - 1
            metrics = {"nodes_read": nodes, "nodes_written": 0, "node_bytes_read": 57 * records + 82 * (records - 1), "node_bytes_written": 0, "max_path_depth": records - 1, "records_scanned": records, "head_bytes": 128}
            report["samples"].append({"records": records, "operation": "audit", "correctness": True, "metrics": metrics})
        verifier.validate_growth_report(report, contract)
        with self.assertRaises(ValueError):
            verifier.validate_growth_report({**report, "samples": report["samples"][:-1]}, contract)
        report["samples"][-1]["metrics"]["node_bytes_read"] += 1
        with self.assertRaises(ValueError):
            verifier.validate_growth_report(report, contract)

    def test_separate_growth_report_requires_current_source_identity(self):
        report, contract = self.growth_fixture()
        report["source_identity"] = {"reviewed/path": "reviewed-sha256"}
        contract["index_growth"]["record_operations"] = {}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "growth.json"
            path.write_text(json.dumps(report))
            # This test isolates provenance; record-growth semantics are tested
            # independently below and remain mandatory in the real validator.
            with mock.patch.object(verifier, "growth_source_identity", return_value=report["source_identity"]), mock.patch.object(verifier, "validate_record_growth", return_value={}):
                verifier.validate_growth_file(path, contract, Path("unused"))
            with mock.patch.object(verifier, "growth_source_identity", return_value={"reviewed/path": "changed-sha256"}):
                with self.assertRaises(ValueError):
                    verifier.validate_growth_file(path, contract, Path("unused"))

    def record_growth_fixture(self):
        settings = verifier.load_contract()["index_growth"]["record_operations"]
        populations = [1, 3]  # Empty-after-delete and partial-final-page boundaries.
        fields = ["full_audits", "head_bytes", "head_bytes_written", "index_nodes_deleted", "max_path_depth", "node_bytes_read", "node_bytes_written", "nodes_read", "nodes_written", "record_bytes_read", "record_bytes_written", "record_rows_read", "records_scanned"]

        def sample(records, operation, **work):
            metrics = dict.fromkeys(fields, 0)
            metrics.update(work)
            return {"records": records, "operation": operation, "correctness": True, "metrics": metrics,
                    "elapsed_ns": 1, "baseline_allocated_bytes": 0, "peak_allocated_bytes": 1, "peak_live_allocated_bytes": 1}

        report = {"schema": settings["schema"], "page_size": 2, "deletions": [], "enumerations": []}
        for records in populations:
            remaining = records - 1
            report["deletions"].append({
                "sample": sample(records, "delete", head_bytes=129, head_bytes_written=129, nodes_read=2 if records == 1 else 5,
                                 node_bytes_read=114 if records == 1 else 360, record_rows_read=1, record_bytes_read=464,
                                 index_nodes_deleted=1 if records == 1 else 2, max_path_depth=0 if records == 1 else 1),
                "remaining_records": remaining, "logical_nodes_before": 2 * records - 1,
                "logical_nodes_after": max(0, 2 * remaining - 1), "logical_node_bytes_after": 57 * remaining + 82 * max(0, remaining - 1),
                "physical_db_bytes_after": 1, "target_absence_verified": True, "remaining_inventory_audited": True,
                "unrelated_record_checks": int(records > 1), "unrelated_record_unchanged": True,
            })
            pages = (records + 1) // 2
            report["enumerations"].append({
                "sample": sample(records, "enumerate", head_bytes=129 * (pages + 1), nodes_read=2 * records - 1,
                                 node_bytes_read=57 * records + 82 * (records - 1), record_rows_read=records,
                                 records_scanned=records, record_bytes_read=464 * records, max_path_depth=0 if records == 1 else 2),
                "begin": sample(records, "begin_records", head_bytes=129), "page_size": 2, "page_count": pages,
                "last_page_records": 1, "records_returned_max": min(2, records), "nodes_read_per_page_max": 1 if records == 1 else 4,
                "node_bytes_read_per_page_max": 57 if records == 1 else 278, "record_rows_per_page_max": min(2, records),
                "record_bytes_per_page_max": 464 * min(2, records), "head_bytes_per_page": 129,
                "frontier_nodes_max": 1 if records == 1 else 3, "retained_proofs_max": min(2, records),
                "peak_allocated_bytes_per_page_max": 1, "peak_live_allocated_bytes_per_page_max": 1,
                "complete_only_final_page": True, "member_identity_revision_digest_matches": True, "whole_inventory_materialized": False,
            })
        return report, settings, populations

    def test_record_growth_requires_exact_population_and_operation_evidence(self):
        report, settings, populations = self.record_growth_fixture()
        self.assertEqual(verifier.validate_record_growth(report, settings, populations)["enumerations"], 2)
        changes = [lambda r: r.pop("deletions"), lambda r: r.pop("enumerations"),
                   lambda r: r["deletions"].pop(), lambda r: r["enumerations"].pop(),
                   lambda r: r["deletions"].append(r["deletions"][0]), lambda r: r["enumerations"].append(r["enumerations"][0]),
                   lambda r: r["deletions"][0]["sample"].update(operation="save"),
                   lambda r: r["enumerations"][0]["sample"].update(correctness=False),
                   lambda r: r["enumerations"][0]["begin"].update(operation="unlock")]
        for index, change in enumerate(changes):
            with self.subTest(mutation=index):
                altered = json.loads(json.dumps(report)); change(altered)
                with self.assertRaises(ValueError):
                    verifier.validate_record_growth(altered, settings, populations)

    def test_record_growth_requires_complete_scan_cost_including_cursor_and_heads(self):
        report, settings, populations = self.record_growth_fixture()
        for field in ["nodes_read", "node_bytes_read", "record_rows_read", "records_scanned", "record_bytes_read", "head_bytes", "nodes_written", "node_bytes_written", "record_bytes_written", "head_bytes_written", "index_nodes_deleted", "full_audits"]:
            with self.subTest(metric=field):
                altered = json.loads(json.dumps(report))
                altered["enumerations"][1]["sample"]["metrics"][field] += 1
                with self.assertRaises(ValueError):
                    verifier.validate_record_growth(altered, settings, populations)
        for change in [lambda r: r["enumerations"][1].update(page_count=1),
                       lambda r: r["enumerations"][1].update(last_page_records=2),
                       lambda r: r["enumerations"][1]["begin"]["metrics"].update(nodes_read=1, node_bytes_read=57),
                       lambda r: r["enumerations"][1]["begin"]["metrics"].update(head_bytes=258)]:
            altered = json.loads(json.dumps(report)); change(altered)
            with self.assertRaises(ValueError):
                verifier.validate_record_growth(altered, settings, populations)

    def test_record_growth_rejects_unbounded_pages_and_deletion_inventory_work(self):
        report, settings, populations = self.record_growth_fixture()
        for field, value in [("nodes_read_per_page_max", 259), ("node_bytes_read_per_page_max", 82 * 258 + 1),
                             ("frontier_nodes_max", 130), ("retained_proofs_max", 3), ("records_returned_max", 3),
                             ("record_rows_per_page_max", 3), ("record_bytes_per_page_max", 2 * 464 + 1), ("head_bytes_per_page", 258)]:
            with self.subTest(page_field=field):
                altered = json.loads(json.dumps(report)); altered["enumerations"][1][field] = value
                with self.assertRaises(ValueError):
                    verifier.validate_record_growth(altered, settings, populations)
        for field, value in [("nodes_read", 260), ("nodes_written", 128), ("index_nodes_deleted", 130),
                             ("records_scanned", 1), ("full_audits", 1), ("record_bytes_written", 464),
                             ("record_rows_read", 2), ("record_bytes_read", 2 * 464), ("head_bytes_written", 0)]:
            with self.subTest(delete_field=field):
                altered = json.loads(json.dumps(report)); altered["deletions"][1]["sample"]["metrics"][field] = value
                with self.assertRaises(ValueError):
                    verifier.validate_record_growth(altered, settings, populations)
        altered = json.loads(json.dumps(report)); altered["deletions"][1]["logical_nodes_after"] += 1
        with self.assertRaises(ValueError):
            verifier.validate_record_growth(altered, settings, populations)

    def test_record_growth_requires_finality_and_identity_without_timing_budget(self):
        report, settings, populations = self.record_growth_fixture()
        for section in ["deletions", "enumerations"]:
            for row in report[section]:
                row["sample"]["elapsed_ns"] = 10**30
                row["sample"]["peak_allocated_bytes"] = 10**30
                row["sample"]["peak_live_allocated_bytes"] = 10**30
        verifier.validate_record_growth(report, settings, populations)
        for field, value in [("complete_only_final_page", False), ("member_identity_revision_digest_matches", False),
                             ("whole_inventory_materialized", True)]:
            altered = json.loads(json.dumps(report)); altered["enumerations"][1][field] = value
            with self.assertRaises(ValueError):
                verifier.validate_record_growth(altered, settings, populations)
        for field in ["target_absence_verified", "remaining_inventory_audited", "unrelated_record_unchanged"]:
            altered = json.loads(json.dumps(report)); altered["deletions"][1][field] = False
            with self.assertRaises(ValueError):
                verifier.validate_record_growth(altered, settings, populations)

    def test_sources_must_remain_stable_while_checks_execute(self):
        self.assertTrue(verifier.require_stable_sources({"code": "a"}, {"code": "a"})["unchanged_during_run"])
        for after in [{}, {"code": "b"}, {"code": "a", "new": "c"}]:
            with self.assertRaises(ValueError):
                verifier.require_stable_sources({"code": "a"}, after)


class HostVerifierChecks(unittest.TestCase):
    def contract(self):
        return json.loads((ROOT / "conformance/host-feasibility-contract.json").read_text())

    def resource_fixture(self):
        # Structural unit data; these values do not assert executed measurements.
        contract = self.contract()
        contract["resources"]["repetitions"] = 1
        contract["resources"]["payload_bytes"] = [0]
        settings = contract["resources"]
        runs = []
        for kind in ("kdf", "payload"):
            samples = []
            operations = settings["kdf_operations"] if kind == "kdf" else settings["payload_operations"]
            for operation in operations:
                peak = 65536 * 1024 if operation == "kdf" else 0
                metrics = {"head_bytes": 0 if operation in {"create", "payload_rejected"} else 129, "records_scanned": 1 if operation in {"unlock", "audit"} else 0, "record_bytes_written": 208 if operation in {"save", "update"} else 0, "record_bytes_read": 208 if operation in {"read", "audit"} else 0, "nodes_read": 1 if operation in {"read", "unlock", "audit"} else 0}
                samples.append({"operation": operation, "case_id": f"payload/0/{operation}" if kind == "payload" else f"kdf/{operation}", "repetition": 0, "correctness": True, "concurrency": 2 if operation == "kdf_concurrent" else 1, "payload_bytes": 0, "input_payload_bytes": 1 if operation == "payload_rejected" else 0, "elapsed_ns": 0, "baseline_allocated_bytes": 0, "peak_allocated_bytes": peak, "peak_live_allocated_bytes": peak, "ending_allocated_bytes": 0, "metrics": metrics})
            runs.append({"kind": kind, "payload_bytes": 0, "release_profile": True, "kdf": settings["kdf"], "process_memory": {"status": "measured", "peak_rss_bytes": 1}, "metadata_bytes": 32, "records": 1, "envelope_bytes": 208, "samples": samples})
        source = ROOT / "research/consumer/datafog-core-0.5.0-beta.3/published-source/src/workspace.rs"
        report = {"schema": "fogvault-resource-budgets/v1", "repetitions": 1, "payload_populations": [0], "consumer_limit": {"bytes": 16777216, "source_sha256": verifier.sha256(source), "version": "0.5.0-beta.3"}, "runs": runs, "samples": [sample for run in runs for sample in run["samples"]]}
        return report, contract

    def test_host_case_omission_unavailable_and_duplicates_fail(self):
        valid = [{"id": "runtime", "status": "pass", "executed": True}]
        verifier.validate_status_cases(valid, ["runtime"])
        for cases in [[], valid + valid, [{**valid[0], "status": "unavailable"}], [{**valid[0], "executed": False}]]:
            with self.assertRaises(ValueError):
                verifier.validate_status_cases(cases, ["runtime"])

    def test_resource_workload_and_admission_evidence_are_required(self):
        report, contract = self.resource_fixture()
        with mock.patch.object(verifier, "validate_feasibility_identity", return_value={}):
            verifier.validate_resource_report(report, contract, ROOT / "experiments/vault-prototype/Cargo.toml")
            for edit in [lambda r: r["runs"].pop(), lambda r: r["runs"][0]["samples"].pop(), lambda r: r["runs"][1]["samples"][-1].update(input_payload_bytes=0), lambda r: r["runs"][0]["samples"][-1].update(peak_allocated_bytes=1, peak_live_allocated_bytes=1), lambda r: r["runs"][0]["process_memory"].update(status="unavailable")]:
                altered = json.loads(json.dumps(report))
                edit(altered)
                with self.assertRaises(ValueError):
                    verifier.validate_resource_report(altered, contract, ROOT / "experiments/vault-prototype/Cargo.toml")

    def test_resource_timing_is_an_observation_not_a_latency_gate(self):
        report, contract = self.resource_fixture()
        # Preserve the flattened/structured equality while changing an observation.
        report["runs"][0]["samples"][0]["elapsed_ns"] = 10**30
        with mock.patch.object(verifier, "validate_feasibility_identity", return_value={}):
            verifier.validate_resource_report(report, contract, ROOT / "experiments/vault-prototype/Cargo.toml")

    def test_host_source_identity_must_match_and_cannot_escape_workspace(self):
        relative = "experiments/vault-prototype/Cargo.toml"
        identity = {relative: verifier.sha256(ROOT / relative)}
        verifier.validate_feasibility_identity({"source_identity": identity}, {relative})
        for changed in [{}, {relative: "0" * 64}, {**identity, "../outside": "0" * 64}, {str(ROOT / relative): identity[relative]}]:
            with self.assertRaises(ValueError):
                verifier.validate_feasibility_identity({"source_identity": changed}, {relative})

    def browser_growth(self, profile="blob"):
        # Structural unit fixture, not measured timings or production capacities.
        return [{"records": records, "correctness": True, "nodes_read": 2 * records - 1, "records_checked": records, "node_bytes": 139 * records - 82, "max_stack_nodes": 1, "max_cached_nodes": 1, "max_record_rows": 1, "get_all_calls": 0, "transactions": 1, "header_transactions": 1, "head_bytes": 129, "record_bodies_materialized": records if profile == "arraybuffer" else 0, "memory_bytes": 65536 * 1024, "elapsed_ms": 0} for records in self.contract()["browser"]["streaming_startup"]["record_populations"]]

    def browser_record_pages(self, profile="blob"):
        settings = self.contract()["browser"]["record_operations"]
        return {**{field: settings[field] for field in ("page_size", "source_records", "source_nodes", "page_lengths")}, "pages": [{"nodes_read": nodes, "node_bytes": size, "records_checked": length, "max_stack_nodes": 3, "transactions": 1, "get_all_calls": 0, "max_cached_nodes": 1, "max_record_rows": 1, "retained_page_records": length, "record_bodies_materialized": length, "arraybuffer_row_clones": length if profile == "arraybuffer" else 0} for length, nodes, size in zip([2, 2, 1], [4, 4, 1], [278, 278, 57])]}

    def test_browser_pages_require_each_snapshot_cost_and_complete_membership(self):
        settings = self.contract()["browser"]["record_operations"]
        for profile in ("blob", "arraybuffer"):
            good = self.browser_record_pages(profile)
            verifier.validate_browser_records({settings["page_case"]: good}, settings, profile)
            for edit in [lambda r: r["pages"].pop(), lambda r: r["page_lengths"].reverse(), lambda r: r["pages"][0].update(nodes_read=3), lambda r: r["pages"][0].update(record_bodies_materialized=0), lambda r: r["pages"][0].update(arraybuffer_row_clones=9), lambda r: r["pages"][0].update(transactions=2), lambda r: r["pages"][0].update(max_cached_nodes=2), lambda r: r["pages"][0].update(max_stack_nodes=130), lambda r: r["pages"][0].update(get_all_calls=1), lambda r: r["pages"][0].update(records_checked=True)]:
                changed = json.loads(json.dumps(good)); edit(changed)
                with self.assertRaises(ValueError):
                    verifier.validate_browser_records({settings["page_case"]: changed}, settings, profile)

    def test_browser_growth_requires_streaming_and_snapshot_work_not_latency(self):
        settings = self.contract()["browser"]["streaming_startup"]
        growth = self.browser_growth()
        growth[-1]["elapsed_ms"] = 10**30
        verifier.validate_browser_growth(growth, settings, "blob")
        for field, value in [("max_cached_nodes", 2), ("max_record_rows", 2), ("get_all_calls", 1), ("transactions", 2), ("header_transactions", 0), ("nodes_read", 0), ("records_checked", 0), ("max_stack_nodes", 130), ("record_bodies_materialized", 1)]:
            changed = json.loads(json.dumps(growth))
            changed[-1][field] = value
            with self.assertRaises(ValueError):
                verifier.validate_browser_growth(changed, settings, "blob")
        with self.assertRaises(ValueError):
            verifier.validate_browser_growth(growth[:-1], settings, "blob")
        verifier.validate_browser_growth(self.browser_growth("arraybuffer"), settings, "arraybuffer")

    def test_browser_engine_cases_payload_and_storage_profile_cannot_silently_change(self):
        contract = self.contract()
        cases = [{"id": name, "status": "pass", "executed": True} for name in contract["browser"]["cases"]]
        by_id = {case["id"]: case for case in cases}
        for case_id, fields in contract["browser"]["required_evidence"].items():
            by_id[case_id].update({field: True for field in fields})
        for case_id, fields in contract["browser"].get("required_counts", {}).items():
            by_id[case_id].update(fields)
        by_id["worker_kdf_keeps_main_event_loop_running"]["timer_callbacks"] = 1
        by_id["core_16mib_opaque_payload_roundtrip"]["payload_bytes"] = 16777216
        by_id["u64_revision_crossing_preserves_all_bits"].update(values=["9007199254740993", "9223372036854775807"], number_input_rejected=True)
        by_id["oversized_input_rejected_before_wasm_copy"].update(head_unchanged=True, wasm_extent_unchanged=True)
        vectors = json.loads((ROOT / "conformance/password-vectors.json").read_text())
        password_settings = contract["browser"]["password_vector_cases"]
        by_id[password_settings["text_case"]].update(vectors=[{"id": row["id"], "utf8_hex": row["utf8_hex"]} for row in vectors["text"]], invalid_utf16_ids=[row["id"] for row in vectors["invalid_utf16"]])
        by_id[password_settings["lifecycle_case"]].update({field + "_id": identity for field, identity in vectors["lifecycle"].items()})
        by_id[password_settings["byte_boundary_case"]].update(shared_array_buffer_available=False, shared_binding_rejection_executed=False, shared_worker_rejection_executed=False, shared_binding_rejections=0)
        engines = [{"name": name, "result": {"schema": "fogvault-browser-feasibility/v1", "pass": True, "scope": {"storage_profile": profile, "storage_schema_version": 2}, "growth": self.browser_growth(profile), "cases": json.loads(json.dumps(cases)), "samples": [{"elapsed_ms": 0, "memory_bytes": 65536 * 1024}], "environment": {"secure_context": True, "indexeddb": True, "webassembly": True, "worker": True, "user_agent": "structural unit fixture"}}} for name, profile in contract["browser"]["storage_profiles"].items()]
        for engine in engines:
            next(case for case in engine["result"]["cases"] if case["id"] == contract["browser"]["record_operations"]["page_case"]).update(self.browser_record_pages(contract["browser"]["storage_profiles"][engine["name"]]))
        report = {"schema": "fogvault-browser-feasibility/v1", "pass": True, "engines": engines}
        node = contract["browser"]["password_adapter_node"]
        report["password_adapter_node"] = {"schema": node["schema"], "scope": node["scope"], "pass": True, "executed": True, "node": "v25.8.2", "shared_array_buffer_available": True, "cases": [{"id": identity, "status": "pass", "executed": True} for identity in node["cases"]], "source_identity": {relative: verifier.sha256(ROOT / relative) for relative in node["source_files"]}}
        with mock.patch.object(verifier, "validate_feasibility_identity", return_value={}):
            verifier.validate_browser_report(report, contract, ROOT / "experiments/vault-prototype/Cargo.toml")
            for edit in [lambda r: r["engines"][0]["result"]["cases"][contract["browser"]["cases"].index("reopen_recovers_latest_receipt_and_superseded_receipts_reject")].update(postcommit_worker_loss_reconciled=False), lambda r: r["engines"].pop(), lambda r: r["engines"][0]["result"]["cases"].pop(), lambda r: r["engines"][1]["result"]["scope"].update(storage_profile="blob"), lambda r: r["engines"][0]["result"]["samples"][0].update(memory_bytes=-1), lambda r: r["engines"][0]["result"].update(**{"pass": False})]:
                altered = json.loads(json.dumps(report))
                edit(altered)
                with self.assertRaises(ValueError):
                    verifier.validate_browser_report(altered, contract, ROOT / "experiments/vault-prototype/Cargo.toml")

            for case_id, fields in contract["browser"].get("required_counts", {}).items():
                index = contract["browser"]["cases"].index(case_id)
                for field, count in fields.items():
                    for wrong in [None, True, count + 1]:
                        altered = json.loads(json.dumps(report))
                        altered["engines"][0]["result"]["cases"][index][field] = wrong
                        with self.assertRaises(ValueError):
                            verifier.validate_browser_report(altered, contract, ROOT / "experiments/vault-prototype/Cargo.toml")
            credential_cases = [case_id for case_id in contract["browser"]["cases"] if case_id.startswith(("password_change_", "kdf_upgrade_", "credential_"))]
            for case_id in credential_cases:
                index = contract["browser"]["cases"].index(case_id)
                altered = json.loads(json.dumps(report))
                altered["engines"][0]["result"]["cases"].pop(index)
                with self.assertRaises(ValueError):
                    verifier.validate_browser_report(altered, contract, ROOT / "experiments/vault-prototype/Cargo.toml")
                altered = json.loads(json.dumps(report))
                for field in contract["browser"]["required_evidence"][case_id]:
                    altered = json.loads(json.dumps(report))
                    altered["engines"][0]["result"]["cases"][index][field] = False
                    with self.assertRaises(ValueError):
                        verifier.validate_browser_report(altered, contract, ROOT / "experiments/vault-prototype/Cargo.toml")

    def test_mobile_unavailable_runtime_is_not_compile_success(self):
        report = {"schema": "fogvault-mobile-feasibility/v1", "pass": True, "checks": [{"id": name, "status": "pass", "executed": True} for name in self.contract()["mobile"]["checks"]], "targets": [{"id": name, "status": "pass", "executed": True, "cases": [{"id": name, "status": "pass", "executed": True} for name in self.contract()["mobile"]["runtime_cases"]]} for name in self.contract()["mobile"]["targets"]]}
        with mock.patch.object(verifier, "validate_feasibility_identity", return_value={}), mock.patch.object(verifier, "validate_mobile_passwords", return_value={}):
            verifier.validate_mobile_report(report, self.contract(), ROOT / "experiments/vault-prototype/Cargo.toml")
            report["targets"][1]["status"] = "unavailable"
            with self.assertRaises(ValueError):
                verifier.validate_mobile_report(report, self.contract(), ROOT / "experiments/vault-prototype/Cargo.toml")
            report["targets"][1]["status"] = "pass"
            report["targets"][1]["cases"].pop()
            with self.assertRaises(ValueError):
                verifier.validate_mobile_report(report, self.contract(), ROOT / "experiments/vault-prototype/Cargo.toml")


if __name__ == "__main__":
    unittest.main()
