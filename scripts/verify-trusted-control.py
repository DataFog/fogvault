#!/usr/bin/env python3
"""Execute in-process protected-control SQLite with actual encrypted vault state.

The explicit trusted namespace is outside the vault/staging attacker's authority.
A different filename is not itself such protection. No control-store rollback,
host compromise, physical-provider or power-loss qualification is claimed.
No Keychain, defaults, user items, search lists or external storage subprocesses.
"""
from __future__ import annotations

import argparse
import contextlib
import signal
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from source_inputs import maintained_sources

FIXTURE = "native::control::proof::native_control_process_fixture"
REGISTRATION = bytes([0x43]) * 16


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario",choices=["all","stale-writer"],default="all")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("refusing to overwrite an evidence report")
    output.parent.mkdir(parents=True, exist_ok=True)
    logs = Path(tempfile.mkdtemp(prefix="trusted-control-logs-", dir=output.parent))
    report = {"schema": "fogvault-trusted-local-control-proof/v1", "pass": False,
              "executed": True, "platform": platform.platform(), "profile": args.scenario, "cases": [],
              "limitations": ["In-process control SQLite in an explicitly independently protected host namespace; synthetic seed provider.",
                  "Attacker controls vault/staging files, not trusted OS/control namespace or host.",
                  "No control-store rollback resistance, hostile-host, physical iOS/Android, or power-loss qualification.",
                  "One-record full-content transition; ordinary point-operation scaling is not measured here.",
                  "Source observed after submission remains unresolved; no blind retry or KnownAbort claim."]}
    inputs = [*sorted((ROOT / "crates/fogvault/src").rglob("*.rs")),
              *sorted((ROOT / "experiments/vault-prototype/src").rglob("*.rs")),
              ROOT / "crates/fogvault/Cargo.toml", ROOT / "crates/fogvault/Cargo.lock",
              ROOT / "experiments/vault-prototype/Cargo.toml", ROOT / "experiments/vault-prototype/Cargo.lock",
              Path(__file__).resolve()]
    inputs.extend(maintained_sources(ROOT))
    report["source_identity"] = {p.relative_to(ROOT).as_posix(): digest(p) for p in inputs}
    children: list[subprocess.Popen] = []
    temporary_root: Path | None = None
    try:
        command = ["cargo", "test", "--offline", "--locked", "--manifest-path",
                   str(ROOT / "crates/fogvault-native/Cargo.toml"), "--features", "diagnostics", "--lib", "--no-run", "--message-format=json"]
        build = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        (logs / "build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError("control fixture build failed; see build.log")
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        executables = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact"
                       and a.get("target", {}).get("name") == "fogvault_native"
                       and a.get("profile", {}).get("test") and a.get("executable")]
        if len(executables) != 1:
            raise RuntimeError("exact native fixture executable missing or ambiguous")
        executable = Path(executables[0])
        report["artifact"] = {"path": str(executable), "sha256": digest(executable)}
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="fogvault-control-proof-")) as temporary:
            base = Path(temporary)
            temporary_root = base
            trusted = base / "trusted"
            trusted.mkdir(mode=0o700)
            def environment(case: str, mode: str, **extra: str) -> tuple[dict, Path]:
                work = base / "untrusted" / case
                work.mkdir(parents=True, exist_ok=True)
                control = trusted / case
                control.mkdir(exist_ok=True)
                env = os.environ.copy()
                env.update(FOGVAULT_CONTROL_MODE=mode, FOGVAULT_CONTROL_ROOT=str(work),
                           FOGVAULT_CONTROL_DATABASE=str(control / "control.sqlite"), FOGVAULT_CONTROL_LOCK=str(control / "control.lock"))
                if case=="stage":env["FOGVAULT_CONTROL_MAXIMUM"]="1"
                registration=control / "vault-id"
                if mode!="init" and registration.exists():
                    env["FOGVAULT_CONTROL_VAULT"]=registration.read_text().strip()
                env.update(extra)
                return env, work

            sequence = 0

            def run(case: str, mode: str, expected: str | None = None, failure: bool = False, **extra: str) -> str:
                nonlocal sequence
                env, _ = environment(case, mode, **extra)
                result = subprocess.run([str(executable), "--exact", FIXTURE, "--nocapture"],
                                        env=env, cwd=ROOT, capture_output=True, text=True, timeout=60)
                sequence += 1
                (logs / f"{sequence:02d}-{case}-{mode}.log").write_text(result.stdout + result.stderr)
                if failure:
                    if result.returncode == 0 or (expected and f"CONTROL_ERROR={expected}" not in result.stdout):
                        raise AssertionError(f"{case}/{mode}: expected rejection {expected}")
                elif result.returncode or (expected and f"CONTROL_RESULT={expected}" not in result.stdout):
                    raise AssertionError(f"{case}/{mode}: expected result {expected}; see logs")
                if mode=="init" and not failure:
                    match=re.search(r"CONTROL_VAULT=([a-f0-9]{32})",result.stdout)
                    if not match:raise AssertionError("trusted initial vault registration missing")
                    (trusted / case / "vault-id").write_text(match.group(1))
                return result.stdout

            def wait_for(path: Path, child: subprocess.Popen) -> None:
                deadline = time.monotonic() + 60  # Harness deadlock watchdog, not a product latency promise.
                while not path.exists():
                    if child.poll() is not None:
                        raise AssertionError("child exited before requested process-death boundary")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("child boundary watchdog expired")
                    time.sleep(0.02)

            def kill_at(case: str, point: str) -> Path:
                nonlocal sequence
                env, work = environment(case, "prepare", FOGVAULT_CONTROL_PAUSE=point)
                sequence += 1
                log = (logs / f"{sequence:02d}-{case}-kill-{point}.log").open("w")
                try:
                    child = subprocess.Popen([str(executable), "--exact", FIXTURE, "--nocapture"],
                                             env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    children.append(child)
                    wait_for(work / f"reached-{point}", child)
                    child.kill() # Parent-only death; storage has no child process.
                    child.wait(timeout=60)
                    if child.returncode != -9:
                        raise AssertionError("expected actual SIGKILL")
                finally:
                    log.close()
                return work

            def passed(name: str, **details: object) -> None:
                report["cases"].append({"id":name,"status":"pass","executed":True,"name": name, "pass": True, **details})
                print(name, flush=True)

            if args.scenario=="all":
                run("intent", "init", "registered")
                _, work = environment("intent", "status")
                source = (work / "vault.sqlite").read_bytes()
                kill_at("intent", "intent")
                run("intent", "status", "staging-source-no-target-activation")
                run("intent", "resume", failure=True, expected="Storage")
                assert not (work / "candidate.stage").exists()
                assert (work / "vault.sqlite").read_bytes() == source
                run("intent", "abandon", "abandoned-unsubmitted")
                run("intent", "status", "accepted-source-readable")
                passed("control_store_intent_survives_death_before_staging")

                run("stage", "init", "registered")
                _, work = environment("stage", "status")
                source = (work / "vault.sqlite").read_bytes()
                kill_at("stage", "stage")
                assert len((work / "candidate.checkpoint").read_bytes()) == 138
                assert (work / "vault.sqlite").read_bytes() == source
                run("stage", "status", "staging-source-no-target-activation")
                run("stage", "resume", "committed-and-control-confirmed")
                run("stage", "status", "accepted-target-readable")
                target = (work / "vault.sqlite").read_bytes()
                with sqlite3.connect(f"file:{work/'vault.sqlite'}?mode=ro",uri=True)as db:
                    assert db.execute("SELECT length(envelope) FROM records").fetchone()[0]==4096+64+176
                passed("control_store_c3_maximum_payload_metadata_envelope_is_readable",payload_bytes=4096,metadata_bytes=64,envelope_bytes=4336)
                assert target != source
                (work / "vault.sqlite").write_bytes(source)
                run("stage", "status", failure=True, expected="Conflict")
                (work / "vault.sqlite").write_bytes(target)
                run("stage", "status", "accepted-target-readable")
                passed("control_store_p3_full_transition_resumes_after_death_and_rejects_old_snapshot")

                run("submission", "init", "registered")
                _, work = environment("submission", "status")
                source = (work / "vault.sqlite").read_bytes()
                kill_at("submission", "submission")
                run("submission", "status", "still-unknown-no-activation")
                run("submission", "abandon", failure=True, expected="OutcomeUnknown")
                run("submission", "resume", failure=True, expected="OutcomeUnknown")
                assert (work / "vault.sqlite").read_bytes() == source
                checkpoint=(work/"candidate.checkpoint").read_bytes()
                (work/"candidate.checkpoint").unlink()
                run("submission","republish-exact",failure=True,expected="Storage")
                run("submission","status","still-unknown-no-activation")
                (work/"candidate.checkpoint").write_bytes(checkpoint)
                run("submission","republish-exact",failure=True,expected="ProviderUnavailable",FOGVAULT_CONTROL_PROVIDER_UNAVAILABLE="1")
                run("submission","status","still-unknown-no-activation")
                assert (work/"vault.sqlite").read_bytes()==source
                run("submission","republish-exact","committed-and-control-confirmed")
                run("submission","status","accepted-target-readable")
                passed("control_store_submission_before_commit_death_remains_unknown")

                for point in ["commit", "confirmed"]:
                    run(point, "init", "registered")
                    _,work=environment(point,"status")
                    source=(work/"vault.sqlite").read_bytes()
                    kill_at(point, point)
                    if point=="commit":
                        with sqlite3.connect(f"file:{work/'vault.sqlite'}?mode=ro",uri=True)as db:
                            target_header=db.execute("SELECT descriptor,head FROM vault_state").fetchone()
                        (work/"vault.sqlite").write_bytes(source)
                        run(point,"status","still-unknown-no-activation")
                        run(point,"republish-exact","committed-and-control-confirmed")
                        with sqlite3.connect(f"file:{work/'vault.sqlite'}?mode=ro",uri=True)as db:
                            assert db.execute("SELECT descriptor,head FROM vault_state").fetchone()==target_header
                    run(point, "status", "accepted-target-readable")
                    run(point, "status", "accepted-target-readable")
                    passed(f"control_store_death_after_{point}_reconciles_exact_target")

                run("tamper", "init", "registered")
                work = kill_at("tamper", "stage")
                source = (work / "vault.sqlite").read_bytes()
                checkpoint = (work / "candidate.checkpoint").read_bytes()
                stage = (work / "candidate.stage").read_bytes()
                altered = bytearray(checkpoint)
                altered[-1] ^= 1
                (work / "candidate.checkpoint").write_bytes(altered)
                run("tamper", "resume", failure=True)
                (work / "candidate.checkpoint").write_bytes(checkpoint)
                for line_kind in [b"D:", b"R:"]:
                    lines = stage.split(b"\n")
                    index = next(i for i, line in enumerate(lines) if line.startswith(line_kind))
                    lines[index] = lines[index][:-1] + (b"1" if lines[index][-1:] != b"1" else b"0")
                    (work / "candidate.stage").write_bytes(b"\n".join(lines))
                    run("tamper", "resume", failure=True)
                    assert (work / "vault.sqlite").read_bytes() == source
                (work / "candidate.stage").write_bytes(stage)
                run("tamper", "resume", "committed-and-control-confirmed")
                passed("control_store_checkpoint_target_and_body_substitution_refuse_without_writes")

                run("orphans","init","registered")
                work=kill_at("orphans","stage")
                lines=(work/"candidate.stage").read_bytes().split(b"\n")
                record=next(line for line in lines if line.startswith(b"R:")).split(b":")[-1]
                objects=lines[3:-1]+[b"N:"+b"ff"*32+b":00",b"R:"+b"fe"*16+b":1:"+record]
                lines=lines[:3]+sorted(line for line in objects if line.startswith(b"N:"))+sorted(line for line in objects if line.startswith(b"R:"))+[b"END"]
                (work/"candidate.stage").write_bytes(b"\n".join(lines))
                run("orphans","resume","committed-and-control-confirmed")
                run("orphans","status","accepted-target-readable")
                with sqlite3.connect(f"file:{work/'vault.sqlite'}?mode=ro",uri=True)as db:
                    assert db.execute("SELECT count(*) FROM records").fetchone()[0]==1
                    assert db.execute("SELECT count(*) FROM index_nodes").fetchone()[0]==1
                passed("control_store_publishes_only_authenticated_reachable_stage_objects")

                for case, complete in [("missing-source", False), ("missing-target", True)]:
                    run(case, "init", "registered")
                    if complete:
                        run(case, "prepare", "committed-and-control-confirmed")
                    _, work = environment(case, "status")
                    source = (work / "vault.sqlite").read_bytes()
                    with sqlite3.connect(trusted/case/"control.sqlite")as db:
                        db.execute("DELETE FROM control_state")
                        db.commit()
                    run(case, "status", failure=True, expected="Integrity")
                    assert (work / "vault.sqlite").read_bytes() == source
                passed("control_store_missing_required_receipt_or_anchor_never_self_registers")

                for case in ["foreign-a","foreign-b"]:
                    run(case,"init","registered")
                _,a=environment("foreign-a","status")
                _,b=environment("foreign-b","status")
                original=(a/"vault.sqlite").read_bytes()
                (a/"vault.sqlite").write_bytes((b/"vault.sqlite").read_bytes())
                run("foreign-a","status",failure=True,expected="Integrity")
                (a/"vault.sqlite").write_bytes(original)
                run("foreign-a","status","accepted-source-readable")
                passed("control_store_selector_uses_trusted_registration_not_presented_vault")

                for phase in ["before-commit","after-commit"]:
                    case=f"control-txn-{phase}"
                    run(case,"init","registered")
                    env,work=environment(case,"cas-inflight",FOGVAULT_CONTROL_SQL_PAUSE=phase,
                        FOGVAULT_CONTROL_SQL_MARKER=str(base/"untrusted"/case/"reached-control-txn"),FOGVAULT_CONTROL_CAS_ID="1")
                    before_vault=(work/"vault.sqlite").read_bytes()
                    with (logs/f"{case}-parent.log").open("w")as handle:
                        child=subprocess.Popen([str(executable),"--exact",FIXTURE,"--nocapture"],cwd=ROOT,env=env,
                            stdout=handle,stderr=subprocess.STDOUT,start_new_session=True)
                        children.append(child)
                        wait_for(work/"reached-control-txn",child)
                        child.kill() # Only the Rust caller PID, not a process group.
                        assert child.wait(timeout=60)==-9
                    if phase=="before-commit":
                        run(case,"pending","no-pending")
                        run(case,"cas-inflight","control-update-committed",FOGVAULT_CONTROL_CAS_ID="2")
                        run(case,"pending","pending-request-"+"02"*16)
                    else:
                        run(case,"pending","pending-request-"+"01"*16)
                    run(case,"abandon","abandoned-unsubmitted")
                    run(case,"status","accepted-source-readable")
                    assert (work/"vault.sqlite").read_bytes()==before_vault
                    passed(f"control_store_parent_only_death_{phase.replace('-', '_')}_has_no_late_storage_child_write")

                run("race", "init", "registered")
                racers = []
                handles = []
                try:
                    for value in [1, 2]:
                        env, work = environment("race", "race", FOGVAULT_CONTROL_RACE_ID=str(value))
                        handle = (logs / f"race-{value}.log").open("w+")
                        handles.append(handle)
                        child = subprocess.Popen([str(executable), "--exact", FIXTURE, "--nocapture"],
                                                 cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
                        children.append(child)
                        racers.append((child, value))
                    for child, value in racers:
                        wait_for(work / f"race-ready-{value}", child)
                    (work / "race-go").write_text("go")
                    for child, _ in racers:
                        if child.wait(timeout=60):
                            raise AssertionError("CAS race child failed")
                    texts = []
                    for handle in handles:
                        handle.seek(0)
                        texts.append(handle.read())
                    assert sum("CONTROL_RESULT=race-Stored" in text for text in texts) == 1
                    assert sum("CONTROL_RESULT=race-Conflict" in text for text in texts) == 1
                finally:
                    for handle in handles:
                        handle.close()
                run("race", "abandon", "abandoned-unsubmitted")
                run("race", "status", "accepted-source-readable")
                passed("control_store_compare_exchange_is_serialized_across_real_processes")
                run("race","bad-reset",failure=True,expected="Conflict")
                run("race","bad-registration",failure=True,expected="Integrity")
                run("race","status","accepted-source-readable")
                passed("control_store_rejects_revision_reset_and_registration_substitution")

            run("stale-writer","init","registered")
            env,work=environment("stale-writer","prepare",FOGVAULT_CONTROL_PAUSE="before-publication",FOGVAULT_CONTROL_RELEASE_ON_FILE="1")
            original=(work/"vault.sqlite").read_bytes()
            with (logs/"stale-prepared-writer.log").open("w")as handle:
                child=subprocess.Popen([str(executable),"--exact",FIXTURE,"--nocapture"],cwd=ROOT,env=env,
                    stdout=handle,stderr=subprocess.STDOUT,start_new_session=True)
                children.append(child)
                wait_for(work/"reached-before-publication",child)
                run("stale-writer","republish-exact","committed-and-control-confirmed")
                run("stale-writer","advance","accepted-later-C")
                latest=(work/"vault.sqlite").read_bytes()
                run("stale-writer","anchor","anchor-generation-3")
                (work/"vault.sqlite").write_bytes(original)
                presented=(work/"vault.sqlite").read_bytes()
                (work/"release-before-publication").write_text("release")
                if child.wait(timeout=60)==0:raise AssertionError("stale prepared writer unexpectedly succeeded")
            stale_text=(logs/"stale-prepared-writer.log").read_text()
            assert "CONTROL_ERROR=Conflict"in stale_text
            assert (work/"vault.sqlite").read_bytes()==presented
            run("stale-writer","anchor","anchor-generation-3")
            run("stale-writer","status",failure=True,expected="Conflict")
            (work/"vault.sqlite").write_bytes(latest)
            run("stale-writer","status","accepted-target-readable")
            passed("control_store_stale_prepared_writer_cannot_overwrite_after_completed_B_and_later_C")
            report["pass"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        for child in children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=60)
        if temporary_root is not None:
            shutil.rmtree(temporary_root, ignore_errors=True)
        cleanup = temporary_root is None or not temporary_root.exists()
        report["temporary_namespace_removed"]=cleanup
        report["external_control_storage_subprocesses"]=False
        report["keychain_operations"]=False
        report["sources_stable"] = all(p.is_file() and digest(p) == report["source_identity"][p.relative_to(ROOT).as_posix()] for p in inputs)
        report["executed_case_ids"]=[case["id"]for case in report["cases"]]
        report["pass"] = bool(report["pass"] and cleanup and report["sources_stable"])
        report["logs"] = {str(p): digest(p) for p in sorted(logs.iterdir()) if p.is_file()}
        output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"pass": report["pass"], "cases": len(report["cases"]), "report": str(output), "error": report.get("error")}))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
