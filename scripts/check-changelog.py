#!/usr/bin/env python3
"""Validate a whole committed PR against its actual target branch."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = {"Added", "Changed", "Fixed", "Deprecated", "Removed", "Security"}
SHA = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?\Z")


class Invalid(ValueError):
    """The requested candidate or PR metadata cannot prove the policy."""


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                            text=True, encoding="utf-8")
    if result.returncode:
        raise Invalid("Git could not resolve the requested candidate; fetch the actual base and head commits.")
    return result.stdout


def commit(ref: str) -> str:
    if not isinstance(ref, str) or not ref.strip() or "\x00" in ref:
        raise Invalid("A nonempty base and head ref are required.")
    return git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}").strip()


def canonical(text: str) -> str:
    return " ".join(text.split())


def visible_lines(text: str):
    """Ignore code and comments before interpreting the simple changelog format."""
    fence: tuple[str, int] | None = None
    comment = False
    for line in text.splitlines():
        if fence is not None:
            character, width = fence
            if re.fullmatch(r" {0,3}" + re.escape(character) + "{" + str(width) + r",}[ \t]*", line):
                fence = None
            continue
        # Indented code cannot start a comment that hides later visible text.
        if not comment and line.expandtabs(4).startswith("    "):
            continue
        visible = ""
        remainder = line
        while remainder:
            if comment:
                end = remainder.find("-->")
                if end < 0:
                    remainder = ""
                else:
                    comment = False
                    remainder = remainder[end + 3:]
            else:
                start = remainder.find("<!--")
                if start < 0:
                    visible += remainder
                    remainder = ""
                else:
                    visible += remainder[:start]
                    comment = True
                    remainder = remainder[start + 4:]
        if visible.expandtabs(4).startswith("    "):
            continue
        # A fence may be the content of an otherwise empty list item.
        opening = re.match(r"^ {0,3}(?:[-*+]\s+)?(`{3,}|~{3,})(.*)$", visible)
        if opening and not (opening.group(1)[0] == "`" and "`" in opening.group(2)):
            delimiter = opening.group(1)
            fence = (delimiter[0], len(delimiter))
            continue
        yield visible


def bullets(text: str, *, unreleased: bool) -> set[str]:
    """Read real bullets; headings/blank/whitespace-only edits cannot qualify."""
    entries: set[str] = set()
    in_unreleased = False
    category: str | None = None
    headings = 0
    for line in visible_lines(text):
        if re.fullmatch(r"##\s+\[Unreleased\]\s*", line):
            headings += 1
            in_unreleased, category = True, None
            continue
        if line.startswith("## "):
            in_unreleased, category = False, None
            continue
        if line.startswith("### "):
            category = line[4:].strip()
            continue
        match = re.match(r"^ {0,3}[-*+]\s+(\S.*)$", line)
        if not match or (unreleased and (not in_unreleased or category not in CATEGORIES)):
            continue
        payload = canonical(match.group(1))
        if any(character.isalnum() for character in payload):
            entries.add(payload)
    if unreleased and headings != 1:
        raise Invalid("CHANGELOG.md must contain exactly one ## [Unreleased] heading.")
    return entries


def file_at(revision: str, name: str) -> str:
    result = subprocess.run(["git", "show", revision + ":" + name], cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        # A missing baseline file is normal at the policy adoption point.
        if not git("ls-tree", "--name-only", revision, "--", name).strip():
            return ""
        raise Invalid("Could not read the changelog from the requested Git object.")
    return result.stdout


def metadata(path: Path | None, base: str, head: str) -> dict:
    if path is None:
        return {"available": False, "no_changelog_label": False,
                "exemption_reason_present": False, "explicit_exemption": False}
    try:
        event = json.loads(path.read_text(encoding="utf-8"))
        pr = event["pull_request"]
        if not isinstance(event, dict) or not isinstance(pr, dict):
            raise Invalid("Event must contain a pull_request object.")
        number = pr["number"]
        if type(number) is not int or number <= 0:
            raise Invalid("PR number must be a positive integer.")
        for name in ("base", "head"):
            candidate = pr[name]
            if (not isinstance(candidate, dict) or not isinstance(candidate["ref"], str)
                    or not candidate["ref"].strip() or not isinstance(candidate["sha"], str)
                    or SHA.fullmatch(candidate["sha"]) is None):
                raise Invalid("PR base/head refs and full commit SHAs are required.")
        if pr["base"]["sha"].lower() != base or pr["head"]["sha"].lower() != head:
            raise Invalid("Checked base/head differ from PR metadata; fetch and check the actual PR target and head.")
        body = pr["body"]
        labels = pr["labels"]
        if body is not None and not isinstance(body, str):
            raise Invalid("PR body must be text or null.")
        if not isinstance(labels, list) or any(
            not isinstance(label, dict) or not isinstance(label.get("name"), str)
            or not label["name"].strip() for label in labels
        ):
            raise Invalid("PR labels must be objects with nonempty name fields.")
        no_changelog = any(label["name"] == "no-changelog" for label in labels)
        prefix = "Changelog exemption:"
        reason_present = any(line.startswith(prefix) and bool(line[len(prefix):].strip())
                             for line in (body or "").splitlines())
        return {"available": True, "pr_number": number, "base_ref": pr["base"]["ref"],
                "head_ref": pr["head"]["ref"], "no_changelog_label": no_changelog,
                "exemption_reason_present": reason_present,
                "explicit_exemption": no_changelog and reason_present}
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise Invalid("Malformed or unreadable PR event; supply the complete GitHub pull_request event.") from error


def evaluate(base_ref: str, head_ref: str, event: Path | None) -> dict:
    base, head = commit(base_ref), commit(head_ref)
    context = metadata(event, base, head)
    merge_base = git("merge-base", base, head).strip()
    changes = git("diff", "--name-only", merge_base, head, "--").splitlines()
    if not changes:
        raise Invalid("No committed PR changes exist against this target; commit the candidate before checking it.")
    before, after = file_at(merge_base, "CHANGELOG.md"), file_at(head, "CHANGELOG.md")
    new_entries: set[str] = set()
    if after:
        try:
            new_entries = bullets(after, unreleased=True) - bullets(before, unreleased=False)
        except Invalid:
            if not context["explicit_exemption"]:
                raise
    if not new_entries and not context["explicit_exemption"]:
        raise Invalid("Add a meaningful new bullet under ## [Unreleased], or supply both no-changelog and a nonempty Changelog exemption: reason.")
    return {"base_commit": base, "head_commit": head, "merge_base": merge_base,
            "changed_files": len(changes), "metadata": context,
            "result": "entry" if new_entries else "exemption",
            "new_entry_count": len(new_entries),
            "changelog_sha256": hashlib.sha256(after.encode()).hexdigest() if after else None,
            "working_tree_dirty": bool(git("status", "--porcelain")),
            "scope": "committed whole-PR diff; uncommitted working files are not proof"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="actual PR target ref or full commit")
    parser.add_argument("--head", default="HEAD", help="PR head; defaults to committed HEAD")
    parser.add_argument("--event", type=Path, help="GitHub pull_request event JSON, including labels/body")
    parser.add_argument("--output", type=Path, help="optional structured evidence file")
    args = parser.parse_args()
    report = {"schema": "fogvault-changelog-policy/v1", "pass": False,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "metadata_available": args.event is not None}
    try:
        report.update(evaluate(args.base, args.head, args.event))
        report["pass"] = True
    except (Invalid, OSError, UnicodeError) as error:
        report["error"] = str(error)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not args.event:
        print("PR metadata unavailable: entry checked; label/body exemption cannot be established locally.")
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
