"""Whole-PR changelog policy, exercised against disposable Git repositories."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_changelog", ROOT / "scripts/check-changelog.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
BASE = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- Existing behavior.\n\n## [0.0.0]\n\n### Added\n\n- Historical behavior.\n"


class ChangelogPolicy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fogvault-changelog-test-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Synthetic changelog test")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.repo / "CHANGELOG.md").write_text(BASE)
        self.save("baseline")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "-c", "change")
        self.patch = mock.patch.object(checker, "ROOT", self.repo)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def save(self, message):
        self.git("add", "--all")
        self.git("commit", "-m", message)

    def change(self, text=None):
        if text is not None:
            (self.repo / "CHANGELOG.md").write_text(text)
        (self.repo / "source.txt").write_text(self.git("rev-parse", "HEAD"))
        self.save("candidate")

    def entry(self):
        self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n- Refuses missing packaged Worker assets."))

    def event(self, *, labels=(), body=None, base=None, head=None, bot=False):
        value = {"pull_request": {"number": 1,
                 "base": {"ref": "main", "sha": base or self.base},
                 "head": {"ref": "change", "sha": head or self.git("rev-parse", "HEAD").strip()},
                 "labels": [{"name": label} for label in labels], "body": body,
                 "user": {"type": "Bot" if bot else "User"}}}
        path = self.repo / ".git/test-event.json"
        path.write_text(json.dumps(value))
        return path

    def check(self, event=None, base=None):
        return checker.evaluate(base or self.base, "HEAD", event)

    def test_meaningful_unreleased_entry_passes_without_pr_metadata(self):
        self.entry()
        result = self.check()
        self.assertEqual(result["result"], "entry")
        self.assertFalse(result["metadata"]["available"])
        self.assertEqual(result["new_entry_count"], 1)

    def test_first_policy_adoption_can_create_changelog(self):
        self.git("rm", "CHANGELOG.md")
        self.save("before adoption")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.change("# Changelog\n\n## [Unreleased]\n\n### Security\n\n- Prevents local credential files entering source archives.\n")
        self.assertEqual(self.check()["result"], "entry")

    def test_missing_entry_fails(self):
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_blank_or_punctuation_bullet_fails(self):
        for bullet in ["-   ", "- ..."]:
            with self.subTest(bullet=bullet):
                self.git("reset", "--hard", self.base)
                self.change(BASE.replace("### Fixed", "### Fixed\n\n" + bullet))
                with self.assertRaises(checker.Invalid):
                    self.check()

    def test_heading_only_edit_fails(self):
        self.change(BASE.replace("### Fixed", "### Fixed\n\n### Changed"))
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_historical_release_only_edit_fails(self):
        self.change(BASE + "\n- Another historical note.\n")
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_fenced_code_bullets_do_not_qualify(self):
        examples = ["```text\n- Hidden example.\n```",
                    "~~~text\n- Hidden example.\n~~~~",
                    "   ````text\n- Hidden example.\n   `````",
                    "- ```text\n  - Hidden example.\n  ```"]
        for example in examples:
            with self.subTest(example=example):
                self.git("reset", "--hard", self.base)
                self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n\n" + example))
                with self.assertRaises(checker.Invalid):
                    self.check()

    def test_fenced_headings_cannot_create_unreleased_section(self):
        self.change("# Changelog\n\n```markdown\n## [Unreleased]\n### Fixed\n- Hidden example.\n```\n")
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_indented_code_bullets_do_not_qualify(self):
        for indent in ["    ", "\t", " \t"]:
            with self.subTest(indent=indent):
                self.git("reset", "--hard", self.base)
                self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n\n" + indent + "- Hidden example."))
                with self.assertRaises(checker.Invalid):
                    self.check()

    def test_html_comment_bullets_and_headings_do_not_qualify(self):
        examples = ["<!--\n- Hidden example.\n-->",
                    "<!--\n## [Unreleased]\n### Added\n- Hidden example.\n-->",
                    "- <!-- Hidden example. -->", "<!-- - Hidden example. -->"]
        for example in examples:
            with self.subTest(example=example):
                self.git("reset", "--hard", self.base)
                self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n\n" + example))
                with self.assertRaises(checker.Invalid):
                    self.check()

    def test_visible_entry_alongside_code_and_comments_qualifies(self):
        example = ("```text\n<!-- An example, not a comment opener.\n- Hidden example.\n```\n"
                   "~~~text\n- Another hidden example.\n~~~\n"
                   "<!--\n## [Unreleased]\n- Hidden comment example.\n-->\n"
                   "- Refuses <!-- hidden editorial note --> malformed input.")
        self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n\n" + example))
        self.assertEqual(self.check()["new_entry_count"], 1)

    def test_inline_code_text_is_still_a_visible_entry(self):
        self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n- ```New observable behavior``` is available."))
        self.assertEqual(self.check()["new_entry_count"], 1)

    def test_old_code_example_does_not_hide_a_new_visible_entry(self):
        before = BASE.replace("- Existing behavior.", "- Existing behavior.\n\n```text\n- New observable behavior.\n```")
        self.change(before)
        self.base = self.git("rev-parse", "HEAD").strip()
        self.change(before.replace("- Existing behavior.", "- Existing behavior.\n- New observable behavior."))
        self.assertEqual(self.check()["new_entry_count"], 1)

    def test_whitespace_only_bullet_edit_fails(self):
        self.change(BASE.replace("- Existing behavior.", "- Existing    behavior.  "))
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_moving_an_existing_historical_entry_does_not_count(self):
        self.change(BASE.replace("- Existing behavior.", "- Existing behavior.\n- Historical behavior."))
        with self.assertRaises(checker.Invalid):
            self.check()

    def test_entry_in_earlier_pr_commit_covers_followup(self):
        self.entry()
        (self.repo / "followup.txt").write_text("synthetic followup")
        self.save("followup")
        self.assertEqual(self.check()["new_entry_count"], 1)

    def test_parent_pr_entry_does_not_cover_stacked_child(self):
        self.entry()
        parent = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "-c", "child")
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check(base=parent)

    def test_explicit_exemption_needs_both_label_and_reason(self):
        self.change()
        event = self.event(labels=["no-changelog"], body="Changelog exemption: Tests only; public behavior is unchanged.")
        self.assertEqual(self.check(event)["result"], "exemption")

    def test_label_only_does_not_exempt(self):
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check(self.event(labels=["no-changelog"]))

    def test_exemption_line_accepts_windows_newlines(self):
        self.change()
        event = self.event(labels=["no-changelog"], body="Internal cleanup.\r\nChangelog exemption: Test-only cleanup.\r\n")
        self.assertEqual(self.check(event)["result"], "exemption")

    def test_reason_only_does_not_exempt(self):
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check(self.event(body="Changelog exemption: Internal test maintenance."))

    def test_blank_reason_does_not_exempt(self):
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check(self.event(labels=["no-changelog"], body="Changelog exemption: \t  \n"))

    def test_bot_pr_obeys_same_entry_or_exemption_rules(self):
        self.change()
        with self.assertRaises(checker.Invalid):
            self.check(self.event(bot=True))
        self.assertEqual(self.check(self.event(bot=True, labels=["no-changelog"], body="Changelog exemption: Dependency test tooling only."))["result"], "exemption")

    def test_malformed_event_fails_even_with_valid_entry(self):
        self.entry()
        original = json.loads(self.event().read_text())
        mutations = [lambda d: d.clear(),
                     lambda d: d["pull_request"].update(number="1"),
                     lambda d: d["pull_request"].pop("base"),
                     lambda d: d["pull_request"]["head"].update(sha="HEAD"),
                     lambda d: d["pull_request"].update(body=[]),
                     lambda d: d["pull_request"].update(labels=["no-changelog"]),
                     lambda d: d["pull_request"].update(labels=[{"name": ""}])]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = json.loads(json.dumps(original))
                mutation(value)
                path = self.repo / ".git/malformed.json"
                path.write_text(json.dumps(value))
                with self.assertRaises(checker.Invalid):
                    self.check(path)

    def test_unreadable_or_non_json_event_fails(self):
        self.entry()
        for content in ["[", "null", "[]"]:
            path = self.repo / ".git/invalid.json"
            path.write_text(content)
            with self.assertRaises(checker.Invalid):
                self.check(path)
        with self.assertRaises(checker.Invalid):
            self.check(self.repo / ".git/missing.json")

    def test_wrong_target_branch_fails_instead_of_counting_parent_entry(self):
        self.entry()
        parent = self.git("rev-parse", "HEAD").strip()
        self.change()
        event = self.event(base=parent)
        with self.assertRaisesRegex(checker.Invalid, "actual PR target"):
            self.check(event, base=self.base)

    def test_mismatched_head_event_fails(self):
        self.entry()
        with self.assertRaisesRegex(checker.Invalid, "actual PR target"):
            self.check(self.event(head=self.base))

    def test_missing_base_ref_fails(self):
        self.entry()
        with self.assertRaises(checker.Invalid):
            self.check(base="refs/heads/not-fetched")

    def test_no_committed_candidate_fails(self):
        with self.assertRaisesRegex(checker.Invalid, "No committed"):
            self.check()

    def test_unknown_category_and_duplicate_unreleased_fail(self):
        for content in [BASE.replace("### Fixed", "### Other\n\n- A new behavior."),
                        BASE + "\n## [Unreleased]\n\n### Fixed\n\n- Another behavior.\n"]:
            self.git("reset", "--hard", self.base)
            self.change(content)
            with self.assertRaises(checker.Invalid):
                self.check()

    def test_advanced_base_uses_merge_base_of_entire_pr(self):
        self.entry()
        self.git("switch", "main")
        (self.repo / "target.txt").write_text("target advanced")
        self.save("target advanced")
        target = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "change")
        result = self.check(self.event(base=target), base=target)
        self.assertEqual(result["merge_base"], self.base)
        self.assertEqual(result["new_entry_count"], 1)

    def test_cli_nonzero_and_missing_metadata_disclosure(self):
        self.entry()
        with mock.patch.object(sys, "argv", ["check-changelog.py", "--base", self.base]), mock.patch("builtins.print") as output:
            self.assertEqual(checker.main(), 0)
            self.assertIn("metadata unavailable", output.call_args_list[0].args[0])
        with mock.patch.object(sys, "argv", ["check-changelog.py", "--base", "missing-base"]), mock.patch("builtins.print"):
            self.assertEqual(checker.main(), 1)


if __name__ == "__main__":
    unittest.main()
