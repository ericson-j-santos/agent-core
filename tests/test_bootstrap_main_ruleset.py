"""Offline, read-only contract tests for an allowlisted one-time ruleset bootstrap."""
from __future__ import annotations

import copy
import json
import os
import unittest

from scripts.bootstrap_main_ruleset import (
    Blocked, Client, POLICY, REPO, RULE_NAME, main_sha, reconcile, validate_policy,
)

HEAD = "a" * 40
RULE_ID = 17014
EXPECTED = json.loads(POLICY.read_text())


class FakeGitHub:
    def __init__(self, *, existing=False, unexpected=False):
        self.created = 0
        self.calls: list[tuple[str, str]] = []
        self.sha = HEAD
        self.force_changed_head = False
        self._main_reads = 0
        self.spec = copy.deepcopy(EXPECTED)
        self.rule_id = RULE_ID
        self.rows = (
            [{"id": RULE_ID, "name": RULE_NAME, "enforcement": "active"}]
            if existing else
            [{"id": 77, "name": "unexpected", "enforcement": "active"}]
            if unexpected else []
        )
        self.protected = existing
        self.detail = {**copy.deepcopy(EXPECTED), "id": RULE_ID} if existing else None

    def get(self, path):
        self.calls.append(("GET", path))
        prefix = f"/repos/{REPO}"
        if path == prefix:
            return {"full_name": REPO, "private": False, "default_branch": "main"}
        if path == prefix + "/branches/main":
            self._main_reads += 1
            sha = "b" * 40 if self.force_changed_head and self._main_reads > 1 else self.sha
            return {"name": "main", "commit": {"sha": sha}, "protected": self.protected}
        if path == prefix + "/rulesets?includes_parents=false":
            return copy.deepcopy(self.rows)
        if path == prefix + f"/rulesets/{RULE_ID}":
            return copy.deepcopy(self.detail)
        if path == prefix + "/rules/branches/main":
            return copy.deepcopy(self.spec["rules"]) if self.protected else []
        raise AssertionError("unexpected GET " + path)

    def create(self, path, body):
        self.calls.append(("POST", path))
        assert path == f"/repos/{REPO}/rulesets"
        self.created += 1
        self.rows = [{"id": RULE_ID, "name": RULE_NAME, "enforcement": "active"}]
        self.detail = {**copy.deepcopy(body), "id": RULE_ID}
        self.protected = True
        return {"id": RULE_ID}


class BootstrapTests(unittest.TestCase):
    def test_create_once_only_exact_target(self):
        fake = FakeGitHub()
        response = reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(response["status"], "verified")
        self.assertEqual(response["ruleset_id"], RULE_ID)
        self.assertTrue(response["created"])
        self.assertEqual(fake.created, 1)
        self.assertEqual(
            [p for method, p in fake.calls if method == "POST"],
            [f"/repos/{REPO}/rulesets"],
        )

    def test_idempotent_replay_does_not_post_twice(self):
        fake = FakeGitHub()
        first = reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        next_result = reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertTrue(first["created"])
        self.assertFalse(next_result["created"])
        self.assertEqual(fake.created, 1)

    def test_existing_compliant_does_not_mutate(self):
        fake = FakeGitHub(existing=True)
        result = reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertFalse(result["created"])
        self.assertEqual(fake.created, 0)

    def test_unknown_existing_ruleset_is_not_touched(self):
        fake = FakeGitHub(unexpected=True)
        with self.assertRaisesRegex(Blocked, "inventory_conflict"):
            reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(fake.created, 0)

    def test_invalid_base_sha_blocks_prior_to_write(self):
        fake = FakeGitHub()
        with self.assertRaisesRegex(Blocked, "main_sha_changed"):
            reconcile(fake, copy.deepcopy(EXPECTED), "b" * 40)
        self.assertEqual(fake.created, 0)

    def test_invalid_sha_format_is_blocked(self):
        fake = FakeGitHub()
        with self.assertRaisesRegex(Blocked, "expected_main_invalid"):
            reconcile(fake, copy.deepcopy(EXPECTED), "bad")
        self.assertEqual(fake.created, 0)

    def test_head_advance_during_preflight_blocks_write(self):
        fake = FakeGitHub()
        fake.force_changed_head = True
        with self.assertRaisesRegex(Blocked, "pre_create_state_changed"):
            reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(fake.created, 0)

    def test_missing_admin_token_fails_closed(self):
        with self.assertRaisesRegex(Blocked, "admin_credential_missing"):
            Client("")

    def test_template_name_target_and_bypass_cannot_change(self):
        for path, new in (
            ("name", "other-name"),
            ("enforcement", "disabled"),
            ("bypass_actors", [{"actor_id": 1, "actor_type": "OrganizationAdmin"}]),
            ("conditions", {"ref_name": {"include": ["refs/heads/dev"], "exclude": []}}),
        ):
            with self.subTest(field=path):
                fake = FakeGitHub()
                mutated = copy.deepcopy(EXPECTED)
                mutated[path] = new
                with self.assertRaises(Blocked):
                    reconcile(fake, mutated, HEAD)
                self.assertEqual(fake.created, 0)

    def test_missing_status_check_blocks_before_write(self):
        fake = FakeGitHub()
        wrong = copy.deepcopy(EXPECTED)
        next(rule for rule in wrong["rules"] if rule["type"] == "required_status_checks")[
            "parameters"
        ]["required_status_checks"] = [{"context": "not-agent-core-test"}]
        with self.assertRaisesRegex(Blocked, "policy_required_guard_invalid"):
            reconcile(fake, wrong, HEAD)
        self.assertEqual(fake.created, 0)

    def test_invisible_bypass_actors_never_validate(self):
        fake = FakeGitHub(existing=True)
        fake.detail.pop("bypass_actors")
        with self.assertRaisesRegex(Blocked, "independent_verification_"):
            reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(fake.created, 0)

    def test_missing_effective_rules_never_validate(self):
        fake = FakeGitHub(existing=True)
        fake.spec["rules"] = []
        with self.assertRaisesRegex(Blocked, "independent_verification_"):
            reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(fake.created, 0)

    def test_existing_unprotected_branch_never_validate(self):
        fake = FakeGitHub(existing=True)
        fake.protected = False
        with self.assertRaisesRegex(Blocked, "independent_verification_"):
            reconcile(fake, copy.deepcopy(EXPECTED), HEAD)
        self.assertEqual(fake.created, 0)

    def test_module_entrypoint_runs_without_import_error_or_admin_token(self):
        import subprocess
        import sys
        safe_env = os.environ.copy()
        safe_env.pop("AGENT_CORE_RULESET_ADMIN_TOKEN", None)
        process = subprocess.run(
            [sys.executable, "-m", "scripts.bootstrap_main_ruleset",
             "--expected-main", HEAD],
            env=safe_env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(
            json.loads(process.stdout).get("reason_code"),
            "admin_credential_missing",
        )
        self.assertNotIn("ModuleNotFoundError", process.stderr)

    def test_no_token_or_shell_in_config_file(self):
        text = POLICY.read_text()
        self.assertNotIn("Authorization:", text)
        self.assertNotIn("token:", text)
        self.assertNotIn("shell", text.lower())

    def test_privileged_actions_bootstrap_is_retired(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        self.assertFalse((root / ".github/workflows/main-ruleset-bootstrap.yml").exists())
        self.assertTrue((root / "scripts/bootstrap_main_ruleset.py").is_file())
        self.assertTrue((root / "config/governance/ruleset-attestation-v1.json").is_file())


if __name__ == "__main__":
    unittest.main()
