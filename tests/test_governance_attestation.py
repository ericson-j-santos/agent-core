"""Read-only version-pinned ruleset attestation tests: never grant bypass."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.audit_main_governance import AuditBlocked
from scripts.audit_readonly_attestation import (
    ATTESTATION_PATH, audit_readonly_attested, validate_attestation,
)

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads(ATTESTATION_PATH.read_text(encoding="utf-8"))
TEMPLATE = json.loads((ROOT / ".github/rulesets/agent-core-main.json").read_text())
REPO = "ericson-j-santos/agent-core"
HEAD = "a" * 40
RULE_ID = 25099330


def fixture(*, show_bypass=False):
    detail = dict(copy.deepcopy(TEMPLATE),
                  id=RULE_ID,
                  updated_at=BASE["ruleset_updated_at"])
    if not show_bypass:
        detail.pop("bypass_actors", None)
    return {
        "repo": {"full_name": REPO, "private": False, "default_branch": "main"},
        "branch": {"name": "main", "protected": True, "commit": {"sha": HEAD}},
        "summary": [{
            "id": RULE_ID, "name": TEMPLATE["name"], "target": "branch",
            "source_type": "Repository", "source": REPO,
            "enforcement": "active", "updated_at": BASE["ruleset_updated_at"],
        }],
        "detail": detail,
        "effective": copy.deepcopy(TEMPLATE["rules"]),
    }


def run_fixture(data, *, attestation=None):
    prefix = f"/repos/{REPO}"
    responses = {
        prefix: data["repo"],
        prefix + "/branches/main": data["branch"],
        prefix + "/rulesets?includes_parents=false": data["summary"],
        prefix + f"/rulesets/{RULE_ID}": data["detail"],
        prefix + "/rules/branches/main": data["effective"],
    }
    trace: list[str] = []
    def fake_get(path):
        trace.append(path)
        return copy.deepcopy(responses[path])
    result = audit_readonly_attested(
        fake_get, attestation or copy.deepcopy(BASE), copy.deepcopy(TEMPLATE))
    return result, trace


class RulesetAttestationTests(unittest.TestCase):
    def test_positive_without_sensitive_bypass_field(self):
        result, trace = run_fixture(fixture())
        self.assertEqual(result["status"], "verified_attested")
        self.assertFalse(result["bypass_live_visible"])
        self.assertTrue(result["bypass_unchanged_since_admin_attestation"])
        self.assertEqual(result["trusted_audit_run"], BASE["trusted_audit_run"])
        self.assertEqual(result["writes_performed"], 0)
        self.assertEqual(len(trace), 7)
        self.assertEqual(trace[-1], f"/repos/{REPO}/branches/main")

    def test_positive_when_admin_can_view_bypass(self):
        result, _ = run_fixture(fixture(show_bypass=True))
        self.assertEqual(result["status"], "verified_live")
        self.assertTrue(result["bypass_live_visible"])

    def test_replay_is_identical_and_readonly(self):
        a, a_trace = run_fixture(fixture())
        b, b_trace = run_fixture(fixture())
        self.assertEqual(a, b)
        self.assertEqual(a_trace, b_trace)
        self.assertFalse(any("POST" in x for x in a_trace))

    def test_summary_timestamp_change_blocks_hidden_bypass(self):
        data = fixture()
        data["summary"][0]["updated_at"] = "2026-10-14T10:52:12.227-07:00"
        with self.assertRaisesRegex(AuditBlocked, "ruleset_version_changed"):
            run_fixture(data)

    def test_detail_version_change_blocks_even_when_summary_stale(self):
        data = fixture()
        data["detail"]["updated_at"] = "2026-10-14T10:52:12.227-07:00"
        with self.assertRaisesRegex(AuditBlocked, "ruleset_detail_version_changed"):
            run_fixture(data)

    def test_missing_updated_at_blocks(self):
        data = fixture()
        data["summary"][0].pop("updated_at")
        with self.assertRaisesRegex(AuditBlocked, "ruleset_version_changed"):
            run_fixture(data)

    def test_mismatched_attestation_fails_closed(self):
        for mutate in (
            lambda x: x.update(trusted_audit_run=9),
            lambda x: x.update(trusted_main_sha="f" * 40),
            lambda x: x.update(bypass_actors_at_attestation=[{"actor_id": 1}]),
            lambda x: x.update(ruleset_id=20),
            lambda x: x.update(repository="another/repo"),
            lambda x: x.update(ruleset_updated_at=""),
        ):
            with self.subTest(mutation=str(mutate)):
                record = copy.deepcopy(BASE)
                mutate(record)
                with self.assertRaises(AuditBlocked):
                    run_fixture(fixture(), attestation=record)

    def test_empty_or_extra_rulesets_blocks(self):
        for value in ([], fixture()["summary"] * 2):
            with self.subTest(n=len(value)):
                data = fixture()
                data["summary"] = value
                with self.assertRaisesRegex(AuditBlocked, "ruleset_inventory_not_unique"):
                    run_fixture(data)

    def test_hidden_bypass_is_never_reported_as_live(self):
        result, _ = run_fixture(fixture())
        self.assertNotIn("bypass_live_verified", result)
        self.assertFalse(result["bypass_live_visible"])
        self.assertNotEqual(result["status"], "verified_live")

    def test_visible_bypass_change_blocks(self):
        data = fixture(show_bypass=True)
        data["detail"]["bypass_actors"].append({
            "actor_id": 1, "actor_type": "RepositoryRole", "bypass_mode": "always"
        })
        with self.assertRaisesRegex(AuditBlocked, "ruleset_live_bypass_changed"):
            run_fixture(data)

    def test_missing_required_check_blocks(self):
        data = fixture()
        for rule in data["effective"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [{"context": "unrelated"}]
        with self.assertRaisesRegex(AuditBlocked, "effective_check_missing"):
            run_fixture(data)

    def test_branch_unprotected_blocks(self):
        data = fixture()
        data["branch"]["protected"] = False
        with self.assertRaisesRegex(AuditBlocked, "branch_not_protected"):
            run_fixture(data)

    def test_main_changed_during_readback_blocks(self):
        data = fixture()
        count = 0
        prefix = f"/repos/{REPO}"
        responses = {
            prefix: data["repo"],
            prefix + "/rulesets?includes_parents=false": data["summary"],
            prefix + f"/rulesets/{RULE_ID}": data["detail"],
            prefix + "/rules/branches/main": data["effective"],
        }
        def fake_get(path):
            nonlocal count
            if path == prefix + "/branches/main":
                count += 1
                return {"name": "main", "protected": True,
                        "commit": {"sha": HEAD if count == 1 else "f" * 40}}
            return copy.deepcopy(responses[path])
        with self.assertRaisesRegex(AuditBlocked, "main_sha_changed_during_readback"):
            audit_readonly_attested(fake_get, copy.deepcopy(BASE), copy.deepcopy(TEMPLATE))

    def test_unprivileged_audit_never_uses_admin_secret(self):
        workflow = (ROOT / ".github/workflows/governance-attestation-canary.yml").read_text()
        self.assertIn("permissions:", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("GITHUB_TOKEN:", workflow)
        self.assertIn("github.token", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("continue-on-error", workflow)

    def test_no_external_credential_or_mutation_in_module(self):
        code = (ROOT / "scripts/audit_readonly_attestation.py").read_text()
        self.assertNotIn("AGENT_CORE_RULESET_ADMIN_TOKEN", code)
        self.assertNotIn('method="POST"', code)
        self.assertNotIn('method="PUT"', code)
        self.assertIn('bypass_live_visible', code)


if __name__ == "__main__":
    unittest.main()
