"""Positive, negative and replay tests for read-only branch-governance audit."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.audit_main_governance import (
    REPOSITORY, AuditBlocked, audit, verify_policy,
)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = json.loads((ROOT / ".github/rulesets/agent-core-main.json").read_text())
HEAD = "c" * 40
RULE_ID = 17001


def fake_dataset():
    t = copy.deepcopy(TEMPLATE)
    return {
        "template": t,
        "repository": {
            "full_name": REPOSITORY, "private": False, "default_branch": "main",
        },
        "branch": {"name": "main", "protected": True, "commit": {"sha": HEAD}},
        "rulesets": [{
            "id": RULE_ID, "name": t["name"], "enforcement": "active", "target": "branch",
        }],
        "detail": dict(copy.deepcopy(t), id=RULE_ID),
        "effective": copy.deepcopy(t["rules"]),
    }


def evaluate(d):
    return verify_policy(
        d["template"], d["repository"], d["branch"],
        d["rulesets"], d["detail"], d["effective"],
    )


class GovernanceAuditTests(unittest.TestCase):
    def test_compliant_live_shape_readonly(self):
        result = evaluate(fake_dataset())
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["main_sha"], HEAD)
        self.assertEqual(result["required_check"], "agent-core-test")
        self.assertTrue(result["remote_enforcement_readback"])
        self.assertEqual(result["writes_performed"], 0)

    def test_replay_returns_identical_observation(self):
        first = evaluate(fake_dataset())
        second = evaluate(fake_dataset())
        self.assertEqual(first, second)

    def test_missing_live_ruleset_fails(self):
        d = fake_dataset()
        d["rulesets"] = []
        with self.assertRaisesRegex(AuditBlocked, "rulesets_missing"):
            evaluate(d)

    def test_inactive_live_ruleset_fails(self):
        d = fake_dataset()
        d["detail"]["enforcement"] = "evaluate"
        with self.assertRaisesRegex(AuditBlocked, "not_active"):
            evaluate(d)

    def test_duplicate_ruleset_fails_closed(self):
        d = fake_dataset()
        d["rulesets"].append(copy.deepcopy(d["rulesets"][0]))
        with self.assertRaisesRegex(AuditBlocked, "not_unique"):
            evaluate(d)

    def test_unprotected_branch_fails(self):
        d = fake_dataset()
        d["branch"]["protected"] = False
        with self.assertRaisesRegex(AuditBlocked, "not_protected"):
            evaluate(d)

    def test_old_or_invalid_sha_fails(self):
        d = fake_dataset()
        d["branch"]["commit"]["sha"] = "outdated"
        with self.assertRaisesRegex(AuditBlocked, "sha_invalid"):
            evaluate(d)

    def test_wrong_repository_fails(self):
        d = fake_dataset()
        d["repository"]["full_name"] = "another-owner/another-repository"
        with self.assertRaisesRegex(AuditBlocked, "repo_identity_invalid"):
            evaluate(d)

    def test_private_visibility_fails(self):
        d = fake_dataset()
        d["repository"]["private"] = True
        with self.assertRaisesRegex(AuditBlocked, "repo_identity_invalid"):
            evaluate(d)

    def test_nondefault_target_fails(self):
        d = fake_dataset()
        d["detail"]["conditions"]["ref_name"]["include"] = ["refs/heads/dev"]
        with self.assertRaisesRegex(AuditBlocked, "branch_target_mismatch"):
            evaluate(d)

    def test_bypass_actor_fails(self):
        d = fake_dataset()
        d["detail"]["bypass_actors"] = [{"actor_id": 1, "actor_type": "OrganizationAdmin"}]
        with self.assertRaisesRegex(AuditBlocked, "bypass_present"):
            evaluate(d)

    def test_strict_required_status_must_hold(self):
        d = fake_dataset()
        for rule in d["effective"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["strict_required_status_checks_policy"] = False
        with self.assertRaisesRegex(AuditBlocked, "effective_strict_missing"):
            evaluate(d)

    def test_required_check_must_match_exact_job(self):
        d = fake_dataset()
        for rule in d["effective"]:
            if rule["type"] == "required_status_checks":
                rule["parameters"]["required_status_checks"] = [{"context": "old-ci-name"}]
        with self.assertRaisesRegex(AuditBlocked, "effective_check_missing"):
            evaluate(d)

    def test_effective_enforcement_can_not_be_replaced_by_template(self):
        d = fake_dataset()
        d["effective"] = [{"type": "pull_request", "parameters": {
            "required_review_thread_resolution": True,
        }}]
        with self.assertRaisesRegex(AuditBlocked, "required_types_missing"):
            evaluate(d)

    def test_threads_resolution_must_be_required(self):
        d = fake_dataset()
        for rule in d["detail"]["rules"]:
            if rule["type"] == "pull_request":
                rule["parameters"]["required_review_thread_resolution"] = False
        with self.assertRaisesRegex(AuditBlocked, "ruleset_thread_resolution_missing"):
            evaluate(d)

    def test_template_mutation_does_not_pass(self):
        d = fake_dataset()
        d["template"]["bypass_actors"].append({"actor_type": "OrganizationAdmin"})
        with self.assertRaisesRegex(AuditBlocked, "template_bypass_invalid"):
            evaluate(d)

    def test_audit_reads_only_approved_endpoints(self):
        d = fake_dataset()
        prefix = f"/repos/{REPOSITORY}"
        lookups = {
            prefix: d["repository"],
            prefix + "/branches/main": d["branch"],
            prefix + "/rulesets?includes_parents=false": d["rulesets"],
            prefix + f"/rulesets/{RULE_ID}": d["detail"],
            prefix + "/rules/branches/main": d["effective"],
        }
        called = []
        def fake_get(path):
            called.append(path)
            return copy.deepcopy(lookups[path])

        observation = audit(fake_get, d["template"])
        self.assertEqual(observation["writes_performed"], 0)
        self.assertEqual(called, list(lookups) + [prefix + "/branches/main"])
        self.assertEqual(observation["main_sha"], HEAD)

    def test_workflow_separates_pr_validation_from_live_enforcement(self):
        """A missing server ruleset must not be mislabeled a code regression."""
        flow = (ROOT / ".github/workflows/main-governance-audit.yml").read_text()
        self.assertIn("name: governance-contract-tests", flow)
        self.assertIn("name: main-server-ruleset-audit", flow)
        self.assertIn(
            "if: github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
            flow,
        )
        self.assertIn("branches: [main]", flow)
        self.assertIn("cron:", flow)
        self.assertIn("run: python scripts/audit_main_governance.py", flow)
        self.assertIn("needs: [governance-contract-tests]", flow)
        self.assertNotIn("continue-on-error:", flow)
        self.assertNotIn("|| true", flow)

    def test_expected_absent_rule_remains_blocking(self):
        """No change to the pure fail-closed gate is allowed for a green PR."""
        d = fake_dataset()
        d["rulesets"] = []
        with self.assertRaises(AuditBlocked):
            evaluate(d)
        d["branch"]["protected"] = False
        with self.assertRaises(AuditBlocked):
            evaluate(d)


    def test_remote_bypass_visibility_must_be_explicit(self):
        """Missing GitHub bypass_actors (often permission-limited) is not []."""
        d = fake_dataset()
        d["detail"].pop("bypass_actors")
        with self.assertRaisesRegex(AuditBlocked, "ruleset_bypass_unverifiable"):
            evaluate(d)

    def test_audit_rejects_main_sha_advancing_during_readback(self):
        d = fake_dataset()
        prefix = f"/repos/{REPOSITORY}"
        urls = {
            prefix: d["repository"],
            prefix + "/branches/main": d["branch"],
            prefix + "/rulesets?includes_parents=false": d["rulesets"],
            prefix + f"/rulesets/{RULE_ID}": d["detail"],
            prefix + "/rules/branches/main": d["effective"],
        }
        calls = []
        def moving_read(path):
            calls.append(path)
            value = copy.deepcopy(urls[path])
            if path == prefix + "/branches/main" and calls.count(path) == 2:
                value["commit"]["sha"] = "d" * 40
            return value
        with self.assertRaisesRegex(AuditBlocked, "main_sha_changed_during_audit"):
            audit(moving_read, d["template"])
        self.assertEqual(calls[-1], prefix + "/branches/main")

    def test_audit_stops_on_missing_ruleset_without_mutation(self):
        d = fake_dataset()
        prefix = f"/repos/{REPOSITORY}"
        observations = {
            prefix: d["repository"],
            prefix + "/branches/main": d["branch"],
            prefix + "/rulesets?includes_parents=false": [],
        }
        called = []
        def fake_get(path):
            called.append(path)
            return copy.deepcopy(observations[path])
        with self.assertRaisesRegex(AuditBlocked, "required_ruleset_missing"):
            audit(fake_get, d["template"])
        self.assertEqual(called, list(observations))
