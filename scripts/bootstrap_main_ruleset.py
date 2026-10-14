"""One-time, fail-closed ruleset bootstrap for the Agent Core repository.

Create only the exact reviewed ruleset and only with a dedicated admin secret.
This code does not print credentials, accept a user-provided target or update rules.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

REPO = "ericson-j-santos/agent-core"
RULE_NAME = "agent-core-main-governed"
EXPECTED_CHECK = "agent-core-test"
POLICY = Path(__file__).resolve().parents[1] / ".github/rulesets/agent-core-main.json"
_SHA = re.compile(r"[a-f0-9]{40}\Z")


class Blocked(RuntimeError):
    pass


class API(Protocol):
    def get(self, path: str) -> Any: ...
    def create(self, path: str, body: dict[str, Any]) -> Any: ...


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) != {
        "name", "target", "enforcement", "bypass_actors", "conditions", "rules"
    }:
        raise Blocked("policy_keys_invalid")
    if (policy["name"] != RULE_NAME or policy["target"] != "branch" or
        policy["enforcement"] != "active" or policy["bypass_actors"] != [] or
        policy["conditions"] != {"ref_name": {
            "include": ["refs/heads/main"], "exclude": []}}):
        raise Blocked("policy_scope_invalid")
    rules = policy["rules"]
    if not isinstance(rules, list) or len(rules) != 4:
        raise Blocked("policy_rule_count_invalid")
    by_type = {r.get("type"): r for r in rules if isinstance(r, dict)}
    if set(by_type) != {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}:
        raise Blocked("policy_rule_set_invalid")
    if any(by_type[t].get("parameters") for t in ("deletion", "non_fast_forward")):
        raise Blocked("policy_builtin_rule_invalid")
    pull = by_type["pull_request"].get("parameters") or {}
    checks = by_type["required_status_checks"].get("parameters") or {}
    if (pull.get("required_review_thread_resolution") is not True or
        type(pull.get("required_approving_review_count")) is not int or
        pull["required_approving_review_count"] < 0 or
        checks.get("strict_required_status_checks_policy") is not True or
        checks.get("required_status_checks") != [{"context": EXPECTED_CHECK}]):
        raise Blocked("policy_required_guard_invalid")
    return policy


def main_sha(api: API) -> str:
    repo = api.get(f"/repos/{REPO}")
    if not isinstance(repo, dict) or repo.get("full_name") != REPO or repo.get("private") is not False or repo.get("default_branch") != "main":
        raise Blocked("repository_identity_invalid")
    branch = api.get(f"/repos/{REPO}/branches/main")
    sha = (branch.get("commit") or {}).get("sha") if isinstance(branch, dict) else None
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise Blocked("main_head_invalid")
    return sha


def _summaries(api: API) -> list[dict[str, Any]]:
    rows = api.get(f"/repos/{REPO}/rulesets?includes_parents=false")
    if not isinstance(rows, list) or len(rows) > 20 or any(not isinstance(x, dict) for x in rows):
        raise Blocked("ruleset_inventory_invalid")
    if any(row.get("name") != RULE_NAME for row in rows) or len(rows) > 1:
        raise Blocked("ruleset_inventory_conflict")
    return rows


def _detail(api: API, rule_id: int) -> dict[str, Any]:
    detail = api.get(f"/repos/{REPO}/rulesets/{rule_id}")
    if not isinstance(detail, dict) or detail.get("id") != rule_id:
        raise Blocked("ruleset_detail_invalid")
    return detail


def reconcile(api: API, desired: dict[str, Any], expected_main: str) -> dict[str, Any]:
    validate_policy(desired)
    if not isinstance(expected_main, str) or not _SHA.fullmatch(expected_main):
        raise Blocked("expected_main_invalid")
    if main_sha(api) != expected_main:
        raise Blocked("main_sha_changed")
    rows = _summaries(api)
    created = False
    if not rows:
        # Compare before POST, and allow a single creation only.
        if main_sha(api) != expected_main or _summaries(api):
            raise Blocked("pre_create_state_changed")
        observed = api.create(f"/repos/{REPO}/rulesets", desired)
        rule_id = observed.get("id") if isinstance(observed, dict) else None
        created = True
    else:
        rule_id = rows[0].get("id")
    if type(rule_id) is not int or rule_id <= 0:
        raise Blocked("ruleset_id_invalid")
    actual = _detail(api, rule_id)
    latest = _summaries(api)
    by_type = {r.get("type"): r for r in actual.get("rules", []) if isinstance(r, dict)}
    if (
        len(actual.get("rules", [])) != 4
        or set(by_type) != {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
    ):
        raise Blocked("ruleset_unexpected_rules")
    if main_sha(api) != expected_main:
        raise Blocked("main_changed_during_reconciliation")
    from scripts.audit_main_governance import verify_policy, AuditBlocked
    repo = api.get(f"/repos/{REPO}")
    branch = api.get(f"/repos/{REPO}/branches/main")
    effective = api.get(f"/repos/{REPO}/rules/branches/main")
    try:
        independent = verify_policy(desired, repo, branch, latest, actual, effective)
    except AuditBlocked as error:
        raise Blocked(f"independent_verification_{error}") from None
    if independent.get("main_sha") != expected_main:
        raise Blocked("independent_main_sha_changed")
    return {"status": "verified", "main_sha": expected_main,
            "ruleset_id": rule_id, "created": created,
            "required_check": EXPECTED_CHECK, "no_bypass": True}


class Client:
    def __init__(self, token: str):
        if not token or len(token) > 4096:
            raise Blocked("admin_credential_missing")
        self.token = token

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if not path.startswith(f"/repos/{REPO}/") and path != f"/repos/{REPO}":
            raise Blocked("api_path_not_allowed")
        if ".." in path or "://" in path or method not in {"GET", "POST"} or (
            method == "POST" and (path != f"/repos/{REPO}/rulesets" or body is None)
        ):
            raise Blocked("api_operation_not_allowed")
        request = urllib.request.Request(
            "https://api.github.com" + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method=method, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "Content-Type": "application/json",
                "User-Agent": "agent-core-ruleset-bootstrap",
            })
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status != (201 if method == "POST" else 200):
                    raise Blocked("github_unexpected_status")
                return json.loads(response.read(200000))
        except urllib.error.HTTPError as exc:
            raise Blocked(f"github_http_{exc.code}") from None
        except (OSError, ValueError):
            raise Blocked("github_transport_failed") from None

    def get(self, path: str) -> Any:
        return self._call("GET", path)

    def create(self, path: str, body: dict[str, Any]) -> Any:
        return self._call("POST", path, body)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-main", required=True)
    args = parser.parse_args()
    try:
        token = os.getenv("AGENT_CORE_RULESET_ADMIN_TOKEN", "")
        result = reconcile(Client(token), json.loads(POLICY.read_text()), args.expected_main)
        print(json.dumps(result, sort_keys=True))
    except (Blocked, OSError, ValueError) as error:
        code = str(error) if isinstance(error, Blocked) else "invalid_policy"
        print(json.dumps({"status": "blocked", "reason_code": code}))
        raise SystemExit(2) from None
