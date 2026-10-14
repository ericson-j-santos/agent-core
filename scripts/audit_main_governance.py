"""Read-only audit of required branch governance; never modifies GitHub.

An absent or inaccessible rule is BLOCKED, even when ordinary CI is green.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

REPOSITORY = "ericson-j-santos/agent-core"
TARGET_BRANCH = "main"
TEMPLATE_PATH = Path(__file__).resolve().parents[1] / ".github/rulesets/agent-core-main.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED_RULE_TYPES = frozenset(
    ("deletion", "non_fast_forward", "pull_request", "required_status_checks")
)


class AuditBlocked(RuntimeError):
    """A closed gate always stops claims that branch protection is active."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AuditBlocked(code)


def verify_policy(
    template: dict[str, Any],
    repository: Any,
    branch: Any,
    ruleset_list: Any,
    ruleset_detail: Any,
    effective_rules: Any,
) -> dict[str, Any]:
    """Pure independent evidence evaluation for unit and negative tests."""
    _require(isinstance(template, dict), "template_invalid")
    expected_ref = {"include": ["refs/heads/main"], "exclude": []}
    _require(template.get("name") == "agent-core-main-governed", "template_name_invalid")
    _require(template.get("target") == "branch", "template_target_invalid")
    _require(template.get("enforcement") == "active", "template_not_active")
    _require(template.get("bypass_actors") == [], "template_bypass_invalid")
    _require(
        (template.get("conditions") or {}).get("ref_name") == expected_ref,
        "template_branch_target_invalid",
    )
    _require(isinstance(repository, dict), "repo_read_invalid")
    _require(
        repository.get("full_name") == REPOSITORY
        and repository.get("private") is False
        and repository.get("default_branch") == TARGET_BRANCH,
        "repo_identity_invalid",
    )
    _require(isinstance(branch, dict), "branch_read_invalid")
    commit = branch.get("commit")
    head = commit.get("sha") if isinstance(commit, dict) else None
    _require(isinstance(head, str) and SHA.fullmatch(head) is not None, "branch_sha_invalid")
    _require(branch.get("protected") is True, "branch_not_protected")
    _require(
        isinstance(ruleset_list, list)
        and 0 < len(ruleset_list) <= 100
        and all(isinstance(item, dict) for item in ruleset_list),
        "rulesets_missing_or_invalid",
    )
    matched = [item for item in ruleset_list if item.get("name") == template["name"]]
    _require(len(matched) == 1, "required_ruleset_not_unique")
    _require(matched[0].get("enforcement") == "active", "ruleset_summary_not_active")
    rule_id = matched[0].get("id")
    _require(type(rule_id) is int and rule_id > 0, "ruleset_id_invalid")
    _require(isinstance(ruleset_detail, dict) and ruleset_detail.get("id") == rule_id,
             "ruleset_detail_mismatch")
    _require(ruleset_detail.get("target") == "branch", "ruleset_detail_target_invalid")
    _require(ruleset_detail.get("enforcement") == "active", "ruleset_detail_not_active")
    # GitHub may omit bypass_actors for a token without ruleset-edit permission.
    # Omitted does not mean no bypass: fail closed with an explicit reason.
    _require("bypass_actors" in ruleset_detail, "ruleset_bypass_unverifiable")
    _require(ruleset_detail["bypass_actors"] == [], "ruleset_bypass_present")
    _require(
        (ruleset_detail.get("conditions") or {}).get("ref_name") == expected_ref,
        "ruleset_branch_target_mismatch",
    )
    def validate_rules(rules: Any, source: str) -> None:
        _require(isinstance(rules, list), source + "_invalid")
        index = {
            item.get("type"): item
            for item in rules
            if isinstance(item, dict) and isinstance(item.get("type"), str)
        }
        _require(REQUIRED_RULE_TYPES.issubset(index), source + "_required_types_missing")
        required = (index["required_status_checks"].get("parameters") or {})
        _require(required.get("strict_required_status_checks_policy") is True,
                 source + "_strict_missing")
        checks = required.get("required_status_checks")
        _require(
            isinstance(checks, list)
            and any(isinstance(x, dict) and x.get("context") == "agent-core-test" for x in checks),
            source + "_check_missing",
        )
        params = index["pull_request"].get("parameters") or {}
        _require(params.get("required_review_thread_resolution") is True,
                 source + "_thread_resolution_missing")
    validate_rules(template.get("rules"), "template")
    validate_rules(ruleset_detail.get("rules"), "ruleset")
    validate_rules(effective_rules, "effective")
    return {
        "status": "verified",
        "repository": REPOSITORY,
        "main_sha": head,
        "ruleset_id": rule_id,
        "required_check": "agent-core-test",
        "remote_enforcement_readback": True,
        "writes_performed": 0,
    }


def read_github(path: str) -> Any:
    prefix = f"/repos/{REPOSITORY}/"
    _require(path == f"/repos/{REPOSITORY}" or path.startswith(prefix), "api_path_denied")
    _require(".." not in path and "://" not in path, "api_path_invalid")
    token = os.environ.get("GITHUB_TOKEN", "")
    _require(bool(token.strip()) and len(token) <= 4096,
             "github_audit_admin_credential_missing")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agent-core-governance-audit",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request("https://api.github.com" + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            _require(resp.status == 200, "github_http_unexpected")
            raw = resp.read(1_000_001)
            _require(len(raw) <= 1_000_000, "github_response_too_large")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise AuditBlocked(f"github_http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        raise AuditBlocked("github_read_failed") from None


def audit(
    read: Callable[[str], Any] = read_github,
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if template is None:
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    root = f"/repos/{REPOSITORY}"
    repo = read(root)
    branch = read(root + "/branches/main")
    summaries = read(root + "/rulesets?includes_parents=false")
    matches = (
        [v for v in summaries if isinstance(v, dict) and v.get("name") == template.get("name")]
        if isinstance(summaries, list)
        else []
    )
    _require(len(matches) > 0, "required_ruleset_missing")
    _require(len(matches) == 1, "required_ruleset_not_unique")
    rule_id = matches[0].get("id")
    _require(type(rule_id) is int and rule_id > 0, "ruleset_id_invalid")
    detail = read(root + f"/rulesets/{rule_id}")
    effective = read(root + "/rules/branches/main")
    observation = verify_policy(template, repo, branch, summaries, detail, effective)
    # A base may advance during multiple API reads; never reuse an older SHA.
    last_branch = read(root + "/branches/main")
    last_sha = (
        (last_branch.get("commit") or {}).get("sha")
        if isinstance(last_branch, dict) else None
    )
    _require(last_sha == observation["main_sha"], "main_sha_changed_during_audit")
    return observation


def main() -> int:
    try:
        result = audit()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AuditBlocked, ValueError, OSError) as exc:
        code = str(exc) if isinstance(exc, AuditBlocked) else "audit_input_invalid"
        print(json.dumps({
            "status": "blocked", "reason_code": code, "repository": REPOSITORY,
            "writes_performed": 0,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
