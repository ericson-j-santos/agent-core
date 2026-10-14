"""Governance drift detection using public ruleset metadata and a pinned admin attestation.

GitHub omits bypass_actors for tokens without ruleset-write access. This
auditor never converts a missing field to a live observation: it compares the
ruleset ID and server-updated timestamp with a previously privileged attestation.
Any change, missing metadata, or ambiguous rule is BLOCKED. No mutating API.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from scripts.audit_main_governance import (
    AuditBlocked, REPOSITORY, SHA, TARGET_BRANCH, TEMPLATE_PATH,
    _require, read_github, verify_policy,
)

ATTESTATION_PATH = Path(__file__).resolve().parents[1] / "config/governance/ruleset-attestation-v1.json"
EXPECTED_RULESET_ID = 25099330
EXPECTED_TRUSTED_RUN = 38604135772
EXPECTED_TRUSTED_SHA = "4a0a2f7053b4d7ab27188f8987086682033c2998"


def validate_attestation(attestation: Any) -> dict[str, Any]:
    fields = {
        "schema_version", "repository", "branch", "ruleset_name", "ruleset_id",
        "ruleset_updated_at", "bypass_actors_at_attestation", "trusted_audit_run",
        "trusted_main_sha", "mode",
    }
    _require(isinstance(attestation, dict) and set(attestation) == fields,
             "attestation_schema_invalid")
    _require(attestation["schema_version"] == "agent-core/ruleset-attestation-v1",
             "attestation_version_invalid")
    _require(attestation["repository"] == REPOSITORY and attestation["branch"] == TARGET_BRANCH,
             "attestation_identity_invalid")
    _require(attestation["ruleset_name"] == "agent-core-main-governed" and
             type(attestation["ruleset_id"]) is int and
             attestation["ruleset_id"] == EXPECTED_RULESET_ID,
             "attestation_ruleset_invalid")
    _require(attestation["bypass_actors_at_attestation"] == [],
             "attestation_bypass_invalid")
    _require(
        type(attestation["trusted_audit_run"]) is int and
        attestation["trusted_audit_run"] == EXPECTED_TRUSTED_RUN and
        attestation["trusted_main_sha"] == EXPECTED_TRUSTED_SHA and
        attestation["mode"] == "privileged_get_verified_no_bypass",
        "attestation_source_invalid",
    )
    updated_at = attestation["ruleset_updated_at"]
    _require(
        isinstance(updated_at, str) and
        len(updated_at) in (24, 29) and updated_at.startswith("2026-10-14T") and
        ("Z" in updated_at or updated_at[-6:-5] in ("-", "+")),
        "attestation_timestamp_invalid",
    )
    return attestation


def _as_utc(value: Any) -> datetime:
    _require(isinstance(value, str) and bool(value),
             "ruleset_timestamp_missing")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AuditBlocked("ruleset_timestamp_invalid") from None
    _require(stamp.tzinfo is not None and stamp.utcoffset() is not None,
             "ruleset_timestamp_timezone_missing")
    return stamp.astimezone(timezone.utc)


def _same_instant(observed: Any, attested: str) -> bool:
    # UTC conversion retains microseconds; never round or add tolerance.
    return _as_utc(observed) == _as_utc(attested)


def _validate_summary(rows: Any, att: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
             "ruleset_inventory_not_unique")
    row = rows[0]
    _require(
        row.get("id") == att["ruleset_id"] and
        row.get("name") == att["ruleset_name"] and
        row.get("target") == "branch" and
        row.get("source_type") == "Repository" and
        row.get("source") == REPOSITORY and
        row.get("enforcement") == "active",
        "ruleset_summary_identity_invalid",
    )
    _require(
        _same_instant(row.get("updated_at"), att["ruleset_updated_at"]),
        "ruleset_version_changed_recredential_required",
    )
    return row


def audit_readonly_attested(
    read: Callable[[str], Any] = read_github,
    attestation: dict[str, Any] | None = None,
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if attestation is None:
        attestation = json.loads(ATTESTATION_PATH.read_text(encoding="utf-8"))
    if template is None:
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    att = validate_attestation(attestation)
    root = f"/repos/{REPOSITORY}"
    repository = read(root)
    initial_branch = read(root + "/branches/main")
    summaries = read(root + "/rulesets?includes_parents=false")
    row = _validate_summary(summaries, att)
    detail = read(root + f"/rulesets/{att['ruleset_id']}")
    _require(isinstance(detail, dict) and detail.get("id") == att["ruleset_id"],
             "ruleset_detail_identity_invalid")
    _require(_same_instant(detail.get("updated_at"), att["ruleset_updated_at"]),
             "ruleset_detail_version_changed")
    live_bypass_visible = "bypass_actors" in detail
    if live_bypass_visible:
        _require(detail["bypass_actors"] == [], "ruleset_live_bypass_changed")
        protected_detail = detail
    else:
        # This is a historical, version-pinned attestation, NOT a live bypass read.
        protected_detail = dict(detail, bypass_actors=att["bypass_actors_at_attestation"])
    effective = read(root + "/rules/branches/main")
    checked = verify_policy(template, repository, initial_branch, summaries, protected_detail, effective)
    _require(checked["ruleset_id"] == row["id"], "ruleset_id_changed_during_audit")
    final_summary = read(root + "/rulesets?includes_parents=false")
    _validate_summary(final_summary, att)
    final_branch = read(root + "/branches/main")
    sha = ((final_branch.get("commit") or {}).get("sha")
           if isinstance(final_branch, dict) else None)
    _require(sha == checked["main_sha"] and isinstance(sha, str) and SHA.fullmatch(sha),
             "main_sha_changed_during_readback")
    return {
        "status": "verified_live" if live_bypass_visible else "verified_attested",
        "repository": REPOSITORY,
        "main_sha": sha,
        "ruleset_id": att["ruleset_id"],
        "ruleset_updated_at": att["ruleset_updated_at"],
        "required_check": "agent-core-test",
        "bypass_live_visible": live_bypass_visible,
        "bypass_unchanged_since_admin_attestation": True,
        "trusted_audit_run": att["trusted_audit_run"],
        "remote_enforcement_readback": True,
        "writes_performed": 0,
    }


def main() -> int:
    try:
        outcome = audit_readonly_attested()
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (AuditBlocked, ValueError, OSError, KeyError) as exc:
        reason = str(exc) if isinstance(exc, AuditBlocked) else "attestation_input_invalid"
        print(json.dumps({"status": "blocked", "reason_code": reason, "writes_performed": 0},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
