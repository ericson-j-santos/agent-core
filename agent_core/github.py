"""Read-only GitHub checks adapter, with bounded HTTPS access and SHA evidence."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from .contracts import Blocked, ModuleDescriptor, ModuleRequest, ModuleResult, valid_sha

CAPABILITY = "github.pr.diagnose.v1"
_MAX_CHECKS = 1000
_MAX_RESPONSE_BYTES = 2_000_000


class GitHubReader(Protocol):
    def get_pull_request(self, repository: str, number: int) -> dict[str, Any]: ...
    def get_check_runs(self, repository: str, sha: str, page: int) -> dict[str, Any]: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("unexpected_redirect")


class GitHubHTTPS:
    """Fixed github.com API origin; no POST, dynamic hostname or arbitrary URL."""

    def __init__(self, token: str | None = None) -> None:
        if token is not None and (not isinstance(token, str) or len(token) > 2048 or not token):
            raise Blocked("invalid_token_configuration")
        self._token = token
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _get(self, path: str) -> dict[str, Any]:
        if not path.startswith("/repos/") or ".." in path or "#" in path:
            raise Blocked("invalid_api_path")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "portable-agent-core/0.2",
        }
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        req = urllib.request.Request("https://api.github.com" + path, headers=headers)
        try:
            with self._opener.open(req, timeout=12) as response:
                if response.status != 200:
                    raise Blocked("unexpected_http_status")
                data = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(data) > _MAX_RESPONSE_BYTES:
                    raise Blocked("github_response_too_large")
                parsed = json.loads(data)
                if not isinstance(parsed, dict):
                    raise Blocked("github_response_not_object")
                return parsed
        except Blocked:
            raise
        except urllib.error.HTTPError as ex:
            raise Blocked("github_http_%d" % ex.code) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise Blocked("github_transport_failure") from None

    def get_pull_request(self, repository: str, number: int) -> dict[str, Any]:
        return self._get("/repos/%s/pulls/%d" % (repository, number))

    def get_check_runs(self, repository: str, sha: str, page: int) -> dict[str, Any]:
        return self._get("/repos/%s/commits/%s/check-runs?per_page=100&page=%d" % (repository, sha, page))


class GitHubPRDiagnostics:
    descriptor = ModuleDescriptor(
        module_id="github-pr-diagnostics", capability_id=CAPABILITY,
        version="1.0.0", max_risk=0, read_only=True,
    )

    def __init__(self, reader: GitHubReader) -> None:
        self._reader = reader

    @staticmethod
    def _identify(pr: Any, number: int) -> tuple[str, str]:
        if not isinstance(pr, dict) or pr.get("number") != number:
            raise Blocked("pr_identity_invalid")
        head = pr.get("head")
        base = pr.get("base")
        hs = head.get("sha") if isinstance(head, dict) else None
        bs = base.get("sha") if isinstance(base, dict) else None
        if not valid_sha(hs) or not valid_sha(bs):
            raise Blocked("pr_sha_invalid")
        return hs, bs

    def observe(self, request: ModuleRequest) -> ModuleResult:
        if set(request.payload.keys()) != {"pr_number"}:
            raise Blocked("payload_fields_not_allowed")
        number = request.payload["pr_number"]
        if type(number) is not int or not (0 < number <= 99_999_999):
            raise Blocked("invalid_pr_number")
        first_sha, base_sha = self._identify(
            self._reader.get_pull_request(request.repository, number), number
        )
        if request.expected_head and request.expected_head != first_sha:
            raise Blocked("expected_head_mismatch")
        checks: list[dict[str, Any]] = []
        total = None
        for page in range(1, 11):
            data = self._reader.get_check_runs(request.repository, first_sha, page)
            if not isinstance(data, dict) or type(data.get("total_count")) is not int:
                raise Blocked("invalid_checks_response")
            if total is None:
                total = data["total_count"]
            if data["total_count"] != total or total < 0 or total > _MAX_CHECKS:
                raise Blocked("checks_count_changed_or_unbounded")
            rows = data.get("check_runs")
            if not isinstance(rows, list) or len(rows) > 100:
                raise Blocked("invalid_checks_page")
            if any(not isinstance(c, dict) for c in rows):
                raise Blocked("invalid_check_row")
            checks.extend(rows)
            if len(checks) >= total:
                break
            if len(rows) != 100:
                raise Blocked("incomplete_checks_page")
        if total is None or len(checks) != total:
            raise Blocked("incomplete_checks")
        identities = [c.get("id") for c in checks]
        if any(type(n) is not int or n <= 0 for n in identities) or len(set(identities)) != len(identities):
            raise Blocked("invalid_check_identity")
        if any(c.get("head_sha") not in (None, first_sha) for c in checks):
            raise Blocked("check_head_mismatch")
        # A second, independent API read guards stale PR observations.
        again_sha, again_base = self._identify(
            self._reader.get_pull_request(request.repository, number), number
        )
        if (again_sha, again_base) != (first_sha, base_sha):
            raise Blocked("pr_changed_during_read")
        successful = sum(c.get("status") == "completed" and c.get("conclusion") == "success" for c in checks)
        failure = sum(c.get("status") == "completed" and c.get("conclusion") in
                      {"failure", "cancelled", "timed_out", "action_required"} for c in checks)
        non_success = len(checks) - successful - failure
        if not checks:
            state = "no_checks_observed"
        elif failure:
            state = "checks_failed"
        elif non_success:
            state = "checks_incomplete_or_skipped"
        else:
            state = "checks_success_jobs_unverified"
        return ModuleResult(
            capability_id=CAPABILITY,
            correlation_id=request.correlation_id,
            head_sha=first_sha,
            evidence={
                "repository": request.repository,
                "pr_number": number,
                "base_sha": base_sha,
                "check_count": len(checks),
                "checks_success": successful,
                "checks_failed": failure,
                "checks_other": non_success,
                "observation": state,
                "head_readback_stable": True,
                "merge_authorized": False,
            },
        )
