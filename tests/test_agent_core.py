"""Portable contract tests; all upstream repository data is synthetic."""
from __future__ import annotations

import contextlib
import io
import json
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from agent_core.__main__ import main
from agent_core.contracts import Blocked, ModuleDescriptor, ModuleRequest, ModuleResult
from agent_core.github import CAPABILITY, GitHubPRDiagnostics, GitHubHTTPS
from agent_core.registry import Registry

REPO = "example-team/generic-project"
HEAD = "a" * 40
BASE = "b" * 40


class SyntheticReader:
    def __init__(self):
        self.posts = 0
        self.pr_reads = 0
        self.check_reads = 0
        self.changing_sha = False
        self.checks = [{"id": 701, "head_sha": HEAD, "status": "completed", "conclusion": "success"},
                       {"id": 702, "head_sha": HEAD, "status": "completed", "conclusion": "failure"}]
        self.invalid_total = None

    def get_pull_request(self, repository, number):
        assert repository == REPO and number == 42
        self.pr_reads += 1
        actual = "f" * 40 if self.changing_sha and self.pr_reads > 1 else HEAD
        return {"number": number, "head": {"sha": actual}, "base": {"sha": BASE}}

    def get_check_runs(self, repository, sha, page):
        assert repository == REPO and sha == HEAD
        self.check_reads += 1
        return {"total_count": self.invalid_total if self.invalid_total is not None else len(self.checks),
                "check_runs": self.checks[(page - 1) * 100:page * 100]}


def req(**kw):
    data = {"repository": REPO, "capability_id": CAPABILITY,
            "correlation_id": "test-correlation-v01", "payload": {"pr_number": 42},
            "expected_head": HEAD}
    data.update(kw)
    return ModuleRequest(**data)


def registry(reader=None):
    r = Registry(frozenset({REPO}))
    r.register(GitHubPRDiagnostics(reader or SyntheticReader()))
    return r


class Contracts(unittest.TestCase):
    def test_success_real_adapter_contract(self):
        reader = SyntheticReader()
        outcome = registry(reader).observe(req())
        self.assertEqual(outcome.head_sha, HEAD)
        self.assertEqual(outcome.evidence["observation"], "checks_failed")
        self.assertFalse(outcome.merge_authorized)
        self.assertFalse(outcome.state_changed)
        self.assertEqual(reader.pr_reads, 2)
        self.assertEqual(reader.check_reads, 1)
        self.assertEqual(reader.posts, 0)

    def test_replay_read_only_and_repeatable(self):
        reader = SyntheticReader()
        r = registry(reader)
        self.assertEqual(r.observe(req()), r.observe(req()))
        self.assertEqual(reader.pr_reads, 4)
        self.assertEqual(reader.posts, 0)

    def test_denies_invalid_entries_before_read(self):
        changes = [
            {"repository": "someone-else/other-repo"},
            {"repository": "../../escape"},
            {"capability_id": "git.commit.force.v1"},
            {"risk": True}, {"risk": 1}, {"risk": -1},
            {"expected_head": "wrong"},
            {"correlation_id": "short"},
            {"version": "untrusted-version"},
            {"payload": {"pr_number": "42"}},
            {"payload": {"pr_number": 42, "command": "unknown"}},
            {"payload": {"pr_number": 0}},
            {"payload": {"pr_number": 100_000_000}},
        ]
        for change in changes:
            with self.subTest(change=change):
                reader = SyntheticReader()
                with self.assertRaises(Blocked):
                    registry(reader).observe(req(**change))
                self.assertEqual(reader.pr_reads, 0)

    def test_unknown_expected_head_denied(self):
        reader = SyntheticReader()
        with self.assertRaisesRegex(Blocked, "expected_head_mismatch"):
            registry(reader).observe(req(expected_head="e" * 40))
        self.assertEqual(reader.check_reads, 0)

    def test_change_during_fetch_denied(self):
        reader = SyntheticReader()
        reader.changing_sha = True
        with self.assertRaisesRegex(Blocked, "pr_changed_during_read"):
            registry(reader).observe(req())
        self.assertEqual(reader.posts, 0)

    def test_duplicate_module_denied(self):
        reader = SyntheticReader()
        r = registry(reader)
        with self.assertRaisesRegex(Blocked, "duplicate_capability"):
            r.register(GitHubPRDiagnostics(reader))

    def test_registration_denies_write_permission(self):
        class Unsafe:
            descriptor = replace(GitHubPRDiagnostics.descriptor, read_only=False)
            def observe(self, _):
                raise AssertionError("must not execute")
        r = Registry(frozenset({REPO}))
        with self.assertRaisesRegex(Blocked, "invalid_module_descriptor"):
            r.register(Unsafe())

    def test_registration_denies_empty_allowlist(self):
        for allowed in (frozenset(), frozenset({"../invalid"})):
            with self.assertRaises(Blocked):
                Registry(allowed)

    def test_skipped_and_absent_checks_not_pass(self):
        for checks, expected in ([{"id": 700, "status": "completed", "conclusion": "skipped"}], "checks_incomplete_or_skipped"), ([], "no_checks_observed"):
            with self.subTest(expected=expected):
                reader = SyntheticReader()
                reader.checks = checks
                observed = registry(reader).observe(req())
                self.assertEqual(observed.evidence["observation"], expected)
                self.assertFalse(observed.merge_authorized)

    def test_succeeded_checks_do_not_authorize_merge(self):
        reader = SyntheticReader()
        reader.checks = [{"id": 42, "status": "completed", "conclusion": "success"}]
        observed = registry(reader).observe(req())
        self.assertEqual(observed.evidence["observation"], "checks_success_jobs_unverified")
        self.assertFalse(observed.merge_authorized)

    def test_check_id_duplicates_and_sha_mismatch(self):
        for checks in ([{"id": 1}, {"id": 1}],
                       [{"id": 1, "head_sha": "c" * 40, "status": "completed", "conclusion": "success"}]):
            reader = SyntheticReader()
            reader.checks = checks
            with self.assertRaises(Blocked):
                registry(reader).observe(req())

    def test_bounded_pagination(self):
        reader = SyntheticReader()
        reader.invalid_total = 1001
        with self.assertRaisesRegex(Blocked, "unbounded"):
            registry(reader).observe(req())
        reader = SyntheticReader()
        reader.invalid_total = 5
        with self.assertRaisesRegex(Blocked, "incomplete_checks_page"):
            registry(reader).observe(req())

    def test_result_failclosed(self):
        class Forged:
            descriptor = GitHubPRDiagnostics.descriptor
            def observe(self, request):
                return ModuleResult(capability_id=CAPABILITY, correlation_id=request.correlation_id,
                                    head_sha=HEAD, evidence={}, merge_authorized=True)
        r = Registry(frozenset({REPO}))
        r.register(Forged())
        with self.assertRaisesRegex(Blocked, "unauthorized_module_result"):
            r.observe(req())

    def test_offline_catalog_does_not_require_env_or_token(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            self.assertEqual(main(["list-modules"]), 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data[0]["capability_id"], CAPABILITY)

    def test_local_cli_e2e_through_registry_adapter(self):
        reader = SyntheticReader()
        output = io.StringIO()
        with (patch.dict(os.environ, {"AGENT_CORE_ALLOWED_REPOS": REPO}, clear=True),
              patch("agent_core.__main__.GitHubHTTPS", return_value=reader),
              contextlib.redirect_stdout(output)):
            rc = main(["diagnose-pr", "--repository", REPO, "--number", "42",
                       "--expected-head", HEAD])
        self.assertEqual(rc, 0)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["head_sha"], HEAD)
        self.assertFalse(receipt["merge_authorized"])
        self.assertFalse(receipt["state_changed"])
        self.assertEqual(reader.pr_reads, 2)
        self.assertEqual(reader.posts, 0)

    def test_local_cli_negative_blocks_sha_drift(self):
        reader = SyntheticReader()
        output = io.StringIO()
        with (patch.dict(os.environ, {"AGENT_CORE_ALLOWED_REPOS": REPO}, clear=True),
              patch("agent_core.__main__.GitHubHTTPS", return_value=reader),
              contextlib.redirect_stdout(output)):
            rc = main(["diagnose-pr", "--repository", REPO, "--number", "42",
                       "--expected-head", "e" * 40])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output.getvalue())["reason_code"], "expected_head_mismatch")
        self.assertEqual(reader.check_reads, 0)
        self.assertEqual(reader.posts, 0)

    def test_cli_denies_unconfigured_allowlist(self):
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            self.assertEqual(main(["diagnose-pr", "--repository", REPO, "--number", "42"]), 2)
        self.assertEqual(json.loads(output.getvalue())["reason_code"], "allowlist_not_configured")


class Transport(unittest.TestCase):
    def test_official_origin_read_only(self):
        requests = []
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, *_): return b'{"number":42}'
        class FakeOpener:
            def open(self, request, timeout):
                requests.append(request)
                return FakeResponse()
        client = GitHubHTTPS()
        client._opener = FakeOpener()
        self.assertEqual(client.get_pull_request(REPO, 42)["number"], 42)
        self.assertEqual(requests[0].get_method(), "GET")
        self.assertEqual(requests[0].full_url, "https://api.github.com/repos/" + REPO + "/pulls/42")
        self.assertFalse(requests[0].has_header("Authorization"))

    def test_transport_denies_exposed_token_in_exception(self):
        class FakeOpener:
            def open(self, *args, **kwargs):
                raise OSError("unsafe server diagnostic token=SECRET")
        client = GitHubHTTPS("SECRET")
        client._opener = FakeOpener()
        with self.assertRaises(Blocked) as exc:
            client.get_pull_request(REPO, 42)
        self.assertEqual(str(exc.exception), "github_transport_failure")
        self.assertNotIn("SECRET", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
