"""Minimal CLI with explicit capability and repository admission."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from .contracts import Blocked, ModuleRequest, valid_repository
from .github import CAPABILITY, GitHubHTTPS, GitHubPRDiagnostics
from .registry import Registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-core")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("list-modules")
    diagnose = commands.add_parser("diagnose-pr")
    diagnose.add_argument("--repository", required=True)
    diagnose.add_argument("--number", required=True, type=int)
    diagnose.add_argument("--expected-head")
    args = parser.parse_args(argv)
    try:
        if args.action == "list-modules":
            print(json.dumps([asdict(GitHubPRDiagnostics.descriptor)], sort_keys=True))
            return 0
        allowed = frozenset(filter(None, (s.strip() for s in os.environ.get("AGENT_CORE_ALLOWED_REPOS", "").split(","))))
        if not allowed or any(not valid_repository(repo) for repo in allowed):
            raise Blocked("allowlist_not_configured")
        token = os.environ.get("GITHUB_TOKEN") or None
        registry = Registry(allowed)
        registry.register(GitHubPRDiagnostics(GitHubHTTPS(token)))
        observation = registry.observe(ModuleRequest(
            repository=args.repository,
            capability_id=CAPABILITY,
            correlation_id="read-pr-%d" % args.number,
            payload={"pr_number": args.number},
            expected_head=args.expected_head,
        ))
        print(json.dumps(asdict(observation), sort_keys=True))
        return 0
    except Blocked as exc:
        print(json.dumps({"status": "blocked", "reason_code": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
