"""Versioned, read-only contracts for an independently deployable Agent Core."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

REQUEST_VERSION = "agent-core/request-v1"
RESULT_VERSION = "agent-core/result-v1"
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,98}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_CORRELATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{5,127}\Z")
_CAPABILITY = re.compile(r"[a-z][a-z0-9]*(?:[.][a-z][a-z0-9]*)+[.]v[1-9][0-9]*\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class Blocked(ValueError):
    """Fail-closed policy violation; safe reason codes only."""


def valid_repository(value: str) -> bool:
    return isinstance(value, str) and bool(_REPOSITORY.fullmatch(value)) and ".." not in value


def valid_sha(value: str) -> bool:
    return isinstance(value, str) and bool(_SHA.fullmatch(value))


@dataclass(frozen=True)
class ModuleDescriptor:
    module_id: str
    capability_id: str
    version: str
    max_risk: int
    read_only: bool

    def validate(self) -> None:
        if (not isinstance(self.module_id, str)
                or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", self.module_id)
                or not isinstance(self.capability_id, str)
                or not _CAPABILITY.fullmatch(self.capability_id)
                or not isinstance(self.version, str)
                or not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", self.version)
                or type(self.max_risk) is not int or self.max_risk != 0
                or self.read_only is not True):
            raise Blocked("invalid_module_descriptor")


@dataclass(frozen=True)
class ModuleRequest:
    repository: str
    capability_id: str
    correlation_id: str
    payload: Mapping[str, Any]
    expected_head: str | None = None
    risk: int = 0
    version: str = REQUEST_VERSION

    def validate(self, allowed_repositories: frozenset[str]) -> None:
        if self.version != REQUEST_VERSION:
            raise Blocked("request_contract_mismatch")
        if not valid_repository(self.repository) or self.repository not in allowed_repositories:
            raise Blocked("repository_not_allowlisted")
        if not isinstance(self.capability_id, str) or not _CAPABILITY.fullmatch(self.capability_id):
            raise Blocked("invalid_capability")
        if not isinstance(self.correlation_id, str) or not _CORRELATION.fullmatch(self.correlation_id):
            raise Blocked("invalid_correlation")
        if type(self.risk) is not int or self.risk != 0:
            raise Blocked("risk_not_permitted")
        if self.expected_head is not None and not valid_sha(self.expected_head):
            raise Blocked("invalid_expected_head")
        if not isinstance(self.payload, Mapping):
            raise Blocked("invalid_payload")


@dataclass(frozen=True)
class ModuleResult:
    capability_id: str
    correlation_id: str
    head_sha: str
    evidence: Mapping[str, Any]
    status: str = "observed"
    version: str = RESULT_VERSION
    merge_authorized: bool = False
    state_changed: bool = False
