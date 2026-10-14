"""Strict, explicit module registration; never loads plugins from untrusted text."""
from __future__ import annotations

from dataclasses import asdict
from typing import Protocol

from .contracts import Blocked, ModuleDescriptor, ModuleRequest, ModuleResult, valid_repository, valid_sha


class ReadOnlyModule(Protocol):
    descriptor: ModuleDescriptor

    def observe(self, request: ModuleRequest) -> ModuleResult: ...


class Registry:
    def __init__(self, allowed_repositories: frozenset[str]) -> None:
        if not allowed_repositories or any(not valid_repository(r) for r in allowed_repositories):
            raise Blocked("allowlist_required")
        self._allowed = allowed_repositories
        self._modules: dict[str, ReadOnlyModule] = {}

    def register(self, module: ReadOnlyModule) -> None:
        if not hasattr(module, "descriptor"):
            raise Blocked("module_missing_descriptor")
        descriptor = module.descriptor
        if not isinstance(descriptor, ModuleDescriptor):
            raise Blocked("module_missing_descriptor")
        descriptor.validate()
        if descriptor.capability_id in self._modules:
            raise Blocked("duplicate_capability")
        self._modules[descriptor.capability_id] = module

    def catalog(self) -> list[dict]:
        return [asdict(self._modules[k].descriptor) for k in sorted(self._modules)]

    def observe(self, request: ModuleRequest) -> ModuleResult:
        request.validate(self._allowed)
        module = self._modules.get(request.capability_id)
        if module is None:
            raise Blocked("capability_not_registered")
        module.descriptor.validate()  # fail closed if policy mutated since registration
        result = module.observe(request)
        if not isinstance(result, ModuleResult) or result.capability_id != request.capability_id:
            raise Blocked("invalid_module_result")
        if (result.merge_authorized is not False or result.state_changed is not False
                or result.status != "observed" or not valid_sha(result.head_sha)):
            raise Blocked("unauthorized_module_result")
        if result.correlation_id != request.correlation_id:
            raise Blocked("correlation_mismatch")
        if request.expected_head and result.head_sha != request.expected_head:
            raise Blocked("expected_head_mismatch")
        return result
