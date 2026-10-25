"""SHA-pinned, bounded GitHub PR evidence retrieval for future agentic RAG.

Read-only context pack: the question may rank trusted, operator-allowlisted
Markdown paths, but it never chooses a host, command, repository or API method.
Retrieved text is untrusted evidence, NOT instructions to the model or executor.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Protocol
from urllib.parse import quote

from .contracts import (
    Blocked, ModuleDescriptor, ModuleRequest, ModuleResult,
    valid_repository, valid_sha,
)
from .github import CAPABILITY as DIAGNOSTICS_CAPABILITY, GitHubHTTPS, GitHubPRDiagnostics

CAPABILITY = "github.pr.context.v1"
_MAX_SOURCES = 4
_MAX_READS = 3
_MAX_SOURCE_BYTES = 65_536
_MAX_SNIPPETS = 5
_MAX_SNIPPET_CHARS = 220
_WORD = re.compile(r"[a-z0-9_\u00c0-\u024f]{2,}", re.IGNORECASE)
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\Z")
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "this", "that", "what", "how",
    "are", "was", "why", "where", "para", "com", "uma", "dos", "das",
    "por", "que", "como", "qual", "quais", "sobre", "esta", "esse",
    "falha", "failed", "error",
})


def _path_allowed(path: Any) -> bool:
    if type(path) is not str:
        return False
    if path in {"README.md", "AGENTS.md"}:
        return True
    parts = path.split("/")
    if not (2 <= len(parts) <= 4 and parts[0] == "docs"
            and parts[-1].endswith(".md")):
        return False
    return all(
        bool(_SEGMENT.fullmatch(part)) and ".." not in part
        and not part.startswith(".")
        for part in parts[1:]
    )


def _words(value: str) -> set[str]:
    return {word.lower() for word in _WORD.findall(value)
            if word.lower() not in _STOPWORDS}


def _file_data(data: Any, path: str) -> tuple[str, str, str, int]:
    """Verify GitHub's blob SHA against decoded bytes, not its self-report only."""
    if (type(data) is not dict or data.get("path") != path
            or data.get("type") != "file" or data.get("encoding") != "base64"
            or type(data.get("content")) is not str
            or not valid_sha(data.get("sha"))
            or type(data.get("size")) is not int
            or not (0 <= data["size"] <= _MAX_SOURCE_BYTES)):
        raise Blocked("context_blob_metadata_invalid")
    try:
        raw = base64.b64decode(data["content"].replace("\n", ""), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise Blocked("context_blob_encoding_invalid") from None
    if len(raw) != data["size"] or "\x00" in text:
        raise Blocked("context_blob_size_or_text_invalid")
    git_blob_sha = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw
    ).hexdigest()
    if git_blob_sha != data["sha"]:
        raise Blocked("context_blob_integrity_invalid")
    return text, git_blob_sha, hashlib.sha256(raw).hexdigest(), len(raw)


class PRContextReader(Protocol):
    def get_pull_request(self, repository: str, number: int) -> dict[str, Any]: ...
    def get_check_runs(self, repository: str, sha: str, page: int) -> dict[str, Any]: ...
    def get_text_file(self, repository: str, path: str, sha: str) -> dict[str, Any]: ...


class ContextGitHubHTTPS(GitHubHTTPS):
    """Additional official GET route; does not accept arbitrary URLs or paths."""

    def get_text_file(self, repository: str, path: str, sha: str) -> dict[str, Any]:
        if not valid_repository(repository) or not _path_allowed(path) or not valid_sha(sha):
            raise Blocked("context_file_request_invalid")
        return self._get(
            "/repos/%s/contents/%s?ref=%s" % (repository, quote(path, safe="/"), sha)
        )


class GitHubPRContext:
    descriptor = ModuleDescriptor(
        module_id="github-pr-context",
        capability_id=CAPABILITY,
        version="1.0.0",
        max_risk=0,
        read_only=True,
    )

    def __init__(self, reader: PRContextReader,
                 source_paths: tuple[str, ...] = ("README.md",)) -> None:
        if (type(source_paths) is not tuple
                or not (1 <= len(source_paths) <= _MAX_SOURCES)
                or len(set(source_paths)) != len(source_paths)
                or any(not _path_allowed(path) for path in source_paths)):
            raise Blocked("context_source_allowlist_invalid")
        self._reader = reader
        self._paths = source_paths

    def observe(self, request: ModuleRequest) -> ModuleResult:
        if set(request.payload) != {"pr_number", "question"}:
            raise Blocked("context_payload_fields_invalid")
        number = request.payload["pr_number"]
        question = request.payload["question"]
        if type(number) is not int or not 0 < number <= 99_999_999:
            raise Blocked("context_pr_number_invalid")
        if (type(question) is not str or not 4 <= len(question) <= 240
                or any(ord(char) < 32 for char in question)):
            raise Blocked("context_question_invalid")
        terms = _words(question)
        if not 1 <= len(terms) <= 24:
            raise Blocked("context_query_terms_invalid")

        # Reuse the existing fail-closed PR/check observer instead of bypassing it.
        diagnostic = GitHubPRDiagnostics(self._reader).observe(ModuleRequest(
            repository=request.repository,
            capability_id=DIAGNOSTICS_CAPABILITY,
            correlation_id=request.correlation_id,
            payload={"pr_number": number},
            expected_head=request.expected_head,
        ))
        head_sha = diagnostic.head_sha
        base_sha = diagnostic.evidence["base_sha"]

        ranked_paths = sorted(
            self._paths,
            key=lambda path: (
                -len(terms & _words(path.replace("/", " "))),
                path != "README.md",
                path,
            ),
        )
        snippets: list[dict[str, Any]] = []
        sources: list[dict[str, Any]] = []
        for path in ranked_paths[:_MAX_READS]:
            body, blob_sha, sha256, size = _file_data(
                self._reader.get_text_file(request.repository, path, head_sha),
                path,
            )
            sources.append({
                "path": path, "ref_sha": head_sha, "blob_sha": blob_sha,
                "sha256": sha256, "bytes": size,
            })
            for number_line, line in enumerate(body.splitlines(), start=1):
                line = line.strip()
                matches = len(terms & _words(line))
                if matches and line:
                    snippets.append({
                        "path": path, "line": number_line,
                        "score": matches,
                        "excerpt": line[:_MAX_SNIPPET_CHARS],
                        "url": "https://github.com/%s/blob/%s/%s#L%d" % (
                            request.repository, head_sha, quote(path, safe="/"),
                            number_line,
                        ),
                        "untrusted_source_text": True,
                    })
            # Bounded second-step retrieval if the first source was insufficient.
            if len(snippets) >= 3 and max(s["score"] for s in snippets) >= 2:
                break

        observed = self._reader.get_pull_request(request.repository, number)
        seen_head, seen_base = GitHubPRDiagnostics._identify(observed, number)
        if (seen_head, seen_base) != (head_sha, base_sha):
            raise Blocked("context_pr_changed_during_retrieval")
        head_repo = observed.get("head", {}).get("repo")
        if isinstance(head_repo, dict) and head_repo.get("full_name") != request.repository:
            raise Blocked("context_cross_repository_head")

        ranked_snippets = sorted(
            snippets, key=lambda item: (-item["score"], item["path"], item["line"])
        )[:_MAX_SNIPPETS]
        return ModuleResult(
            capability_id=CAPABILITY,
            correlation_id=request.correlation_id,
            head_sha=head_sha,
            evidence={
                "repository": request.repository,
                "pr_number": number,
                "base_sha": base_sha,
                "retrieval_state": "matched" if ranked_snippets else "insufficient_evidence",
                "question_terms": sorted(terms),
                "sources": sources,
                "snippets": ranked_snippets,
                "github_checks": dict(diagnostic.evidence),
                "pr_head_readback_stable": True,
                "retrieved_content_is_untrusted": True,
                "execution_authorized": False,
            },
        )
