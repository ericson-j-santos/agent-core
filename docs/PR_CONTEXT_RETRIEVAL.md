# SHA-pinned PR context retrieval — foundation for Agentic RAG

## Scope and status

Capability: \`github.pr.context.v1\`, **read-only** (risk 0).

This is a bounded retrieval component, **not** a complete Agentic RAG agent,
vector search service, GitHub log reader, autonomous model, code editor or
replacement for the Worker Pool. It augments the existing PR/check diagnostics
with evidence excerpts from a small, explicitly selected set of Markdown
documents at the **same PR head SHA**.

A caller may ask a question to prioritize retrieval. The question cannot
choose commands, tools, API hosts, paths outside the operator allowlist or a
repository outside \`AGENT_CORE_ALLOWED_REPOS\`. Retrieved text is untrusted,
including instructions that may appear inside the source itself.

## Existing parts reused

- \`GitHubPRDiagnostics\`: real PR head/base and check-run snapshot, with
  independent reread and fail-closed outcomes.
- \`GitHubHTTPS\`: fixed official GitHub HTTPS origin, GET-only, no redirects
  and bounded response sizes.
- \`Registry\`, \`ModuleRequest\` and \`ModuleResult\`: versioned risk-0
  capability admission, repository allowlist, expected head and no writes.

## Source contract and planning

1. Require exact PR number, question, expected head SHA and repository allowlist.
2. Diagnose PR/check-runs through the pre-existing module.
3. Restrict source paths to \`README.md\`, \`AGENTS.md\` or Markdown below
   \`docs/\`. Only explicitly supplied paths are eligible; no search of
   arbitrary files or implicit traversal of an entire repository.
4. Prioritize paths matching question terms. Read at most three of up to four
   configured paths. If evidence remains weak, read another bounded source.
5. For every source, enforce the requested commit SHA, exact path, UTF-8,
   64-KiB cap, Git blob SHA integrity and an independent SHA-256 receipt.
6. Return up to five lexical matches, capped to 220 characters per excerpt,
   each with line number and immutable GitHub source link.
7. Re-read the PR head/base from the official API after retrieval and fail
   closed if they changed.

If no matching lines are found, report \`insufficient_evidence\` rather than
invent an answer. Check-run status is a snapshot; success does not attest
execution of every job or authorize merge. No content is interpreted as an
instruction to execute.

## Operator usage

After the normal operational preflight (when running on governed hosts), and
with a repository allowlisted by the operator:

\`\`\`text
AGENT_CORE_ALLOWED_REPOS=owner/repository
python -m agent_core research-pr --repository owner/repository \
  --number 123 --expected-head <40-char-PR-head-SHA> \
  --question "What CI evidence explains this failure?" \
  --sources README.md docs/CI.md
\`\`\`

A GitHub token is optional only for public resources; private resources require
existing approved \`GITHUB_TOKEN\` configuration. Do not put tokens in command
arguments or responses. This command does not invoke Ollama or a worker and
does not write to GitHub.

## Validation gates

Unit tests must cover positive retrieval, SHA-pinned blob integrity,
torn/stale PR readback, insufficient evidence, unsafe path rejection,
source bounds, prompt-injection-as-data, token-safe transport, repeatability
and the actual CLI module path. For a PR, GitHub Actions runs a real read-only
call to the official API at that PR's HEAD and a negative 404 control.
Check job execution and SHA before declaring it validated.

## Deferred integration

The Engineering Worker Pool may later consume this JSON evidence as
**untrusted context only**, under a specific capability contract and input
budget. The model must not treat retrieved excerpts as instructions or as
authorization to edit code. Any integration with Ollama, task dispatch,
CAS/patch persistence, Validator, draft PR, replay and actual hardware
requires separate authorized E2E evidence. None is certified by this module.
