# Portable Agent Core

A generic, read-only agent module foundation. It does **not** copy the source history, workflows, credentials, user data, environment identifiers, or runtime internals of another repository.

This repository is a **public-source project** intended for independently governed pull requests. Its source is published by reviewed commits; the required branch ruleset must be applied separately and verified on GitHub.

## Scope

The initial capability `github.pr.diagnose.v1` reads the current pull request and check-runs through GitHub's official HTTPS API and confirms the same head SHA in a second independent read. It never writes to repositories or issues, merges code, deploys, creates a task queue, allocates a worker, or executes shell commands from input data. A green check is not evidence that the jobs executed or that merge is authorized.

The module registry admits only explicitly registered, versioned, read-only, risk-0 capabilities. There is no dynamic plugin loading from user inputs or GitHub comments. The code has no dependency on Ollama, Docker, a workstation, or an existing private orchestrator.

## Quick checks

With Python 3.11+, the offline module catalog does not require an account:

```text
python -m agent_core list-modules
```

For an authorized read-only diagnostic, the **operator** configures a repository allowlist in `AGENT_CORE_ALLOWED_REPOS` and may supply an official GitHub token through the CI secret environment `GITHUB_TOKEN`. Run the `diagnose-pr` CLI with a repository, PR number, and expected head SHA. Do not print or commit tokens, workflow credentials, or response bodies.

Run verification through GitHub Actions CI or the local `unittest` suite. The Python project can also be built as a wheel; the workflow validates its contents.

## Governance and extraction boundary

The source is a **fresh, generic implementation** based on the stable capability and read-only contracts. No entire private repository clone, issue body, run log, identity-specific control issue, host name, path, Docker configuration, private GitHub URL, or archived Git history is included.

The JSON template at `.github/rulesets/agent-core-main.json` does **not** activate a rule automatically. After the public repository exists, an authorized repository administrator must import/configure the rule through GitHub and independently confirm that the `agent-core-test` check was actually run and is required before merging, that direct writes, force pushes and deletions are rejected, and that the expected branch/identity apply. CI alone does not prove server-side branch enforcement.

GitHub Free permits protection of public repositories; this package does not alter the visibility of any existing private repository. A public repository does **not** automatically grant a permissive open-source license. No license is provided until its owner explicitly selects one.

## Deferred modules

Integrations with external task trackers, execution pools, managed hosts or language models require separate versioned capabilities, isolation, authorization, concurrency control, recovery evidence and end-to-end testing. This read-only package is not a fully autonomous assistant.

## Validation boundaries

- Unit and local transport tests: included.
- GitHub Actions real PR E2E + HTTP 404 negative control: configured, requires **running on the new public repository**.
- Merge, deployment, repository creation, protection enforcement and live remote worker execution: **not part of this release candidate**.
