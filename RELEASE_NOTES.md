# Release 0.2.0 — source candidate

This portable public-source candidate contains exactly one built-in read-only adapter (`github.pr.diagnose.v1`), versioned contracts, strict allowlist and expected-head checks, CLI, 20 local tests, private-reference guard, a GitHub-hosted CI workflow and a ruleset import template.

Evidence collected in a disposable build container includes local positive/negative/idempotent tests, syntax validation, Python wheel build, wheel inspection and isolated import. This evidence is **not** a live GitHub E2E on a future public repository and does **not** prove a ruleset is applied.

This release candidate is intended for a newly initialized public repository; packaging alone does not enforce governance or approve a merge. The existing private project retains its own historical PR and runtime. No billing change, deployment or GitHub administrative rule change is performed.
