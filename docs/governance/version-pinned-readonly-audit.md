# Governance audit without long-lived Administration:write credentials

## Why a simple read-only token is not sufficient

The official GitHub REST endpoint for a repository ruleset **omits**
`bypass_actors` when the requesting identity lacks **write access to the
ruleset**. Repository `Administration:read` alone cannot prove bypass is empty.
Do not silently interpret an omitted field as `[]`.

The original post-merge check at [run #38604135772](https://github.com/ericson-j-santos/agent-core/actions/runs/38604135772)
ran at `main@4a0a2f7053b4d7ab27188f8987086682033c2998` with
administrative visibility, verifying a single active ruleset `25099330`,
`bypass_actors=[]`, the exact required `agent-core-test`, strict checks,
pull-request requirement and no force-push or deletion.

## Version-pinned attestation

`config/governance/ruleset-attestation-v1.json` stores only public,
non-secret facts from that verification: ruleset ID, GitHub-maintained
`updated_at` and trusted evidence IDs, with the known-empty bypass list.
A no-admin audit:

1. Reads the current GitHub repository, main SHA and live ruleset inventory.
2. Rejects absent, duplicate, renamed, retargeted, disabled or replaced rulesets.
3. Requires the live summary **and** details to return the identical
   `updated_at` and ID from the privileged attestation.
4. Independently validates the effective required rules through the official
   GitHub API and rereads the SHA and ruleset version.
5. If `bypass_actors` is visible, checks it live. Otherwise, treats the pinned
   empty bypass list as **historical evidence of an unchanged version**, not as
   a new live observation.

Any modification to the ruleset is expected to change GitHub's `updated_at`.
Changes, unknown timestamps, hidden/missing effective rules or API permission
errors fail closed. This check is a *drift-detection compensating control*,
not equivalent to fetching hidden bypass actors live on every run. It
cannot detect a provider defect where policy changes without the provider
updating `updated_at`. Material governance changes require a new privileged
attestation, independently reviewed and pinned in a PR.

## Secure cutover

Run the [unprivileged canary](../.github/workflows/governance-attestation-canary.yml)
with the native GitHub Actions token and no admin secrets. After an
independent positive E2E on the exact SHA, replace the daily privileged
`main-server-ruleset-audit` job with this version-pinned, read-only audit and
verify the result on main. Keep `agent-core-test` required server-side.

**Only then** revoke the temporary fine-grained bootstrap PAT in GitHub and
delete `AGENT_CORE_RULESET_ADMIN_TOKEN` from repository Actions Secrets. The
GitHub connector in this chat cannot read or delete those credentials; do not
paste any credential into issues, code, logs or chat.

For deliberate ruleset updates, use the authorized administrative UI/API,
take a new privileged readback and update the attestation only after reviewing
the official rules and fresh audit evidence. Until a new baseline is reviewed,
the monitoring job must fail and development may continue in isolated branches,
but governance readiness remains blocked.

This change does not create a second task queue, service, monitoring cadence or
other repository. The existing GitHub Actions daily schedule is reused.
