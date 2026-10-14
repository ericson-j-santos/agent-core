# Public repo cutover — acceptance and rollback

## Intended destination

A **newly created** public repository under the owner's GitHub account, provisionally named `agent-core`.

No existing private repository must be renamed, transferred, converted to public, forked publicly or mirrored with its history. Only reviewed source files in this package may enter the new repository; propose implementation by a PR rather than direct writes to main. If that repository name is unavailable, revalidate a new target before any write.

## Before first publication

1. Confirm the owner's target account, publication authorization, repository name and GitHub Free eligibility.
2. Confirm the public repository was created independently, without copying any private Git history or mirror, and initialize a harmless baseline before proposing source in a PR.
3. Verify repo identity, visibility, owner and initial empty tree by independent API readback.
4. Independently rescan exactly these text sources for secrets, credentials, private repo references, hostnames, personal data and external URLs; fail closed on any unexpected content.
5. Check Python syntax, all tests, wheel installation and imports, reproducibility/integrity manifest.
6. Publish only the reviewed source files, never the staging wheel, tests' generated caches, ZIP archives, any `.env`, secrets, or directory copied from a private repository.

## Immediately after creation

1. Confirm the resulting initial commit SHA, tree/files and GitHub Actions actually executed the `agent-core-test` job on that SHA.
2. Import the reviewed `.github/rulesets/agent-core-main.json` as an **active** branch ruleset on `main`. It is not enforced merely because its file was committed.
3. Independently read back the live ruleset and required status check name, main branch protection, no bypass, no direct writes, no force-push, no deletion, and PR requirement.
4. Execute a safe negative PR/check scenario proving that unapproved changes cannot merge and a positive PR/check scenario proving a reviewed change can merge. Do not perform destructive probes on `main`.
5. Complete a real GitHub PR E2E against the **same SHA**: observe check-runs, verify HEAD stable, verify 404 negative control and confirm no writes by the diagnostic.
6. Leave the original private orchestrator and PR #61 unchanged unless an independent migration is authorized and all its gates are met.

## Failure handling

Keep the private code unchanged. If public repository setup or rule enforcement fails, mark the new repository `UNVERIFIED`; do not merge follow-up work or delete the original. Do not force-push or delete a repository for a cleanup shortcut. Record a checkpoint in the existing GitHub issue and request only the specific permission/connection needed.

## Security note

Public visibility does not provide an open-source license. No license is included in this candidate; adding one is a separate owner decision.
