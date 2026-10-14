# Security policy (release candidate)

This package uses read-only GitHub API requests for one allowlisted repository per request. Never commit access tokens, secret names/values, private repository content, user data, workspace dumps, binary artifacts, host inventory, or operational credentials to the public repository.

All capability changes must remain risk-0 and read-only until a separate governed review and E2E authorizes an explicit additional capability. The module registry intentionally rejects mutating descriptors.

Reports should be shared through a private security channel rather than a public issue if they contain a vulnerability or credential. A public GitHub repository does not imply that historical/private source material may be mirrored there.
