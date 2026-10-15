# Security policy

Only the latest released 0.x version receives fixes. Until a first release exists, use the default branch and report the commit SHA.

## Report a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** private reporting flow at https://github.com/carelessdept/ci-guard-mcp/security/advisories/new once private reporting is enabled by the maintainer. If that channel is unavailable, open an issue asking for a private reporting channel without including vulnerability details. Never post live credentials, exploit-ready private repository contents, or sensitive user data publicly.

Include affected versions, a minimal sanitized reproduction, impact and any suggested fix. There is no guaranteed response SLA or bounty program. A maintainer will coordinate a fix and disclosure when the report can be reproduced.

## Threat model

The tool reads local files and Git index blobs; it never evaluates repository scripts, runs package installers for the scanned project, validates tokens with providers, or uploads source. Secret values are omitted from findings. Paths and environment names remain repository-controlled data: consumers must not treat findings as assistant instructions, HTML, terminal commands or shell input. The built-in reporters escape GitHub commands and Markdown cells.

The MCP server limits tool paths to the canonical launch root, omits content from operational errors, bounds inbound messages, and skips symlinks during file collection. This is not an operating-system sandbox, nor does it defend against concurrent file replacement by a malicious local user. Only launch it on repository content you are authorized to read. Configuration can disable detectors and ignore paths; review policy changes as carefully as source changes.

Heuristics can miss secrets and unsafe code. Test/template exclusions, ignored paths, file-size limits and binary-file skipping reduce coverage. Consult the README before using results as a CI gate. If a credential is discovered, revoke it with its issuer immediately and assess history and access logs; deleting the file alone does not revoke it.

The GitHub Action downloads locked build dependencies with scripts disabled. Release publishing uses GitHub OIDC rather than a stored npm token after trusted-publisher setup. Keep action consumers pinned to a reviewed commit SHA.
