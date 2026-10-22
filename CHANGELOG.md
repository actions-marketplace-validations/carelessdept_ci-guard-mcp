# Changelog

Changes are recorded here by released version. Versions follow Semantic Versioning; pre-1.0 breaking changes may occur in minor releases.

## 0.2.0

- **OS-boundary egress-deny sandbox & runtime zero-network lockdown (`--sandbox`, `--no-git`)**: Added `src/sandbox.ts` enforcing Seatbelt (`sandbox-exec -p '(version 1)(allow default)(deny network*)'` on macOS) and network namespace isolation (`unshare -r -n` on Linux) alongside in-process socket/fetch/DNS lockdown (`ERR_CI_GUARD_NETWORK_DISABLED`), plus `--no-git` pure filesystem scanning with zero child processes.
- **GitLab CI (`.gitlab-ci.yml`, `.gitlab/ci/*.yml`) auditing**: Added detection for untrusted Merge Request / commit variable shell injection (`workflow/script-injection`), untrusted MR head checkouts (`workflow/pwn-request`), and unpinned `include:` / `component:` / `image:` references (`workflow/unpinned-action`).
- **Workflow secret log exfiltration detection (`workflow/secret-exfiltration`)**: Detects direct `${{ secrets.* }}` and `${{ toJSON(secrets) }}` interpolation inside `run:` shell scripts.
- **Golden clean-repo false-positive regression benchmark suite**: Added comprehensive clean multi-auditor repository benchmarks asserting zero false positives across hardened GitHub Actions, GitLab CI, `.env.example`, Compose, and lockfiles.

## 0.1.0

- Four static auditors for workflow security, environment drift, recognizable/contextual secrets and package lockfile hygiene.
- CLI with text, JSON, SARIF 2.1.0 and GitHub annotation/summary reporting, selectable auditors and severity gates.
- Git index scanning for staged secrets, redacted findings, nested ignore handling and file-size diagnostics.
- Read-only stdio MCP server with four tools, initialization/version negotiation, input validation and launch-root confinement.
- Composite GitHub Action with three count outputs, source-built locked runtime and self-audit workflow.
- Node 20/22 platform matrix, tag-driven OIDC npm publishing workflow, contribution and disclosure policies, and documentation site.
