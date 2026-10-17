# ci-guard-mcp

[![CI](https://github.com/carelessdept/ci-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/carelessdept/ci-guard-mcp/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/ci-guard-mcp.svg)](https://www.npmjs.com/package/ci-guard-mcp)
[![ci-guard-mcp MCP server](https://glama.ai/mcp/servers/carelessdept/ci-guard-mcp/badges/score.svg)](https://glama.ai/mcp/servers/carelessdept/ci-guard-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**One local audit engine. A CLI, a GitHub Action, and four MCP tools.**

Catch risky GitHub workflows, undocumented environment variables, possible credentials, and conflicting dependency configuration before merging. Audits are deterministic, read-only, and run without sending source code to a service. Two runtime dependencies: `yaml` and `ignore`.

## Run locally

Requires Node.js 20 or later. Git is required for index scans and tracked-file selection.

```sh
# Run directly with npx:
npx ci-guard-mcp scan . --fail-on warn
npx ci-guard-mcp scan . --format json
npx ci-guard-mcp scan . --format sarif > findings.sarif
npx ci-guard-mcp scan . --auditor workflows --auditor lockfile
npx ci-guard-mcp scan . --auditor secrets --staged
npx ci-guard-mcp scan . --auditor secrets --include-ignored

# Or from a local source checkout:
npm ci --ignore-scripts
npm run build
node dist/cli.js scan .
```

Exit codes: **0** below threshold, **1** findings at or above threshold, **2** invalid arguments, configuration or I/O failure. `--fail-on error` is the default; `warn` also fails on warnings. Informational findings never fail a scan. Output formats are `text`, `json`, `sarif`, and `github`. `--root PATH` is equivalent to the positional scan directory. `--include-ignored` audits tracked files even when they match `.gitignore` rules (for example, a `.env` committed before `.gitignore` was added). `--help` lists every flag.

Staged mode is intentionally limited to secrets: it reads entire changed index blobs, including renamed/added files, so unstaged edits cannot conceal a staged credential. It applies ignore rules from the index and skips deletions, symlinks and submodules. Other audits need the repository-wide context and cannot be combined with `--staged`.

## GitHub Action

After this repository is published, use a reviewed full commit SHA in place of `FULL_COMMIT_SHA`:

```yaml
name: Repository audit
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: carelessdept/ci-guard-mcp@FULL_COMMIT_SHA
        id: guard
        with:
          path: .
          fail-on: warn
```

Inputs: `path` (default `.`), `fail-on` (`error` or `warn`, default `error`). Outputs: `errors`, `warnings`, `findings` as decimal counts. Outputs and the Markdown job summary are written before the finding threshold is evaluated. Findings become escaped workflow annotations; a failed audit exits the action with status 1. Operational failure exits 2 and does not claim complete counts.

This composite action installs its locked build dependencies with lifecycle scripts disabled into a runner-temp directory and runs the compiled CLI. It requires npm registry access, Bash, and a runner compatible with `actions/setup-node@v4`. The scanned repository's dependencies and scripts are never installed or executed. The self-audit workflow runs the local action and verifies its outputs. Run the CLI separately with `--format sarif` when uploading to a code-scanning service; the action itself does not upload reports or request write permissions.

## MCP server

The stdio server uses newline-delimited JSON-RPC 2.0, negotiates MCP versions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`, and implements initialization, ping, tool discovery, tool calls and silent notifications. A client must send `notifications/initialized` after initialization. No network transport or credentials are needed.

Example MCP client configuration after npm publication:

```json
{
  "mcpServers": {
    "ci-guard": {
      "command": "npx",
      "args": ["--yes", "ci-guard-mcp", "--mcp", "--root", "/absolute/path/to/repository"]
    }
  }
}
```

For a source checkout, use `"command": "node"` and `"args": ["/absolute/path/to/ci-guard-mcp/dist/cli.js", "--mcp", "--root", "/absolute/path/to/repository"]`.

| Tool | Behavior | Arguments |
| --- | --- | --- |
| `scan_repo` | All four auditors | `path?: string`, `includeIgnored?: boolean` |
| `check_env_drift` | Environment and deployment drift | `path?: string` |
| `audit_github_workflows` | Workflow security | `path?: string` |
| `check_secret_leaks` | Redacted credential findings | `path?: string`, `staged?: boolean`, `includeIgnored?: boolean` |

Paths resolve inside the launch root; parent traversal and symlinks escaping it are rejected. Responses contain text JSON plus `structuredContent` with the same report. Invalid tool arguments are JSON-RPC errors; execution failures use `isError: true`. Stdout contains only protocol messages. Frames over 1 MiB are rejected, and the server recovers at the next newline. Requests are serialized to keep memory use and ordering predictable; scans complete before the next queued request, so cancellation notifications do not interrupt an active audit.

## Audit rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `workflow/pwn-request` | error | `pull_request_target` checkout with event-derived PR head ref/repository |
| `workflow/script-injection` | error | GitHub event/head-ref expressions directly interpolated in `run` |
| `workflow/unpinned-action` | warn | Remote actions/reusable workflows without 40-character SHAs; container actions without sha256 digests |
| `workflow/missing-permissions` | warn | Missing top-level `permissions` |
| `workflow/invalid-yaml` | error | Malformed workflow YAML, duplicate keys or non-mapping document |
| `env/undocumented` | warn | Literal source references absent from `.env.example` / `.env.template` |
| `env/dead-template` | info | Template declarations without detected source or deployment use |
| `env/invalid-compose` | error | Malformed Compose YAML |
| `secret/aws`, `secret/github`, `secret/stripe`, `secret/openai`, `secret/anthropic`, `secret/slack`, `secret/private-key` | error | Recognizable credential shapes/private-key headers |
| `secret/high-entropy` | error | High-entropy quoted assignments to credential-like names |
| `lockfile/conflict` | error | Multiple recognized package-manager lockfiles in the same directory |
| `lockfile/insecure-http` | error | HTTP URLs in text lockfiles |
| `lockfile/unbounded-version` | warn | `*`, `latest`, and npm aliases to them in dependency sections |
| `lockfile/invalid-package` | error | Invalid JSON package manifests |
| `scan/skipped-file` | warn | Files exceeding the configured size limit |

Environment patterns support `process.env.X`, bracket syntax, `import.meta.env.X`, Python `os.environ[...]` / `.get(...)` / `os.getenv(...)`, Go `os.Getenv(...)`, and Rust `std::env::var(...)` / `env::var(...)`. Templates and declarations are aggregated across the scan root. Docker `ENV` and Compose `environment` entries count as consumers; deployment-only variables still require documentation when source references them. Tests/fixtures are excluded from source reference extraction.

Secrets use known prefixes and contextual entropy (at least 24 characters, Shannon entropy ≥4.3 bits/character). Values and source snippets are never included in findings, SARIF or MCP results. In a Git root, normal secret audits read tracked working-tree files; untracked files are skipped. Without Git, all eligible files are scanned. Other auditors include untracked files. `.gitignore` and nested ignore rules are respected by default (pass `--include-ignored` or `includeIgnored: true` to force-scan tracked files matching `.gitignore`), alongside built-in dependency/build-directory exclusions. Symlinks and NUL-containing binary files are skipped.

## Configuration

Use `.ciguardrc.json` or `package.json`'s `ciguard` object. The rc file takes precedence. Unknown keys and invalid types fail explicitly. Arrays replace defaults rather than merging. Patterns in `ignore` and `secretIgnore` use gitignore syntax relative to the scan root.

```json
{
  "ignore": ["generated/"],
  "allowActions": ["actions/*"],
  "ignoreEnv": ["NODE_ENV", "CI", "PATH", "HOME"],
  "secretIgnore": ["test/", "tests/", "__tests__/", "fixtures/", "__fixtures__/", "*.test.*", "*.spec.*", ".env.example", ".env.template"],
  "disabledRules": [],
  "maxFileBytes": 1048576
}
```

By default `allowActions` is empty: official actions also require immutable pins. Set `actions/*` explicitly to permit mutable official references, or list exact identities such as `actions/checkout`. `maxFileBytes` accepts 1 KiB–16 MiB; oversized text files produce warnings, which cannot be suppressed through `disabledRules`. The repository's own config excludes `docs/` because the landing page contains instructional examples and adds GitHub's two runtime output variables to `ignoreEnv`.

## SDK

```ts
import { scan, formatSarif } from 'ci-guard-mcp';
const report = await scan({ root: '/path/to/repo', auditors: ['workflows', 'secrets'] });
console.log(report.summary);
const sarif = formatSarif(report);
```

Named auditor functions accept `{ files: [{ path, content }], config }` for in-memory integrations. SDK `config` overrides file configuration. Reports contain version, findings, counts and files scanned; no timestamp or absolute root is included, allowing stable snapshots. `filesScanned` counts eligible text files collected, including files not relevant to a selected auditor.

## Boundaries and limitations

This is a static heuristic auditor, not a proof of security or a credential validity checker. It does not execute code, resolve computed environment names, follow calls across files, inspect Git history, decrypt files, audit remote reusable workflow bodies, or analyze dependency vulnerabilities. YAML workflow checks inspect local structured steps and job-level reusable workflow references. Event-derived values passed through intermediate expressions or files can evade direct interpolation checks. Literal environment patterns can match commented examples or strings. Dead-template notices are advisory because external consumers and dynamic reads are invisible.

Default secret exclusions deliberately reduce noise in tests/templates; replace `secretIgnore` with `[]` for broader coverage. Synthetic tokens that look real can still be reported, and unknown/low-entropy/encoded credentials can be missed. Tracked files ignored by `.gitignore` are excluded in a normal scan unless `--include-ignored` (`includeIgnored: true`) is passed. Binary lockfiles are skipped as binary content. Package-specific environment scopes are not inferred; scan a package directory separately for isolated drift checks. Repository configuration is trusted local policy, so review config and ignore changes in pull requests. Do not use the MCP launch root as an OS-level sandbox against a concurrently malicious local process.

## Development and release

```sh
npm ci --ignore-scripts
npm run check
node dist/cli.js scan --fail-on warn
npm pack --dry-run
```

CI runs tests/typechecks/build/package checks on Node 20 and 22 across Linux, macOS and Windows. See [CONTRIBUTING.md](CONTRIBUTING.md) for regression tests and [SECURITY.md](SECURITY.md) for disclosure.

MIT licensed. Maintained openly through reproducible reports, focused changes and documented limitations.

Protocol references: [MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
