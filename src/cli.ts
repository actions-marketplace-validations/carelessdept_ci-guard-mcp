#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { scan } from './index.js';
import { serveStdio } from './mcp-server.js';
import { installZeroNetworkGuard, spawnInOsSandbox } from './sandbox.js';
import { formatConsole } from './reporters/console.js';
import { formatGitHub, formatSummary } from './reporters/github-actions.js';
import { formatSarif } from './reporters/sarif.js';
import { AUDITORS, type Auditor } from './types.js';
const cliEntryPath = fileURLToPath(import.meta.url);
const help = `ci-guard-mcp 0.2.0 — static repository audits

Usage: ci-guard-mcp scan [path] [options]
       ci-guard-mcp --mcp [--root path] [--sandbox]

  --format text|json|sarif|github   Output format (default: text)
  --fail-on error|warn             Exit 1 at this severity (default: error)
  --auditor NAME                  Select an auditor; repeat to combine
  --staged                        Scan Git index blobs; requires --auditor secrets
  --include-ignored               Include tracked files matching .gitignore rules
  --no-git                        Pure filesystem scan without invoking git subprocesses
  --sandbox                       Enforce OS-boundary egress-deny sandbox (Seatbelt/netns)
  --root PATH                     Scan directory / MCP allowed root
  --help                          Print usage
  --version                       Print version

Exit codes: 0 success, 1 findings reach threshold, 2 usage/configuration/I/O error.
No files are changed except GitHub-provided summary and output files in github mode.
`;
export async function main(argv = process.argv.slice(2)): Promise<number> {
  try {
    const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, strict: true, options: {
      format: { type: 'string', default: 'text' }, 'fail-on': { type: 'string', default: 'error' },
      auditor: { type: 'string', multiple: true }, root: { type: 'string' }, staged: { type: 'boolean' },
      'include-ignored': { type: 'boolean' }, 'no-git': { type: 'boolean' }, sandbox: { type: 'boolean' },
      mcp: { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
    } });
    if (values.help) { process.stdout.write(help); return 0; }
    if (values.version) { process.stdout.write('0.2.0\n'); return 0; }
    if (values.sandbox && process.env.CI_GUARD_SANDBOX_ACTIVE !== '1') {
      return await spawnInOsSandbox(process.execPath, [...process.execArgv, cliEntryPath, ...argv]);
    }
    installZeroNetworkGuard();
    if (values.mcp) {
      if (positionals.length || values.staged || values['include-ignored'] || values['no-git'] || values.auditor || argv.some(a => a.startsWith('--format') || a.startsWith('--fail-on'))) throw new Error('--mcp accepts only --root and --sandbox');
      await serveStdio(values.root); return 0;
    }
    if (positionals[0] !== 'scan' || positionals.length > 2) throw new Error('Expected scan [path]; use --help for usage');
    if (values.root && positionals[1]) throw new Error('Specify a positional path or --root, not both');
    if (!['text', 'json', 'sarif', 'github'].includes(values.format)) throw new Error('Invalid --format');
    if (!['error', 'warn'].includes(values['fail-on'])) throw new Error('Invalid --fail-on');
    if (values.auditor?.some(a => !AUDITORS.includes(a as Auditor))) throw new Error(`Auditors: ${AUDITORS.join(', ')}`);
    const root = values.root ?? positionals[1];
    const report = await scan({
      ...(root ? { root } : {}),
      staged: values.staged ?? false,
      includeIgnored: values['include-ignored'] ?? false,
      noGit: values['no-git'] ?? false,
      ...(values.auditor ? { auditors: values.auditor as Auditor[] } : {}),
    });
    let rendered: string;
    switch (values.format) {
      case 'json': rendered = JSON.stringify(report, null, 2); break;
      case 'sarif': rendered = JSON.stringify(formatSarif(report), null, 2); break;
      case 'github':
        rendered = formatGitHub(report);
        if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, formatSummary(report));
        if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `errors=${report.summary.error}\nwarnings=${report.summary.warn}\nfindings=${report.findings.length}\n`);
        break;
      default: rendered = formatConsole(report);
    }
    if (rendered) process.stdout.write(`${rendered}\n`);
    return report.summary.error > 0 || (values['fail-on'] === 'warn' && report.summary.warn > 0) ? 1 : 0;
  } catch (e) {
    // Never serialize child-process stderr, which may contain repository content.
    const message = e instanceof Error && !('cmd' in e) ? e.message.replace(/[\r\n\x1b]/g, ' ') : 'Repository read failed';
    process.stderr.write(`ci-guard-mcp: ${message}\n`);
    return 2;
  }
}
main().then(code => { process.exitCode = code; }).catch(() => { process.stderr.write('ci-guard-mcp: unexpected failure\n'); process.exitCode = 2; });
