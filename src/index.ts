import { realpath, stat } from 'node:fs/promises';
import { loadConfig } from './config.js';
import { collectFiles, git, isGitRoot } from './files.js';
import { auditWorkflows } from './auditors/workflows.js';
import { auditEnvDrift } from './auditors/env-drift.js';
import { auditSecrets } from './auditors/secrets.js';
import { auditLockfiles } from './auditors/lockfile.js';
import { AUDITORS, type AuditReport, type ScanOptions, type Auditor } from './types.js';
export * from './types.js';
export { loadConfig, DEFAULT_CONFIG } from './config.js';
export { auditWorkflows, auditEnvDrift, auditSecrets, auditLockfiles };
export { formatConsole } from './reporters/console.js';
export { formatSarif } from './reporters/sarif.js';
export { formatGitHub, formatSummary } from './reporters/github-actions.js';
const engines = { workflows: auditWorkflows, 'env-drift': auditEnvDrift, secrets: auditSecrets, lockfile: auditLockfiles };
export async function scan(options: ScanOptions = {}): Promise<AuditReport> {
  const root = await realpath(options.root ?? process.cwd());
  if (!(await stat(root)).isDirectory()) throw new Error('Scan root must be a directory');
  const selected = options.auditors ?? [...AUDITORS];
  if (!selected.every(a => AUDITORS.includes(a))) throw new Error('Unknown auditor');
  if (options.staged && (selected.length !== 1 || selected[0] !== 'secrets')) throw new Error('Staged mode supports only the secrets auditor; use --auditor secrets --staged');
  const config = await loadConfig(root, options.config);
  const { files, warnings } = await collectFiles(root, config, options.staged ?? false, options.includeIgnored ?? false);
  // Normal secret scans inspect tracked content when this is a Git root. Other engines also inspect untracked source.
  const tracked = !options.staged && selected.includes('secrets') && await isGitRoot(root)
    ? new Set((await git(root, ['ls-files', '-z'])).split('\0')) : undefined;
  const findings = [...warnings];
  for (const name of [...new Set<Auditor>(selected)]) findings.push(...engines[name]({ files: name === 'secrets' && tracked ? files.filter(f => tracked.has(f.path)) : files, config }));
  const filtered = findings.filter(f => f.ruleId === 'scan/skipped-file' || !config.disabledRules.includes(f.ruleId));
  filtered.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || a.ruleId.localeCompare(b.ruleId, 'en'));
  const summary = { error: 0, warn: 0, info: 0 };
  for (const f of filtered) summary[f.severity]++;
  return { version: '0.1.0', findings: filtered, summary, filesScanned: files.length };
}
