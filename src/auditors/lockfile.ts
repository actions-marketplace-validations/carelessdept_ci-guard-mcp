import path from 'node:path';
import type { AuditContext, Finding } from '../types.js';
import { lineAt } from '../files.js';
const lockNames = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']);
export function auditLockfiles({ files }: AuditContext): Finding[] {
  const findings: Finding[] = [], groups = new Map<string, string[]>();
  for (const f of files) {
    if (lockNames.has(path.posix.basename(f.path))) {
      const directory = path.posix.dirname(f.path);
      groups.set(directory, [...(groups.get(directory) ?? []), f.path]);
      for (const match of f.content.matchAll(/\bhttp:\/\/[^\s"'<>]+/g)) findings.push({ ruleId: 'lockfile/insecure-http', severity: 'error', file: f.path, line: lineAt(f.content, match.index), message: 'Lockfile contains an unencrypted HTTP dependency URL.', suggestion: 'Use an HTTPS registry and regenerate the lockfile.' });
    }
    if (path.posix.basename(f.path) !== 'package.json') continue;
    let pkg: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(f.content);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
      pkg = parsed as Record<string, unknown>;
    } catch {
      findings.push({ ruleId: 'lockfile/invalid-package', severity: 'error', file: f.path, line: 1, message: 'package.json must contain a valid JSON object.', suggestion: 'Fix the package manifest.' }); continue;
    }
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const deps = pkg[section];
      if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue;
      for (const [name, version] of Object.entries(deps)) if (typeof version === 'string' && /^(?:\*|latest|npm:.+@(?:\*|latest))$/.test(version.trim())) {
        const offset = f.content.indexOf(JSON.stringify(name));
        findings.push({ ruleId: 'lockfile/unbounded-version', severity: 'warn', file: f.path, line: lineAt(f.content, Math.max(0, offset)), message: `${section}.${name} uses an unbounded version selector.`, suggestion: 'Use an intentional version range and commit a single package-manager lockfile.' });
      }
    }
  }
  for (const names of groups.values()) if (names.length > 1) findings.push({ ruleId: 'lockfile/conflict', severity: 'error', file: names[0]!, line: 1, message: `Conflicting lockfiles in the same package: ${names.map(n => path.posix.basename(n)).join(', ')}.`, suggestion: 'Choose one package manager and remove competing lockfiles.' });
  return findings;
}
