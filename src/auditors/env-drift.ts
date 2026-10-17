import { parseDocument } from 'yaml';
import type { AuditContext, Finding } from '../types.js';
import { lineAt } from '../files.js';
const patterns = [
  /\bprocess\s*\.\s*env\s*(?:\.\s*([A-Za-z_][\w]*)|\[\s*['"]([A-Za-z_][\w]*)['"]\s*\])/g,
  /\bimport\s*\.\s*meta\s*\.\s*env\s*(?:\.\s*([A-Za-z_][\w]*)|\[\s*['"]([A-Za-z_][\w]*)['"]\s*\])/g,
  /\bos\s*\.\s*environ\s*(?:\[\s*['"]([A-Za-z_][\w]*)['"]\s*\]|\.\s*get\s*\(\s*['"]([A-Za-z_][\w]*)['"])/g,
  /\bos\s*\.\s*getenv\s*\(\s*['"]([A-Za-z_][\w]*)['"]/g,
  /\bos\s*\.\s*Getenv\s*\(\s*"([A-Za-z_][\w]*)"/g,
  /\b(?:std\s*::\s*)?env\s*::\s*var\s*\(\s*"([A-Za-z_][\w]*)"/g,
];
export function auditEnvDrift({ files, config }: AuditContext): Finding[] {
  const findings: Finding[] = [];
  const refs = new Map<string, { file: string; line: number }>();
  const templates = new Map<string, { file: string; line: number }>();
  const deployed = new Set<string>();
  for (const f of files) {
    if (/\.(?:[cm]?[jt]sx?|py|go|rs)$/.test(f.path) && !/(?:^|\/)(?:test|tests|fixtures|__tests__|__fixtures__)\/|\.(?:test|spec)\./.test(f.path)) {
      for (const regex of patterns) for (const m of f.content.matchAll(regex)) {
        const name = m[1] ?? m[2];
        if (name && !refs.has(name)) refs.set(name, { file: f.path, line: lineAt(f.content, m.index) });
      }
    }
    if (/(?:^|\/)\.env\.(?:example|template)$/.test(f.path)) {
      for (const m of f.content.matchAll(/^\s*(?:export\s+)?([A-Za-z_][\w]*)\s*=/gm)) templates.set(m[1]!, { file: f.path, line: lineAt(f.content, m.index) });
    }
    if (/(?:^|\/)Dockerfile(?:\.[\w.-]+)?$/.test(f.path)) {
      for (const m of f.content.replace(/\\\r?\n/g, ' ').matchAll(/^\s*ENV\s+(.+)/gmi)) {
        const body = m[1]!.replace(/\\\r?\n/g, ' ');
        const assignments = [...body.matchAll(/(?:^|\s)([A-Za-z_]\w*)=/g)];
        for (const v of assignments) deployed.add(v[1]!);
        if (!assignments.length) { const name = body.match(/^([A-Za-z_]\w*)\s/); if (name) deployed.add(name[1]!); }
      }
    }
    if (/(?:^|\/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/.test(f.path)) {
      const doc = parseDocument(f.content);
      if (doc.errors.length) {
        findings.push({ ruleId: 'env/invalid-compose', severity: 'error', file: f.path, line: 1, message: 'Compose file contains invalid YAML.', suggestion: 'Fix Compose YAML before checking environment drift.' });
      } else {
        try {
          const obj = doc.toJS({ maxAliasCount: 100 }) as { services?: Record<string, { environment?: Record<string, unknown> | unknown[] }> } | null;
          for (const service of Object.values(obj?.services ?? {})) {
            const env = service?.environment;
            if (Array.isArray(env)) for (const v of env) { if (typeof v === 'string') deployed.add(v.split('=')[0]!); }
            else if (env && typeof env === 'object') for (const key of Object.keys(env)) deployed.add(key);
          }
        } catch {
          findings.push({ ruleId: 'env/invalid-compose', severity: 'error', file: f.path, line: 1, message: 'Compose file contains excessive YAML alias expansion or invalid structure.', suggestion: 'Reduce YAML alias nesting and fix Compose structure before checking environment drift.' });
        }
      }
    }
  }
  for (const [name, location] of refs) {
    if (config.ignoreEnv.includes(name)) continue;
    if (!templates.has(name)) findings.push({ ruleId: 'env/undocumented', severity: 'warn', ...location, message: `${name} is referenced in source but absent from an environment template${deployed.has(name) ? ' (it is defined in deployment configuration)' : ''}.`, suggestion: `Document ${name} in .env.example or .env.template.` });
  }
  for (const [name, location] of templates) if (!refs.has(name) && !deployed.has(name) && !config.ignoreEnv.includes(name)) findings.push({ ruleId: 'env/dead-template', severity: 'info', ...location, message: `${name} is documented but has no detected source or deployment reference.`, suggestion: 'Remove it if unused, or retain it with an ignoreEnv entry when consumed dynamically or externally.' });
  return findings;
}
