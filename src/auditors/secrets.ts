import ignore from 'ignore';
import type { AuditContext, Finding } from '../types.js';
import { lineAt } from '../files.js';
const signatures: { id: string; label: string; pattern: RegExp }[] = [
  { id: 'aws', label: 'AWS access key ID', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { id: 'github', label: 'GitHub access token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { id: 'stripe', label: 'Stripe live secret key', pattern: /\bsk_live_[A-Za-z0-9]{16,255}\b/g },
  { id: 'openai', label: 'OpenAI project key', pattern: /\bsk-proj-[A-Za-z0-9_-]{20,255}\b/g },
  { id: 'anthropic', label: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,255}\b/g },
  { id: 'slack', label: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{16,255}\b/g },
  { id: 'private-key', label: 'Private PEM key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
];
export function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const c of value) counts.set(c, (counts.get(c) ?? 0) + 1);
  return [...counts.values()].reduce((sum, n) => sum - (n / value.length) * Math.log2(n / value.length), 0);
}
function placeholder(value: string): boolean {
  return /(?:example|placeholder|changeme|your[_-]|replace[_-]|dummy|fake|<|\$\{)/i.test(value) || /^(?:x+|0+|1+)$/i.test(value);
}
export function auditSecrets({ files, config }: AuditContext): Finding[] {
  const findings: Finding[] = [];
  const excluded = ignore().add(config.secretIgnore);
  for (const f of files) {
    if (excluded.ignores(f.path)) continue;
    const emitted = new Set<string>();
    const emit = (id: string, index: number, label: string) => {
      const line = lineAt(f.content, index), key = `${line}:${id}`;
      if (emitted.has(key)) return;
      emitted.add(key);
      findings.push({ ruleId: `secret/${id}`, severity: 'error', file: f.path, line, message: `Possible ${label} detected; value redacted.`, suggestion: 'Revoke and rotate the credential, remove it from tracked content, and check repository history.' });
    };
    for (const signature of signatures) for (const match of f.content.matchAll(signature.pattern)) {
      if (!placeholder(match[0])) emit(signature.id, match.index, signature.label);
    }
    const assigned = /\b(?:[A-Za-z_][\w.-]*(?:secret|token|password|api[_-]?key)|secret|token|password|api[_-]?key)\b["']?\s*[:=]\s*["']([A-Za-z0-9+/=_-]{24,256})["']/gi;
    for (const m of f.content.matchAll(assigned)) {
      const line = lineAt(f.content, m.index);
      if (!placeholder(m[1]!) && entropy(m[1]!) >= 4.3 && ![...emitted].some(k => k.startsWith(`${line}:`))) emit('high-entropy', m.index, 'high-entropy credential assignment');
    }
  }
  return findings;
}
