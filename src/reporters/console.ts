import type { AuditReport } from '../types.js';
export function formatConsole(report: AuditReport): string {
  const clean = (s: string) => s.replace(/[\x00-\x1f\x7f-\x9f]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return [...report.findings.map(f => `${clean(f.file)}:${f.line} ${f.severity.toUpperCase()} ${f.ruleId}\n  ${clean(f.message)}\n  ${clean(f.suggestion)}`), `${report.filesScanned} files scanned · ${report.summary.error} errors · ${report.summary.warn} warnings · ${report.summary.info} informational`].join('\n');
}
