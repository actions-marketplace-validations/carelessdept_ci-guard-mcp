import type { AuditReport } from '../types.js';
const escapeData = (s: string) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProperty = (s: string) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
const md = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\|/g, '&#124;').replace(/`/g, '&#96;').replace(/[\r\n]/g, ' ');
export function formatGitHub(report: AuditReport): string {
  return report.findings.map(f => `::${f.severity === 'info' ? 'notice' : f.severity === 'warn' ? 'warning' : 'error'} file=${escapeProperty(f.file)},line=${f.line},title=${escapeProperty(f.ruleId)}::${escapeData(`${f.message} ${f.suggestion}`)}`).join('\n');
}
export function formatSummary(report: AuditReport): string {
  return ['## CI Guard audit', '', `Scanned **${report.filesScanned}** files. **${report.summary.error}** errors, **${report.summary.warn}** warnings, **${report.summary.info}** informational.`, '', '| Severity | Location | Rule | Finding |', '| --- | --- | --- | --- |', ...report.findings.slice(0, 1000).map(f => `| ${f.severity} | ${md(f.file)}:${f.line} | ${f.ruleId} | ${md(f.message)} |`), ...(report.findings.length > 1000 ? ['', 'Summary truncated to 1,000 findings; use JSON or SARIF for the full report.'] : []), ''].join('\n');
}
