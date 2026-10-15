import { createHash } from 'node:crypto';
import type { AuditReport } from '../types.js';
export function formatSarif(report: AuditReport): object {
  const ids = [...new Set(report.findings.map(f => f.ruleId))].sort();
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
    tool: { driver: { name: 'ci-guard-mcp', version: report.version, informationUri: 'https://github.com/carelessdept/ci-guard-mcp', rules: ids.map(id => ({ id, shortDescription: { text: id }, help: { text: report.findings.find(f => f.ruleId === id)!.suggestion } })) } },
    results: report.findings.map(f => ({ ruleId: f.ruleId, ruleIndex: ids.indexOf(f.ruleId), level: f.severity === 'warn' ? 'warning' : f.severity === 'info' ? 'note' : 'error', message: { text: `${f.message} ${f.suggestion}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file.split('/').map(encodeURIComponent).join('/'), uriBaseId: '%SRCROOT%' }, region: { startLine: f.line, startColumn: f.column ?? 1 } } }], partialFingerprints: { primaryLocationLineHash: createHash('sha256').update(`${f.ruleId}\0${f.file}\0${f.line}`).digest('hex') } }))
  }] };
}
