export type Severity = 'error' | 'warn' | 'info';
export type Auditor = 'workflows' | 'env-drift' | 'secrets' | 'lockfile';
export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  column?: number;
  message: string;
  suggestion: string;
}
export interface Config {
  ignore: string[];
  allowActions: string[];
  ignoreEnv: string[];
  secretIgnore: string[];
  disabledRules: string[];
  maxFileBytes: number;
}
export interface AuditReport {
  version: '0.1.0';
  findings: Finding[];
  summary: Record<Severity, number>;
  filesScanned: number;
}
export interface SourceFile { path: string; content: string }
export interface AuditContext { files: SourceFile[]; config: Config }
export interface ScanOptions {
  root?: string;
  staged?: boolean;
  includeIgnored?: boolean;
  auditors?: Auditor[];
  config?: Partial<Config>;
}
export const AUDITORS: readonly Auditor[] = ['workflows', 'env-drift', 'secrets', 'lockfile'];
