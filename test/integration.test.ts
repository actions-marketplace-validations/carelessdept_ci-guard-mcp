import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, symlink, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { scan, formatSarif } from '../src/index.js';
import { formatGitHub, formatSummary } from '../src/reporters/github-actions.js';
import { formatConsole } from '../src/reporters/console.js';
import { validateConfig, loadConfig } from '../src/config.js';
import { repo } from './helpers.js';
const exec = promisify(execFile);
const cli = path.resolve('src/cli.ts');
async function run(args: string[], env: Record<string, string | undefined> = {}) {
  try { return { ...(await exec(process.execPath, ['--import', 'tsx', cli, ...args], { env: { ...process.env, ...env } })), code: 0 }; }
  catch (e) { const err = e as { stdout: string; stderr: string; code: number }; return { stdout: err.stdout, stderr: err.stderr, code: err.code }; }
}
test('configuration rejects unknown/prototype keys and invalid types, rc wins over package', async t => {
  for (const value of [null, [], { constructor: [] }, JSON.parse('{"__proto__":[]}'), { typo: [] }, { ignore: 'a' }, { maxFileBytes: 1 }]) assert.throws(() => validateConfig(value));
  const root = await repo(t, { '.ciguardrc.json': '{"allowActions":["actions/*"]}', 'package.json': '{"ciguard":{"allowActions":["other/*"]}}' });
  assert.deepEqual((await loadConfig(root)).allowActions, ['actions/*']);
  await writeFile(path.join(root, '.ciguardrc.json'), '{');
  await assert.rejects(loadConfig(root), /Invalid JSON/);
});
test('nested gitignore respects negation, config ignores and symlink exclusion', async t => {
  const root = await repo(t, { '.gitignore': '*.ts\n!keep.ts\n', 'keep.ts': 'process.env.KEEP', 'hide.ts': 'process.env.HIDE', 'child/.gitignore': '!visible.ts\n', 'child/visible.ts': 'process.env.VISIBLE', 'generated/a.js': 'process.env.GENERATED' });
  await symlink('keep.ts', path.join(root, 'link.ts'));
  const report = await scan({ root, auditors: ['env-drift'], config: { ignore: ['generated/'] } });
  assert.deepEqual(report.findings.map(f => f.file), ['child/visible.ts', 'keep.ts']);
});
test('oversized files warn, binary files skip, disabled rules apply, reports are deterministic', async t => {
  const root = await repo(t, { 'large.txt': 'a'.repeat(1025), 'binary.bin': '\0AKIA' + 'Z4M8Q2W6E9R3T7Y1', 'a.ts': 'process.env.X' });
  const options = { root, config: { maxFileBytes: 1024, disabledRules: ['env/undocumented', 'scan/skipped-file'] } };
  const a = await scan(options), b = await scan(options);
  assert.deepEqual(a, b); assert.deepEqual(a.findings.map(f => f.ruleId), ['scan/skipped-file']);
});
test('reporters escape workflow-command and markdown injection and create valid SARIF locations', () => {
  const report = { version: '0.1.0' as const, filesScanned: 1, summary: { error: 1, warn: 0, info: 0 }, findings: [{ ruleId: 'secret/aws', severity: 'error' as const, file: 'a,b:c%\n`|<x>.txt', line: 2, message: 'redacted\n::error::fake <img>|`', suggestion: 'Rotate.' }] };
  const github = formatGitHub(report);
  assert.equal(github.split('\n').length, 1); assert.ok(github.includes('a%2Cb%3Ac%25%0A'));
  const summary = formatSummary(report); assert.ok(!summary.includes('<img>')); assert.ok(summary.includes('&lt;img&gt;'));
  assert.ok(!formatConsole(report).includes('\n::error::'));
  const sarif = JSON.parse(JSON.stringify(formatSarif(report)));
  assert.equal(sarif.version, '2.1.0'); assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 2);
  assert.ok(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.includes('%0A'));
});
test('CLI enforces thresholds, JSON/SARIF formats and usage failures', async t => {
  const root = await repo(t, { 'a.ts': 'process.env.REQUIRED' });
  const json = await run(['scan', root, '--format', 'json']);
  assert.equal(json.code, 0); assert.equal(JSON.parse(json.stdout).summary.warn, 1);
  assert.equal((await run(['scan', root, '--fail-on', 'warn'])).code, 1);
  const sarif = await run(['scan', root, '--format', 'sarif']); assert.equal(JSON.parse(sarif.stdout).version, '2.1.0');
  for (const args of [['scan', root, '--format', 'bad'], ['scan', root, '--fail-on', 'info'], ['scan', root, '--auditor', 'bad'], ['scan', root, '--staged'], ['unknown']]) assert.equal((await run(args)).code, 2);
  assert.equal((await run(['--help'])).code, 0); assert.equal((await run(['--version'])).stdout.trim(), '0.1.0');
});
test('GitHub mode writes outputs and summary even when findings fail the gate', async t => {
  const root = await repo(t, { 'key.txt': 'AKIA' + 'Z4M8Q2W6E9R3T7Y1' });
  const summary = path.join(root, 'summary.md'), output = path.join(root, 'outputs.txt');
  const r = await run(['scan', root, '--format', 'github'], { GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output });
  assert.equal(r.code, 1); assert.ok(r.stdout.startsWith('::error file=key.txt,line=1'));
  assert.equal(await readFile(output, 'utf8'), 'errors=1\nwarnings=0\nfindings=1\n');
  assert.ok((await readFile(summary, 'utf8')).includes('CI Guard audit'));
});
test('MCP CLI is a clean stdio subprocess with working initialization and EOF shutdown', async t => {
  const root = await repo(t); const { spawn } = await import('node:child_process');
  const child = spawn(process.execPath, ['--import', 'tsx', cli, '--mcp', '--root', root]);
  let stdout = ''; child.stdout.on('data', c => { stdout += String(c); });
  let stderr = ''; child.stderr.on('data', c => { stderr += String(c); });
  const done = new Promise<number | null>((resolve, reject) => { child.once('close', resolve); child.once('error', reject); });
  child.stdin.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'client', version: '1' } } }) + '\n');
  assert.equal(await done, 0, stderr); assert.equal(JSON.parse(stdout).result.protocolVersion, '2024-11-05');
});
