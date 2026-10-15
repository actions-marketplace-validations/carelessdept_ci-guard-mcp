import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, symlink } from 'node:fs/promises';
import path from 'node:path';
import { auditSecrets } from '../src/auditors/secrets.js';
import { scan } from '../src/index.js';
import { context, repo, git } from './helpers.js';
const tokens = [ ['aws', 'AKIA' + 'Z4M8Q2W6E9R3T7Y1'], ['github', 'ghp_' + 'aB9z'.repeat(9)], ['github', 'github_pat_' + 'aB9z_'.repeat(10)], ['stripe', 'sk_live_' + 'aB9z'.repeat(8)], ['openai', 'sk-proj-' + 'aB9z'.repeat(12)], ['anthropic', 'sk-ant-' + 'aB9z'.repeat(12)], ['slack', 'xoxb-' + '1234567890-'.repeat(3)], ['private-key', '-----BEGIN RSA PRIVATE KEY-----'] ];
for (const [id, token] of tokens) test(`detects ${id} and never returns credential values`, () => {
  const f = auditSecrets(context({ 'config.txt': token! }));
  assert.equal(f[0]!.ruleId, `secret/${id}`);
  assert.ok(!JSON.stringify(f).includes(token!));
});
test('entropy detection is contextual and skips hashes, placeholders and excluded paths', () => {
  const random = 'f8Kp2Rz9Wq5Tx7La0Md3Nv6Bs1Hc4Yj';
  assert.equal(auditSecrets(context({ 'config.js': `const api_key = "${random}"` }))[0]!.ruleId, 'secret/high-entropy');
  assert.deepEqual(auditSecrets(context({ 'hash.txt': random, 'config.js': 'const api_key = "your_placeholder_value_here"', '.env.example': tokens[0]![1]!, 'fixtures/key.txt': tokens[0]![1]!, 'a.test.ts': tokens[0]![1]! })), []);
});
test('staged mode reads index rather than working copy and skips deletion/symlink', async t => {
  const root = await repo(t, { 'key.txt': tokens[0]![1]! });
  git(root, 'init', '-q'); git(root, 'add', 'key.txt');
  await writeFile(path.join(root, 'key.txt'), 'safe working copy');
  const report = await scan({ root, staged: true, auditors: ['secrets'] });
  assert.equal(report.summary.error, 1);
  assert.equal((await scan({ root, auditors: ['secrets'] })).summary.error, 0);
  await symlink('key.txt', path.join(root, 'link')); git(root, 'add', 'link');
  assert.equal((await scan({ root, staged: true, auditors: ['secrets'] })).summary.error, 1);
});
test('normal Git scans ignore untracked credentials and honor gitignore', async t => {
  const root = await repo(t, { '.gitignore': 'ignored.txt\n', 'tracked.txt': tokens[0]![1]!, 'untracked.txt': tokens[0]![1]!, 'ignored.txt': tokens[0]![1]! });
  git(root, 'init', '-q'); git(root, 'add', 'tracked.txt', '.gitignore');
  const report = await scan({ root, auditors: ['secrets'] });
  assert.deepEqual(report.findings.map(f => f.file), ['tracked.txt']);
});
test('staged mode refuses a non-Git root and mixed auditors', async t => {
  const root = await repo(t);
  await assert.rejects(scan({ root, staged: true, auditors: ['secrets'] }), /Git repository root/);
  await assert.rejects(scan({ root, staged: true }), /only the secrets/);
});
test('staged ignore rules come from the index and renamed files scan under their new path', async t => {
  const root = await repo(t, { 'old.txt': 'safe', '.gitignore': 'ignored.txt\n' });
  git(root, 'init', '-q'); git(root, 'add', '.');
  git(root, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'baseline');
  git(root, 'mv', 'old.txt', 'new.txt');
  await writeFile(path.join(root, 'new.txt'), tokens[0]![1]!); git(root, 'add', 'new.txt');
  await writeFile(path.join(root, 'ignored.txt'), tokens[0]![1]!); git(root, 'add', '-f', 'ignored.txt');
  await writeFile(path.join(root, '.gitignore'), '');
  const report = await scan({ root, staged: true, auditors: ['secrets'] });
  assert.deepEqual(report.findings.map(f => f.file), ['new.txt']);
  git(root, 'rm', '--cached', 'new.txt');
  assert.equal((await scan({ root, staged: true, auditors: ['secrets'] })).summary.error, 0);
});
