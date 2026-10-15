import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditLockfiles } from '../src/auditors/lockfile.js';
import { context } from './helpers.js';
test('detects conflicting managers, insecure tarballs and every dependency section', () => {
  const f = auditLockfiles(context({ 'package-lock.json': '{"resolved":"http://registry.test/a.tgz"}', 'yarn.lock': '', 'package.json': JSON.stringify({ dependencies: { a: '*' }, devDependencies: { b: 'latest' }, peerDependencies: { c: '*' }, optionalDependencies: { d: 'npm:alias@latest' } }) }));
  assert.equal(f.filter(v => v.ruleId === 'lockfile/conflict').length, 1);
  assert.equal(f.filter(v => v.ruleId === 'lockfile/insecure-http').length, 1);
  assert.equal(f.filter(v => v.ruleId === 'lockfile/unbounded-version').length, 4);
});
test('separate monorepo package locks do not conflict', () => {
  assert.deepEqual(auditLockfiles(context({ 'package-lock.json': '{}', 'packages/a/pnpm-lock.yaml': '', 'package.json': '{"dependencies":{"a":"^1.2.3"}}' })), []);
});
test('invalid manifests produce errors; HTTPS and workspace ranges are allowed', () => {
  assert.equal(auditLockfiles(context({ 'package.json': '{' }))[0]!.ruleId, 'lockfile/invalid-package');
  assert.deepEqual(auditLockfiles(context({ 'pnpm-lock.yaml': 'https://registry.test/a.tgz', 'package.json': '{"dependencies":{"a":"workspace:*","b":"~1.2.0"}}' })), []);
});
