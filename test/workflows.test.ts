import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditWorkflows } from '../src/auditors/workflows.js';
import { context } from './helpers.js';
const sha = 'a'.repeat(40);
function audit(body: string, override = {}) { return auditWorkflows(context({ '.github/workflows/test.yml': body }, override)); }
test('reports pwn-request, injection, mutable actions and missing permissions with lines', () => {
  const found = audit('on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo "${{ github.event.issue.title }}"\n');
  assert.deepEqual(new Set(found.map(f => f.ruleId)), new Set(['workflow/pwn-request', 'workflow/script-injection', 'workflow/unpinned-action', 'workflow/missing-permissions']));
  assert.equal(found.find(f => f.ruleId === 'workflow/script-injection')!.line, 8);
});
test('safe workflow with immutable pins and env indirection is clean', () => {
  assert.deepEqual(audit(`on: [push, pull_request]\npermissions: { contents: read }\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@${sha}\n      - env:\n          TITLE: \${{ github.event.issue.title }}\n        run: echo "$TITLE"\n`), []);
});
test('allowlist is opt-in and scoped to action identity', () => {
  assert.equal(audit('permissions: {}\njobs: {build: {steps: [{uses: actions/checkout@v4}, {uses: actions-evil/tool@v1}]}}', { allowActions: ['actions/*'] }).filter(f => f.ruleId === 'workflow/unpinned-action').length, 1);
});
test('detects array and mapping triggers, repository expression and bracket context', () => {
  for (const trigger of ['[push, pull_request_target]', '{pull_request_target: {}}']) {
    const found = audit(`on: ${trigger}\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@${sha}\n        with:\n          repository: \${{ github['event'].pull_request.head.repo.full_name }}\n      - run: echo \${{ github.head_ref }}\n`);
    assert.ok(found.some(f => f.ruleId === 'workflow/pwn-request'));
    assert.ok(found.some(f => f.ruleId === 'workflow/script-injection'));
  }
});
test('checks reusable workflows and container digests', () => {
  const found = audit(`permissions: {}\njobs:\n  reused:\n    uses: org/repo/.github/workflows/ci.yml@main\n  local:\n    steps:\n      - uses: ./local\n      - uses: docker://alpine@sha256:${'a'.repeat(64)}\n      - uses: docker://alpine:latest\n`);
  assert.equal(found.length, 2);
});
test('malformed and duplicate YAML fails closed without exposing content', () => {
  for (const body of ['jobs: [', 'on: push\non: pull_request', '- scalar']) {
    assert.ok(audit(body).some(f => f.ruleId === 'workflow/invalid-yaml' && f.severity === 'error'));
  }
});
test('resolves YAML anchors and avoids treating event_name as untrusted event content', () => {
  const body = `permissions: {}\nx-step: &unsafe\n  run: echo \${{ github.event.issue.title }}\non: push\njobs:\n  test:\n    steps:\n      - *unsafe\n      - run: echo \${{ github.event_name }}\n`;
  const f = audit(body);
  assert.equal(f.length, 1); assert.equal(f[0]!.ruleId, 'workflow/script-injection');
});
test('expression scanning tolerates repeated incomplete delimiters and multiple expressions', () => {
  assert.equal(audit(`permissions: {}\njobs:\n  a:\n    steps:\n      - run: '${'${{'.repeat(10000)}'\n`).length, 0);
  assert.ok(audit('permissions: {}\njobs: {a: {steps: [{run: "echo ${{ github.event_name }} ${{ github.head_ref }}"}]}}').some(f => f.ruleId === 'workflow/script-injection'));
});
