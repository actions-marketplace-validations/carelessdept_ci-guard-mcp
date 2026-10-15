import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditEnvDrift } from '../src/auditors/env-drift.js';
import { context } from './helpers.js';
test('recognizes all five languages and JS forms, retaining source lines', () => {
  const findings = auditEnvDrift(context({
    'a.ts': 'process.env.API_URL;\nimport.meta.env.VITE_URL; process.env["BRACKET"];',
    'b.py': 'os.environ["PY_KEY"]; os.environ.get("PY_GET"); os.getenv("PY_ALT")',
    'c.go': 'os.Getenv("GO_KEY")', 'd.rs': 'std::env::var("RS_KEY")',
    '.env.example': 'API_URL=\n',
  }));
  assert.deepEqual(findings.map(f => f.message.split(' ')[0]).sort(), ['VITE_URL', 'BRACKET', 'PY_KEY', 'PY_GET', 'PY_ALT', 'GO_KEY', 'RS_KEY'].sort());
  assert.equal(findings.find(f => f.message.startsWith('VITE_URL'))!.line, 2);
});
test('deployment variables still require documentation; deployment use prevents dead template reports', () => {
  const f = auditEnvDrift(context({ 'app.js': 'process.env.API_URL', 'Dockerfile': 'ENV API_URL=https://example.test KEEP=yes\n', '.env.template': 'KEEP=\nDEAD=\n', 'docker-compose.yml': 'services:\n  web:\n    environment:\n      - COMPOSE_KEEP=yes\n', 'sub/.env.example': 'COMPOSE_KEEP=\n' }));
  assert.equal(f.length, 2);
  assert.ok(f.some(v => v.ruleId === 'env/undocumented' && v.message.includes('deployment')));
  assert.ok(f.some(v => v.ruleId === 'env/dead-template' && v.message.startsWith('DEAD')));
});
test('ignores builtins and configured env names, skips test fixtures', () => {
  assert.deepEqual(auditEnvDrift(context({ 'app.ts': 'process.env.NODE_ENV; process.env.CUSTOM', 'test/a.py': 'os.environ["TEST"]' }, { ignoreEnv: ['NODE_ENV', 'CUSTOM'] })), []);
});
test('compose mapping and legacy/multiline Docker ENV declarations count as consumers', () => {
  assert.deepEqual(auditEnvDrift(context({ '.env.example': 'ONE=\nTWO=\nTHREE=\nFOUR=\n', 'Dockerfile': 'ENV ONE value\nENV TWO=2 \\\n THREE=3\n', 'compose.yaml': 'services: {app: {environment: {FOUR: value}}}' })), []);
});
test('invalid compose produces explicit error', () => {
  assert.equal(auditEnvDrift(context({ 'compose.yaml': 'services: [' }))[0]!.ruleId, 'env/invalid-compose');
});
