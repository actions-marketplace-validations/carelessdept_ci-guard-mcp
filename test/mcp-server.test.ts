import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Readable } from 'node:stream';
import { symlink } from 'node:fs/promises';
import path from 'node:path';
import { McpServer, serveStdio } from '../src/mcp-server.js';
import { repo } from './helpers.js';
const request = (method: string, params: object = {}, id: number | string = 1) => ({ jsonrpc: '2.0', id, method, params });
const init = () => request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
async function ready(root: string) { const s = new McpServer(root); await s.handle(init()); await s.handle({ jsonrpc: '2.0', method: 'notifications/initialized' }); return s; }
function asResult(response: unknown) { return response as { result: { tools: { name: string }[]; isError: boolean; structuredContent: { findings: { ruleId: string }[] } }; error?: { code: number } }; }
test('negotiates protocol, advertises four tools, ping and lifecycle', async t => {
  const root = await repo(t), server = new McpServer(root);
  assert.equal(asResult(await server.handle(request('tools/list'))).error!.code, -32002);
  await server.handle(init()); await server.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(asResult(await server.handle(request('tools/list'))).result.tools.length, 4);
  assert.deepEqual(asResult(await server.handle(request('ping'))).result, {});
  assert.equal(await server.handle({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 999 } }), undefined);
});
test('every tool actually runs its selected auditor', async t => {
  const root = await repo(t, { 'a.ts': 'process.env.REQUIRED', 'key.txt': 'AKIA' + 'Z4M8Q2W6E9R3T7Y1', 'package.json': '{"dependencies":{"x":"latest"}}', '.github/workflows/ci.yml': 'on: push\njobs: {}' });
  const s = await ready(root);
  for (const [name, prefix] of [['scan_repo', 'lockfile/'], ['check_env_drift', 'env/'], ['audit_github_workflows', 'workflow/'], ['check_secret_leaks', 'secret/']]) {
    const r = asResult(await s.handle(request('tools/call', { name, arguments: {} })));
    assert.equal(r.result.isError, false); assert.ok(r.result.structuredContent.findings.some(f => f.ruleId.startsWith(prefix!)));
  }
});
test('rejects traversal and symlinks escaping allowed root', async t => {
  const root = await repo(t), outside = await repo(t);
  await symlink(outside, path.join(root, 'escape'));
  const s = await ready(root);
  for (const target of ['..', outside, 'escape']) assert.equal(asResult(await s.handle(request('tools/call', { name: 'scan_repo', arguments: { path: target } }))).result.isError, true);
});
test('validates JSON-RPC and tool arguments without responding to notifications', async t => {
  const s = await ready(await repo(t));
  assert.equal(asResult(await s.handle([])).error!.code, -32600);
  assert.equal(asResult(await s.handle(request('missing'))).error!.code, -32601);
  for (const params of [{ name: 'missing' }, { name: 'scan_repo', arguments: { staged: true } }, { name: 'check_secret_leaks', arguments: { staged: 'yes' } }, { name: 'scan_repo', arguments: { path: 5 } }]) assert.equal(asResult(await s.handle(request('tools/call', params))).error!.code, -32602);
  assert.equal(await s.handle({ jsonrpc: '2.0', method: 'tools/list' }), undefined);
});
test('stdio handles split UTF-8 frames, parse errors, pipelining and EOF without logging', async t => {
  const root = await repo(t), output = new PassThrough(); let raw = '';
  output.on('data', chunk => { raw += String(chunk); });
  const wire = ['{broken', JSON.stringify(init()), JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }), JSON.stringify(request('ping', {}, 'é'))].join('\n');
  const bytes = Buffer.from(wire), boundary = bytes.indexOf(Buffer.from('é')) + 1;
  await serveStdio(root, Readable.from([bytes.subarray(0, 4), bytes.subarray(4, boundary), bytes.subarray(boundary)]), output);
  const responses = raw.trim().split('\n').map(v => JSON.parse(v));
  assert.equal(responses.length, 3); assert.equal(responses[0].error.code, -32700); assert.equal(responses[2].id, 'é');
});
test('oversized frames recover at next newline', async t => {
  const out = new PassThrough(); let raw = ''; out.on('data', c => { raw += String(c); });
  await serveStdio(await repo(t), Readable.from(['x'.repeat(1_048_577), '\n' + JSON.stringify(request('ping')) + '\n']), out);
  assert.deepEqual(raw.trim().split('\n').map(v => JSON.parse(v).error?.code ?? 'ok'), [-32600, 'ok']);
});
