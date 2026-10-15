import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { TestContext } from 'node:test';
import { DEFAULT_CONFIG } from '../src/config.js';
import type { AuditContext } from '../src/types.js';
export function context(files: Record<string, string>, override = {}): AuditContext {
  return { files: Object.entries(files).map(([path, content]) => ({ path, content })), config: { ...DEFAULT_CONFIG, ...override } };
}
export async function repo(t: TestContext, files: Record<string, string> = {}) {
  const base = path.resolve('.tmp'); await mkdir(base, { recursive: true });
  const root = await mkdtemp(path.join(base, 'test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) { await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), content); }
  return root;
}
export function git(root: string, ...args: string[]) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_COUNT: '0' } });
}
