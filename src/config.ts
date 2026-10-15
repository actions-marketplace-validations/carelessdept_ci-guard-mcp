import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Config } from './types.js';
import { safeFile } from './files.js';
export const DEFAULT_CONFIG: Config = {
  ignore: [], allowActions: [], ignoreEnv: ['NODE_ENV', 'CI', 'PATH', 'HOME'],
  secretIgnore: ['test/', 'tests/', '__tests__/', 'fixtures/', '__fixtures__/', '*.test.*', '*.spec.*', '.env.example', '.env.template'],
  disabledRules: [], maxFileBytes: 1_048_576,
};
export function validateConfig(value: unknown): Partial<Config> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Configuration must be an object');
  const result: Partial<Config> = {};
  for (const [key, val] of Object.entries(value)) {
    if (!(Object.hasOwn(DEFAULT_CONFIG, key))) throw new Error(`Unknown configuration option: ${key}`);
    if (key === 'maxFileBytes') {
      if (!Number.isSafeInteger(val) || (val as number) < 1024 || (val as number) > 16_777_216) throw new Error('maxFileBytes must be an integer from 1024 to 16777216');
      result.maxFileBytes = val as number;
    } else {
      if (!Array.isArray(val) || !val.every(v => typeof v === 'string' && !v.includes('\0'))) throw new Error(`${key} must be an array of strings`);
      (result as Record<string, unknown>)[key] = val;
    }
  }
  return result;
}
async function jsonFile(root: string, name: string): Promise<unknown> {
  if (!await safeFile(root, name)) return undefined;
  const raw = await readFile(path.join(root, name), 'utf8');
  if (Buffer.byteLength(raw) > 1_048_576) throw new Error(`Configuration too large: ${name}`);
  try { return JSON.parse(raw); } catch { throw new Error(`Invalid JSON in ${name}`); }
}
export async function loadConfig(root: string, override: Partial<Config> = {}): Promise<Config> {
  const rc = await jsonFile(root, '.ciguardrc.json');
  const pkg = rc === undefined ? await jsonFile(root, 'package.json') : undefined;
  const embedded = pkg && typeof pkg === 'object' ? (pkg as Record<string, unknown>).ciguard : undefined;
  return { ...DEFAULT_CONFIG, ...(rc !== undefined ? validateConfig(rc) : embedded !== undefined ? validateConfig(embedded) : {}), ...validateConfig(override) };
}
