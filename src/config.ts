import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type { Config } from './types.js';
import { git, gitIndexBlobSize, isGitRoot, safeFile } from './files.js';

export const DEFAULT_CONFIG: Config = Object.freeze({
  ignore: Object.freeze([]) as unknown as string[],
  allowActions: Object.freeze([]) as unknown as string[],
  ignoreEnv: Object.freeze(['NODE_ENV', 'CI', 'PATH', 'HOME']) as unknown as string[],
  secretIgnore: Object.freeze([
    'test/',
    'tests/',
    '__tests__/',
    'fixtures/',
    '__fixtures__/',
    '*.test.*',
    '*.spec.*',
    '.env.example',
    '.env.template',
  ]) as unknown as string[],
  disabledRules: Object.freeze([]) as unknown as string[],
  maxFileBytes: 1_048_576,
});

export function validateConfig(value: unknown): Partial<Config> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Configuration must be an object');
  }
  const result: Partial<Config> = {};
  for (const [key, val] of Object.entries(value)) {
    if (!Object.hasOwn(DEFAULT_CONFIG, key)) {
      throw new Error(`Unknown configuration option: ${key}`);
    }
    if (key === 'maxFileBytes') {
      if (!Number.isSafeInteger(val) || (val as number) < 1024 || (val as number) > 16_777_216) {
        throw new Error('maxFileBytes must be an integer from 1024 to 16777216');
      }
      result.maxFileBytes = val as number;
    } else {
      if (!Array.isArray(val) || !val.every(v => typeof v === 'string' && !v.includes('\0'))) {
        throw new Error(`${key} must be an array of strings`);
      }
      (result as Record<string, unknown>)[key] = [...val];
    }
  }
  return result;
}

async function jsonWorkingTreeFile(root: string, name: string): Promise<unknown> {
  if (!(await safeFile(root, name))) return undefined;
  if ((await stat(path.join(root, name))).size > 1_048_576) {
    throw new Error(`Configuration too large: ${name}`);
  }
  const raw = await readFile(path.join(root, name), 'utf8');
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in ${name}`);
  }
}

async function jsonIndexFile(root: string, name: string): Promise<unknown> {
  const stageRow = (await git(root, ['ls-files', '--stage', '-z', '--', name], 64 * 1024))
    .split('\0')
    .find(Boolean);
  if (!stageRow) return undefined;
  const mode = stageRow.slice(0, 6);
  if (mode !== '100644' && mode !== '100755') return undefined;

  const size = await gitIndexBlobSize(root, name);
  if (size === undefined) return undefined;
  if (size > 1_048_576) {
    throw new Error(`Configuration too large: ${name}`);
  }
  const raw = await git(root, ['show', `:${name}`], 1_048_576 + 64 * 1024);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in ${name}`);
  }
}

export async function loadConfig(
  root: string,
  override: Partial<Config> = {},
  staged = false,
): Promise<Config> {
  if (staged && !(await isGitRoot(root))) {
    throw new Error('--staged requires the selected directory to be a Git repository root');
  }
  const reader = staged ? jsonIndexFile : jsonWorkingTreeFile;
  const rc = await reader(root, '.ciguardrc.json');
  const pkg = rc === undefined ? await reader(root, 'package.json') : undefined;
  const embedded =
    pkg && typeof pkg === 'object' ? (pkg as Record<string, unknown>).ciguard : undefined;

  return {
    ignore: [...DEFAULT_CONFIG.ignore],
    allowActions: [...DEFAULT_CONFIG.allowActions],
    ignoreEnv: [...DEFAULT_CONFIG.ignoreEnv],
    secretIgnore: [...DEFAULT_CONFIG.secretIgnore],
    disabledRules: [...DEFAULT_CONFIG.disabledRules],
    maxFileBytes: DEFAULT_CONFIG.maxFileBytes,
    ...(rc !== undefined
      ? validateConfig(rc)
      : embedded !== undefined
        ? validateConfig(embedded)
        : {}),
    ...validateConfig(override),
  };
}
