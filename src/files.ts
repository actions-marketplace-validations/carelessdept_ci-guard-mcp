import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import ignore from 'ignore';
import type { Config, Finding, SourceFile } from './types.js';

const exec = promisify(execFile);
const builtins = ignore().add([
  '.git/',
  'node_modules/',
  'dist/',
  'build/',
  'coverage/',
  '.cache/',
  '.tmp/',
  'vendor/',
  'target/',
  '.venv/',
]);

// Hardened read-only Git config overrides prepended to every git invocation (A1)
const HARDENED_GIT_CONFIG_ARGS = [
  '-c', 'core.fsmonitor=false',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'core.pager=cat',
  '-c', 'core.sshCommand=false',
  '-c', 'core.askPass=false',
  '-c', 'protocol.allow=never',
  '-c', 'diff.external=',
  '-c', 'filter.lfs.smudge=',
  '-c', 'filter.lfs.clean=',
  '-c', 'filter.lfs.process=',
];

const SAFE_ENV_KEYS = [
  'PATH',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TMPDIR',
  'TEMP',
  'TMP',
  'SystemRoot',
  'WINDIR',
  'COMSPEC',
  'PATHEXT',
];

function buildHardenedGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    HOME: '/nonexistent',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_ASKPASS: 'echo',
    SSH_ASKPASS: 'echo',
  };
  for (const key of SAFE_ENV_KEYS) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }
  return env;
}

// Cached newline offset index for O(log L) line number lookups on dense files (A7)
let cachedText = '';
let cachedNewlines: number[] = [];

function getNewlineOffsets(text: string): number[] {
  if (text === cachedText) return cachedNewlines;
  const offsets: number[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) offsets.push(i);
  }
  cachedText = text;
  cachedNewlines = offsets;
  return offsets;
}

export function lineAt(text: string, offset: number): number {
  if (offset <= 0) return 1;
  const clamped = Math.min(offset, text.length);
  const newlines = getNewlineOffsets(text);
  let low = 0;
  let high = newlines.length - 1;
  let count = 0;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (newlines[mid]! < clamped) {
      count = mid + 1;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return count + 1;
}

export async function safeFile(root: string, relative: string): Promise<boolean> {
  if (path.isAbsolute(relative) || relative.split(/[\\/]/).some(p => p === '..' || p === '.git')) return false;
  let current = root;
  try {
    const parts = relative.split('/');
    for (const [i, part] of parts.entries()) {
      current = path.join(current, part);
      const stat = await lstat(current);
      if (stat.isSymbolicLink() || (i < parts.length - 1 && !stat.isDirectory())) return false;
      if (i === parts.length - 1) return stat.isFile();
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  return false;
}

export async function git(root: string, args: string[], maxBuffer = 32 * 1024 * 1024): Promise<string> {
  const result = await exec('git', [...HARDENED_GIT_CONFIG_ARGS, '-C', root, ...args], {
    maxBuffer,
    timeout: 15_000,
    windowsHide: true,
    encoding: 'utf8',
    env: buildHardenedGitEnv(),
  });
  return result.stdout;
}

/**
 * Queries the byte size of an index object (e.g. `:path`) before reading its body (A5).
 */
export async function gitIndexBlobSize(root: string, relativePath: string): Promise<number | undefined> {
  try {
    const out = await git(root, ['cat-file', '-s', `:${relativePath}`], 64 * 1024);
    const parsed = Number.parseInt(out.trim(), 10);
    return Number.isFinite(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Checks whether `root` is a valid Git top-level directory.
 * If `.git` exists at `root` (and is not a symlink), a failure to run `git` throws an explicit
 * operational error rather than silently degrading secret scan scope (A8).
 */
export async function isGitRoot(root: string): Promise<boolean> {
  let metadata;
  try {
    metadata = await lstat(path.join(root, '.git'));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw e;
  }
  if (metadata.isSymbolicLink()) return false;

  try {
    const top = (await git(root, ['rev-parse', '--show-toplevel'], 64 * 1024)).trim();
    const resolvedTop = await realpath(top);
    if (resolvedTop !== root) {
      throw new Error(`corrupt or incomplete .git metadata at ${root}`);
    }
    return true;
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`Git repository metadata found at scan root, but git execution failed: ${detail}`);
  }
}

export async function collectFiles(
  root: string,
  config: Config,
  staged: boolean,
  includeIgnored = false,
): Promise<{ files: SourceFile[]; warnings: Finding[] }> {
  const files: SourceFile[] = [];
  const warnings: Finding[] = [];
  const custom = ignore().add(config.ignore);
  const warn = (p: string, message: string) =>
    warnings.push({
      ruleId: 'scan/skipped-file',
      severity: 'warn',
      file: p,
      line: 1,
      message,
      suggestion: 'Inspect this file separately or increase maxFileBytes.',
    });

  async function add(p: string, index = false) {
    if (builtins.ignores(p) || custom.ignores(p)) return;
    if (!index && !(await safeFile(root, p))) return;

    if (index) {
      // Check blob size in Git index BEFORE loading blob into memory (A5)
      const blobSize = await gitIndexBlobSize(root, p);
      if (blobSize === undefined) return;
      if (blobSize > config.maxFileBytes) {
        warn(p, 'File exceeds the configured scan size limit.');
        return;
      }
      const content = await git(root, ['show', `:${p}`], Math.max(64 * 1024, config.maxFileBytes + 64 * 1024));
      if (Buffer.byteLength(content) > config.maxFileBytes) {
        warn(p, 'File exceeds the configured scan size limit.');
        return;
      }
      if (!content.includes('\0')) files.push({ path: p, content });
      return;
    }

    const fullPath = path.join(root, p);
    if ((await lstat(fullPath)).size > config.maxFileBytes) {
      warn(p, 'File exceeds the configured scan size limit.');
      return;
    }
    const content = await readFile(fullPath, 'utf8');
    if (Buffer.byteLength(content) > config.maxFileBytes) {
      warn(p, 'File exceeds the configured scan size limit.');
      return;
    }
    if (!content.includes('\0')) files.push({ path: p, content });
  }

  if (staged) {
    let gitRootOk = false;
    try {
      gitRootOk = await isGitRoot(root);
    } catch (err) {
      throw new Error(
        `--staged requires a functional Git repository root (${err instanceof Error ? err.message : String(err)})`,
      );
    }
    if (!gitRootOk) {
      throw new Error('--staged requires the selected directory to be a Git repository root');
    }

    const names = (await git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']))
      .split('\0')
      .filter(Boolean);
    const modes = new Map(
      (await git(root, ['ls-files', '--stage', '-z']))
        .split('\0')
        .filter(Boolean)
        .map(row => [row.slice(row.indexOf('\t') + 1), row.slice(0, 6)]),
    );
    const indexIgnores: { base: string; matcher: ReturnType<typeof ignore> }[] = [];
    if (!includeIgnored) {
      for (const [p, mode] of [...modes].sort(([a], [b]) => a.split('/').length - b.split('/').length)) {
        if (path.posix.basename(p) !== '.gitignore' || !['100644', '100755'].includes(mode)) continue;
        const igSize = await gitIndexBlobSize(root, p);
        if (igSize === undefined) continue;
        if (igSize > config.maxFileBytes) {
          warn(p, 'Index ignore file exceeds the configured size limit.');
          continue;
        }
        const content = await git(root, ['show', `:${p}`], Math.max(64 * 1024, config.maxFileBytes + 64 * 1024));
        if (Buffer.byteLength(content) > config.maxFileBytes) {
          warn(p, 'Index ignore file exceeds the configured size limit.');
          continue;
        }
        indexIgnores.push({ base: path.posix.dirname(p), matcher: ignore().add(content) });
      }
    }
    for (const p of names.sort()) {
      if (modes.get(p) !== '100644' && modes.get(p) !== '100755') continue;
      let ignored = false;
      for (const rule of indexIgnores) {
        if (rule.base !== '.' && !p.startsWith(`${rule.base}/`)) continue;
        const relative = rule.base === '.' ? p : p.slice(rule.base.length + 1);
        const check = rule.matcher.test(relative);
        if (check.ignored) ignored = true;
        if (check.unignored) ignored = false;
      }
      if (includeIgnored || !ignored) await add(p, true);
    }
  } else {
    async function walk(dir: string, inherited: { base: string; matcher: ReturnType<typeof ignore> }[]) {
      const rules = [...inherited];
      const name = dir ? `${dir}/.gitignore` : '.gitignore';
      if (!includeIgnored && (await safeFile(root, name))) {
        const igPath = path.join(root, name);
        const igStat = await lstat(igPath);
        if (igStat.size > config.maxFileBytes) {
          warn(name, 'Ignore file exceeds the configured size limit.');
        } else {
          rules.push({ base: dir, matcher: ignore().add(await readFile(igPath, 'utf8')) });
        }
      }
      const entries = await readdir(path.join(root, dir), { withFileTypes: true });
      for (const entry of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
        const p = dir ? `${dir}/${entry.name}` : entry.name;
        const candidate = entry.isDirectory() ? `${p}/` : p;
        if (entry.isSymbolicLink() || builtins.ignores(candidate) || custom.ignores(candidate)) continue;
        let ignored = false;
        for (const rule of rules) {
          const relative = rule.base ? candidate.slice(rule.base.length + 1) : candidate;
          const check = rule.matcher.test(relative);
          if (check.ignored) ignored = true;
          if (check.unignored) ignored = false;
        }
        if (!includeIgnored && ignored) continue;
        if (entry.isDirectory()) await walk(p, rules);
        else if (entry.isFile()) await add(p);
      }
    }
    await walk('', []);
  }
  return { files: files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)), warnings };
}
