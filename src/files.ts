import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import ignore from 'ignore';
import type { Config, Finding, SourceFile } from './types.js';
const exec = promisify(execFile);
const builtins = ignore().add(['.git/', 'node_modules/', 'dist/', 'build/', 'coverage/', '.cache/', '.tmp/', 'vendor/', 'target/', '.venv/']);
export function lineAt(text: string, offset: number): number { return text.slice(0, offset).split('\n').length; }
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
  } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  return false;
}
export async function git(root: string, args: string[]): Promise<string> {
  const result = await exec('git', ['-C', root, ...args], { maxBuffer: 32 * 1024 * 1024, encoding: 'utf8' });
  return result.stdout;
}
export async function isGitRoot(root: string): Promise<boolean> {
  try {
    const metadata = await lstat(path.join(root, '.git'));
    if (metadata.isSymbolicLink()) return false;
    return await realpath((await git(root, ['rev-parse', '--show-toplevel'])).trim()) === root;
  }
  catch { return false; }
}
export async function collectFiles(root: string, config: Config, staged: boolean): Promise<{ files: SourceFile[]; warnings: Finding[] }> {
  const files: SourceFile[] = [], warnings: Finding[] = [];
  const custom = ignore().add(config.ignore);
  const warn = (p: string, message: string) => warnings.push({ ruleId: 'scan/skipped-file', severity: 'warn', file: p, line: 1, message, suggestion: 'Inspect this file separately or increase maxFileBytes.' });
  async function add(p: string, index = false) {
    if (builtins.ignores(p) || custom.ignores(p)) return;
    // Index blobs are read without touching working-tree paths, including symlinks.
    if (!index && !await safeFile(root, p)) return;
    const content = index ? await git(root, ['show', `:${p}`]) : await (async () => {
      if ((await lstat(path.join(root, p))).size > config.maxFileBytes) { warn(p, 'File exceeds the configured scan size limit.'); return undefined; }
      return readFile(path.join(root, p), 'utf8');
    })();
    if (content === undefined) return;
    if (Buffer.byteLength(content) > config.maxFileBytes) { warn(p, 'File exceeds the configured scan size limit.'); return; }
    if (!content.includes('\0')) files.push({ path: p, content });
  }
  if (staged) {
    if (!await isGitRoot(root)) throw new Error('--staged requires the selected directory to be a Git repository root');
    const names = (await git(root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'])).split('\0').filter(Boolean);
    const modes = new Map((await git(root, ['ls-files', '--stage', '-z'])).split('\0').filter(Boolean).map(row => [row.slice(row.indexOf('\t') + 1), row.slice(0, 6)]));
    const indexIgnores: { base: string; matcher: ReturnType<typeof ignore> }[] = [];
    for (const [p, mode] of [...modes].sort(([a], [b]) => a.split('/').length - b.split('/').length)) {
      if (path.posix.basename(p) !== '.gitignore' || !['100644', '100755'].includes(mode)) continue;
      const content = await git(root, ['show', `:${p}`]);
      if (Buffer.byteLength(content) > config.maxFileBytes) { warn(p, 'Index ignore file exceeds the configured size limit.'); continue; }
      indexIgnores.push({ base: path.posix.dirname(p), matcher: ignore().add(content) });
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
      if (!ignored) await add(p, true);
    }
  } else {
    async function walk(dir: string, inherited: { base: string; matcher: ReturnType<typeof ignore> }[]) {
      const rules = [...inherited];
      const name = dir ? `${dir}/.gitignore` : '.gitignore';
      if (await safeFile(root, name)) rules.push({ base: dir, matcher: ignore().add(await readFile(path.join(root, name), 'utf8')) });
      const entries = await readdir(path.join(root, dir), { withFileTypes: true });
      for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
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
        if (ignored) continue;
        if (entry.isDirectory()) await walk(p, rules);
        else if (entry.isFile()) await add(p);
      }
    }
    await walk('', []);
  }
  return { files: files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0), warnings };
}
