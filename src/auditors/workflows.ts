import { parseDocument, LineCounter, isMap, isSeq, isScalar, isAlias } from 'yaml';
import type { Node } from 'yaml';
import type { AuditContext, Finding } from '../types.js';

function baseGet(node: unknown, key: string): unknown {
  return isMap(node) ? node.get(key, true) : undefined;
}
function baseScalar(node: unknown): string {
  return isScalar(node) ? String(node.value ?? '') : '';
}
function baseValues(node: unknown): unknown[] {
  return isMap(node) ? node.items.map(p => p.value) : isSeq(node) ? node.items : [];
}

/**
 * Scans a string for GitHub Actions `${{ ... }}` expressions using a single-quote-aware
 * lexer (recognizing `''` escaped single quotes so `}}` inside string literals cannot
 * prematurely close the expression, fixing A3).
 */
export function isUntrusted(value: string): boolean {
  let cursor = 0;
  const maxLen = value.length;

  while (cursor < maxLen) {
    const start = value.indexOf('${{', cursor);
    if (start < 0) return false;

    let i = start + 3;
    let inSingleQuote = false;
    let unquotedTokens = '';
    let currentQuoteContent = '';
    let closed = false;

    while (i < maxLen) {
      const ch = value[i]!;
      if (inSingleQuote) {
        if (ch === "'") {
          // Doubled single-quote escape inside GitHub Actions string literal
          if (i + 1 < maxLen && value[i + 1] === "'") {
            currentQuoteContent += "'";
            i += 2;
            continue;
          }
          inSingleQuote = false;
          // Preserve bracket property access keys like ['event'] or ['head_ref'], strip other string literals
          if (/^(?:event|head_ref)$/i.test(currentQuoteContent.trim())) {
            unquotedTokens += `'${currentQuoteContent.trim()}'`;
          } else {
            unquotedTokens += "''";
          }
          currentQuoteContent = '';
          i++;
          continue;
        }
        currentQuoteContent += ch;
        i++;
        continue;
      }

      if (ch === "'") {
        inSingleQuote = true;
        currentQuoteContent = '';
        i++;
        continue;
      }

      if (ch === '}' && i + 1 < maxLen && value[i + 1] === '}') {
        closed = true;
        cursor = i + 2;
        break;
      }

      unquotedTokens += ch;
      i++;
    }

    if (!closed) {
      return false;
    }

    if (hasUntrustedGitHubReference(unquotedTokens)) {
      return true;
    }
  }

  return false;
}

const SAFE_NUMERIC_EVENT_PATHS =
  /^github\s*\.\s*event\s*\.\s*(?:(?:pull_request|issue|discussion|check_suite|check_run|workflow_run|deployment|release)\s*\.\s*(?:number|id)|number)\b(?![\s.\[])/i;

function hasUntrustedGitHubReference(expr: string): boolean {
  const refPattern =
    /\bgithub\s*(?:\.\s*(?:event|head_ref)\b|\[\s*['"](?:event|head_ref)['"]\s*\])[\w.\s[\]'"]*/gi;
  for (const match of expr.matchAll(refPattern)) {
    const segment = match[0].trim();
    if (SAFE_NUMERIC_EVENT_PATHS.test(segment)) {
      continue;
    }
    return true;
  }
  return false;
}

export function auditWorkflows({ files, config }: AuditContext): Finding[] {
  const findings: Finding[] = [];
  for (const file of files.filter(f => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path))) {
    const lines = new LineCounter();
    const doc = parseDocument(file.content, { lineCounter: lines, uniqueKeys: true });
    const emit = (
      ruleId: string,
      severity: Finding['severity'],
      node: unknown,
      message: string,
      suggestion: string,
    ) => {
      const offset = (node as Node | undefined)?.range?.[0] ?? 0;
      findings.push({
        ruleId,
        severity,
        file: file.path,
        line: lines.linePos(offset).line,
        message,
        suggestion,
      });
    };
    if (doc.errors.length) {
      for (const err of doc.errors) {
        emit(
          'workflow/invalid-yaml',
          'error',
          { range: [err.pos[0]] },
          'Workflow contains invalid or ambiguous YAML.',
          'Fix YAML syntax and duplicate keys.',
        );
      }
      continue;
    }
    const resolve = (node: unknown): unknown => (isAlias(node) ? node.resolve(doc) : node);
    const get = (node: unknown, key: string): unknown => resolve(baseGet(resolve(node), key));
    const scalar = (node: unknown): string => baseScalar(resolve(node));
    const values = (node: unknown): unknown[] => baseValues(resolve(node)).map(resolve);
    const top = doc.contents;
    if (!isMap(top)) {
      emit(
        'workflow/invalid-yaml',
        'error',
        top,
        'Workflow must be a YAML mapping.',
        'Define on and jobs as workflow keys.',
      );
      continue;
    }
    if (!top.has('permissions')) {
      emit(
        'workflow/missing-permissions',
        'warn',
        top,
        'Workflow has no explicit top-level token permissions.',
        'Add permissions: { contents: read } or permissions: {} and grant job permissions explicitly.',
      );
    }
    const trigger = get(top, 'on');
    const privileged =
      scalar(trigger) === 'pull_request_target' ||
      (isSeq(trigger) && trigger.items.some(v => scalar(v) === 'pull_request_target')) ||
      (isMap(trigger) && trigger.has('pull_request_target'));
    for (const job of values(get(top, 'jobs'))) {
      const inspectUses = (uses: unknown) => {
        const action = scalar(uses);
        if (!action || action.startsWith('./')) return;
        const split = action.lastIndexOf('@');
        const name = split < 0 ? action : action.slice(0, split);
        const ref = split < 0 ? '' : action.slice(split + 1);
        const allowed = config.allowActions.some(pattern =>
          pattern.endsWith('/*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern,
        );
        const pinned = action.startsWith('docker://')
          ? /@sha256:[a-f0-9]{64}$/i.test(action)
          : /^[a-f0-9]{40}$/i.test(ref);
        if (!pinned && !allowed) {
          emit(
            'workflow/unpinned-action',
            'warn',
            uses,
            'External action or reusable workflow is not pinned to an immutable digest.',
            'Pin actions to a full 40-character commit SHA and containers to a sha256 digest.',
          );
        }
      };
      inspectUses(get(job, 'uses'));
      for (const step of values(get(job, 'steps'))) {
        const uses = get(step, 'uses');
        inspectUses(uses);
        const run = get(step, 'run');
        if (isUntrusted(scalar(run))) {
          emit(
            'workflow/script-injection',
            'error',
            run,
            'Untrusted GitHub context is interpolated directly into a shell script.',
            'Pass event fields through step env and use quoted shell variables.',
          );
        }
        if (privileged && /^actions\/checkout(?:\/[^@]+)?@/i.test(scalar(uses))) {
          const withNode = get(step, 'with');
          const ref = scalar(get(withNode, 'ref'));
          const repo = scalar(get(withNode, 'repository'));
          const unsafe = [ref, repo].some(isUntrusted);
          if (unsafe) {
            emit(
              'workflow/pwn-request',
              'error',
              withNode,
              'pull_request_target checks out attacker-controlled pull request content with a privileged token context.',
              'Use pull_request for untrusted code or isolate trusted metadata handling without checking out the PR.',
            );
          }
        }
      }
    }
  }
  return findings;
}
