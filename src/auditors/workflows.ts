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
 * Extracts unquoted expression tokens from `${{ ... }}` blocks using a single-quote-aware lexer
 * (recognizing `''` escaped single quotes so `}}` inside string literals cannot prematurely close
 * the expression, fixing A3).
 */
function extractExpressionTokens(value: string, preserveKeys: RegExp): string[] {
  const expressions: string[] = [];
  let cursor = 0;
  const maxLen = value.length;

  while (cursor < maxLen) {
    const start = value.indexOf('${{', cursor);
    if (start < 0) break;

    let i = start + 3;
    let inSingleQuote = false;
    let unquotedTokens = '';
    let currentQuoteContent = '';
    let closed = false;

    while (i < maxLen) {
      const ch = value[i]!;
      if (inSingleQuote) {
        if (ch === "'") {
          if (i + 1 < maxLen && value[i + 1] === "'") {
            currentQuoteContent += "'";
            i += 2;
            continue;
          }
          inSingleQuote = false;
          if (preserveKeys.test(currentQuoteContent.trim())) {
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
      break;
    }

    expressions.push(unquotedTokens);
  }

  return expressions;
}

/**
 * Scans a string for GitHub Actions `${{ ... }}` expressions referencing untrusted event inputs.
 */
export function isUntrusted(value: string): boolean {
  const expressions = extractExpressionTokens(value, /^(?:event|head_ref)$/i);
  return expressions.some(hasUntrustedGitHubReference);
}

/**
 * Detects direct `${{ secrets.* }}` or `${{ toJSON(secrets) }}` interpolation inside a shell `run:` block.
 */
export function hasDirectSecretInterpolation(value: string): boolean {
  const expressions = extractExpressionTokens(value, /^[a-z0-9_]+$/i);
  return expressions.some(expr =>
    /\bsecrets\s*(?:\.\s*[a-zA-Z0-9_-]+|\[\s*['"][^'"]+['"]\s*\])/i.test(expr) ||
    /\btoJSON\s*\(\s*secrets\s*\)/i.test(expr),
  );
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

const GITLAB_UNTRUSTED_VAR_REGEX =
  /\$(?:\{)?(?:CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|TARGET_BRANCH_NAME|LABELS)|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME|CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|BRANCH|REF_NAME|TAG))\b/i;

const GITLAB_MR_HEAD_CHECKOUT_REGEX =
  /\bgit\s+(?:checkout|fetch|pull)\b[^\n]*\$(?:\{)?(?:CI_MERGE_REQUEST_(?:SOURCE_BRANCH_SHA|REF_PATH|SOURCE_BRANCH_NAME)|CI_EXTERNAL_PULL_REQUEST_SOURCE_COMMIT_SHA)\b/i;

const GITLAB_RESERVED_TOP_KEYS = new Set([
  'stages',
  'variables',
  'default',
  'include',
  'workflow',
  'image',
  'services',
  'before_script',
  'after_script',
  'cache',
  'pages',
]);

function isGitHubWorkflowPath(p: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p);
}

function isGitLabWorkflowPath(p: string): boolean {
  return /^\.gitlab-ci\.ya?ml$/.test(p) || /^\.gitlab\/ci\/[^/]+\.ya?ml$/.test(p);
}

export function auditWorkflows({ files, config }: AuditContext): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    const isGitHub = isGitHubWorkflowPath(file.path);
    const isGitLab = !isGitHub && isGitLabWorkflowPath(file.path);
    if (!isGitHub && !isGitLab) continue;

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
        isGitHub ? 'Define on and jobs as workflow keys.' : 'Define stages and jobs as top-level keys.',
      );
      continue;
    }

    if (isGitLab) {
      auditGitLabDocument(top, get, scalar, values, resolve, emit);
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
        const runText = scalar(run);
        if (isUntrusted(runText)) {
          emit(
            'workflow/script-injection',
            'error',
            run,
            'Untrusted GitHub context is interpolated directly into a shell script.',
            'Pass event fields through step env and use quoted shell variables.',
          );
        }
        if (hasDirectSecretInterpolation(runText)) {
          emit(
            'workflow/secret-exfiltration',
            'error',
            run,
            'GitHub secret context is interpolated directly into a shell script where it may leak to build logs or process arguments.',
            'Bind secrets to step env variables and reference them as quoted shell variables without echoing.',
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

function auditGitLabDocument(
  top: unknown,
  get: (node: unknown, key: string) => unknown,
  scalar: (node: unknown) => string,
  values: (node: unknown) => unknown[],
  resolve: (node: unknown) => unknown,
  emit: (
    ruleId: string,
    severity: Finding['severity'],
    node: unknown,
    message: string,
    suggestion: string,
  ) => void,
): void {
  const inspectImage = (imageNode: unknown) => {
    if (!imageNode) return;
    const targetNode = isMap(imageNode) ? get(imageNode, 'name') : imageNode;
    const image = scalar(targetNode);
    if (!image) return;
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      emit(
        'workflow/unpinned-action',
        'warn',
        targetNode ?? imageNode,
        'GitLab CI container image is not pinned to an immutable sha256 digest.',
        'Pin container images to image@sha256:<64-hex-digest>.',
      );
    }
  };

  inspectImage(get(top, 'image'));
  inspectImage(get(get(top, 'default'), 'image'));

  const includeNode = get(top, 'include');
  const includeItems = isSeq(includeNode) ? includeNode.items.map(resolve) : includeNode ? [includeNode] : [];
  for (const item of includeItems) {
    if (isScalar(item)) {
      const val = scalar(item);
      if (/^https?:\/\//i.test(val) && !/[/@][a-f0-9]{40}(?:\/|$)/i.test(val)) {
        emit(
          'workflow/unpinned-action',
          'warn',
          item,
          'External GitLab CI include URL is not pinned to an immutable 40-character commit SHA.',
          'Pin remote includes to an immutable 40-character commit SHA.',
        );
      }
    } else if (isMap(item)) {
      const remote = get(item, 'remote');
      if (remote && !/[/@][a-f0-9]{40}(?:\/|$)/i.test(scalar(remote))) {
        emit(
          'workflow/unpinned-action',
          'warn',
          remote,
          'Remote GitLab CI template is not pinned to an immutable 40-character commit SHA.',
          'Use a commit-pinned URL for remote includes.',
        );
      }
      const project = get(item, 'project');
      if (project) {
        const ref = get(item, 'ref');
        if (!/^[a-f0-9]{40}$/i.test(scalar(ref))) {
          emit(
            'workflow/unpinned-action',
            'warn',
            ref ?? item,
            'Cross-project GitLab CI include is not pinned to a 40-character commit SHA.',
            'Add ref: "<40-char-commit-sha>" to the project include.',
          );
        }
      }
      const component = get(item, 'component');
      if (component && !/@[a-f0-9]{40}$/i.test(scalar(component))) {
        emit(
          'workflow/unpinned-action',
          'warn',
          component,
          'GitLab CI component is not pinned to a 40-character commit SHA.',
          'Pin the component version after @ to a 40-character commit SHA.',
        );
      }
    }
  }

  if (!isMap(top)) return;
  for (const pair of top.items) {
    const jobKey = baseScalar(pair.key);
    if (!jobKey || jobKey.startsWith('.') || GITLAB_RESERVED_TOP_KEYS.has(jobKey)) continue;
    const job = resolve(pair.value);
    if (!isMap(job)) continue;

    inspectImage(get(job, 'image'));

    for (const scriptKey of ['before_script', 'script', 'after_script']) {
      const scriptNode = get(job, scriptKey);
      const lines = isSeq(scriptNode)
        ? scriptNode.items.map(resolve)
        : isScalar(scriptNode)
          ? [scriptNode]
          : [];
      for (const lineNode of lines) {
        const cmd = scalar(lineNode);
        if (!cmd) continue;
        if (GITLAB_UNTRUSTED_VAR_REGEX.test(cmd)) {
          emit(
            'workflow/script-injection',
            'error',
            lineNode,
            'Untrusted GitLab merge request or commit metadata variable is interpolated directly into a shell script.',
            'Pass untrusted CI variables as environment variables without direct shell expansion.',
          );
        }
        if (GITLAB_MR_HEAD_CHECKOUT_REGEX.test(cmd)) {
          emit(
            'workflow/pwn-request',
            'error',
            lineNode,
            'GitLab CI job checks out untrusted merge request source code directly inside a script step.',
            'Isolate untrusted fork merge request jobs from protected variables and privileged runners.',
          );
        }
      }
    }
  }
}
