import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import dgram from 'node:dgram';
import dns from 'node:dns';

export const MACOS_SEATBELT_PROFILE = '(version 1)(allow default)(deny network*)';

let guardInstalled = false;

export function createZeroNetworkError(api: string): Error & { code: string } {
  const err = new Error(
    `Outbound network access (${api}) is blocked by ci-guard-mcp zero-network policy`,
  ) as Error & { code: string };
  err.code = 'ERR_CI_GUARD_NETWORK_DISABLED';
  return err;
}

/**
 * Installs an in-process runtime lockdown blocking TCP, TLS, HTTP/S, HTTP/2, UDP, DNS, and fetch.
 */
export function installZeroNetworkGuard(): void {
  if (guardInstalled) return;
  guardInstalled = true;

  const block = (api: string) => () => {
    throw createZeroNetworkError(api);
  };

  globalThis.fetch = (async () => {
    throw createZeroNetworkError('fetch');
  }) as typeof fetch;

  net.Socket.prototype.connect = block('net.Socket.connect') as unknown as typeof net.Socket.prototype.connect;
  tls.connect = block('tls.connect') as unknown as typeof tls.connect;
  http.request = block('http.request') as unknown as typeof http.request;
  http.get = block('http.get') as unknown as typeof http.get;
  https.request = block('https.request') as unknown as typeof https.request;
  https.get = block('https.get') as unknown as typeof https.get;
  http2.connect = block('http2.connect') as unknown as typeof http2.connect;
  dgram.Socket.prototype.send = block('dgram.Socket.send') as unknown as typeof dgram.Socket.prototype.send;
  dns.lookup = block('dns.lookup') as unknown as typeof dns.lookup;
}

function canUseLinuxNetns(): boolean {
  if (process.platform !== 'linux') return false;
  try {
    const probe = spawnSync('unshare', ['-r', '-n', 'true'], { stdio: 'ignore', timeout: 2000 });
    return probe.status === 0;
  } catch {
    return false;
  }
}

/**
 * Spawns a command inside an OS-boundary egress-deny sandbox:
 * - macOS: `/usr/bin/sandbox-exec` with `(deny network*)`
 * - Linux: `unshare -r -n` network namespace isolation (when available)
 * Plus sets `CI_GUARD_SANDBOX_ACTIVE=1` so the child process activates `installZeroNetworkGuard()`.
 */
export function spawnInOsSandbox(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
  const childEnv: NodeJS.ProcessEnv = { ...env, CI_GUARD_SANDBOX_ACTIVE: '1' };
  let bin = command;
  let binArgs = args;

  if (process.platform === 'darwin') {
    bin = '/usr/bin/sandbox-exec';
    binArgs = ['-p', MACOS_SEATBELT_PROFILE, command, ...args];
  } else if (canUseLinuxNetns()) {
    bin = 'unshare';
    binArgs = ['-r', '-n', command, ...args];
  }

  return new Promise<number>((resolve, reject) => {
    const child = spawn(bin, binArgs, {
      stdio: 'inherit',
      env: childEnv,
      windowsHide: true,
    });
    child.once('error', reject);
    child.once('close', code => resolve(code ?? 2));
  });
}
