// packages/capture-claude/src/hook-process-tree.ts
//
// Host context for a capture record: the parent process chain and the
// controlling TTY. Both are stable for the life of a Claude Code session,
// so they are looked up once per session and cached.

import { execSync } from 'node:child_process';
import type { ProcessNode } from '@depose/core';

const processTreeCache = new Map<string, ProcessNode[]>();
const ttyCache = new Map<string, string | null>();

/**
 * Clear the per-session caches. Useful for testing.
 */
export function clearProcessTreeCache(): void {
  processTreeCache.clear();
  ttyCache.clear();
}

/**
 * Get the cached process tree for a session, or compute and cache it.
 *
 * @param sessionId - The agent session the hook is serving.
 * @param walk - The tree walker to use on a cache miss.
 * @returns The parent process chain, best-effort.
 */
export function getCachedProcessTree(
  sessionId: string,
  walk: () => ProcessNode[] = walkProcessTree
): ProcessNode[] {
  const cached = processTreeCache.get(sessionId);
  if (cached !== undefined) {
    return cached;
  }
  const tree = walk();
  processTreeCache.set(sessionId, tree);
  return tree;
}

/**
 * Get the cached TTY for a session, or resolve and cache it.
 *
 * @param sessionId - The agent session the hook is serving.
 * @param resolve - The resolver to use on a cache miss.
 * @returns The TTY device path or null.
 */
export function getCachedTty(
  sessionId: string,
  resolve: () => string | null = resolveTty
): string | null {
  const cached = ttyCache.get(sessionId);
  if (cached !== undefined) {
    return cached;
  }
  const tty = resolve();
  ttyCache.set(sessionId, tty);
  return tty;
}

/**
 * Walk the parent process tree (best-effort, macOS/Linux).
 *
 * @returns The chain from this process upward, stopping at init or a loop.
 */
export function walkProcessTree(): ProcessNode[] {
  const tree: ProcessNode[] = [];
  try {
    let currentPid = process.pid;
    const seen = new Set<number>();
    for (let i = 0; i < 10; i++) {
      if (seen.has(currentPid)) break;
      seen.add(currentPid);
      const node = getProcessNode(currentPid);
      if (!node) break;
      tree.push(node);
      if (node.ppid === 0 || node.ppid === 1 || seen.has(node.ppid)) break;
      currentPid = node.ppid;
    }
  } catch {
    // Best-effort; return whatever we got
  }
  return tree;
}

/**
 * Get a ProcessNode for a given PID using `ps`.
 * Best-effort, returns null on failure.
 */
function getProcessNode(pid: number): ProcessNode | null {
  try {
    const output = execSync(
      `ps -o ppid=,comm= -p ${pid} 2>/dev/null`,
      { encoding: 'utf-8', timeout: 2000 }
    ).trim();
    if (!output) return null;
    const parts = output.split(/\s+/);
    const ppid = parseInt(parts[0] || '0', 10);
    const exe = parts.slice(1).join(' ');
    return { pid, ppid, exe, argv0: exe };
  } catch {
    return null;
  }
}

/**
 * Resolve the TTY identifier for the current process.
 *
 * @returns The TTY device path or null when there is no terminal.
 */
export function resolveTty(): string | null {
  try {
    const tty = execSync('tty 2>/dev/null', { encoding: 'utf-8' }).trim();
    return tty || null;
  } catch {
    return null;
  }
}
