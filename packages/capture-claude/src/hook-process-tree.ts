// packages/capture-claude/src/hook-process-tree.ts
//
// Host context for a capture record: the parent process chain and the
// controlling TTY. Both are stable for the life of a Claude Code session,
// so they are looked up once per session and cached.
//
// The chain used to cost one `ps` per generation, up to ten processes
// spawned per hook invocation, which dominated the hook's latency: the
// pre hook took 180 ms against the post hook's 60 ms and the difference
// was almost entirely process spawns. It is now one `ps` listing every
// process, parsed into a pid map that the walk follows. On Linux the
// listing is skipped entirely in favour of /proc, which costs no
// process at all.

import { execFileSync } from 'node:child_process';
import { readFileSync, readlinkSync } from 'node:fs';
import type { ProcessNode } from '@depose/core';

const processTreeCache = new Map<string, ProcessNode[]>();
const ttyCache = new Map<string, string | null>();

/** How far up the chain to walk before giving up. */
const MAX_DEPTH = 10;

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

/** One process, as read from /proc or from a `ps` listing. */
interface ProcessRow {
  ppid: number;
  comm: string;
}

/**
 * Walk the parent process chain from this process upward.
 *
 * @returns The chain, stopping at init, at a cycle, or at MAX_DEPTH.
 *   Best-effort: an unreadable process ends the walk rather than failing
 *   the capture.
 */
export function walkProcessTree(): ProcessNode[] {
  const lookup = processTable();
  const tree: ProcessNode[] = [];
  const seen = new Set<number>();
  let pid = process.pid;

  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    if (seen.has(pid)) break;
    seen.add(pid);
    const row = lookup(pid);
    if (!row) break;
    tree.push({ pid, ppid: row.ppid, exe: row.comm, argv0: row.comm });
    if (row.ppid === 0 || row.ppid === 1 || seen.has(row.ppid)) break;
    pid = row.ppid;
  }
  return tree;
}

/**
 * A pid lookup for this host.
 *
 * On Linux each process is one small read from /proc, so nothing is
 * spawned and nothing is listed up front. Elsewhere one `ps` lists every
 * process and the result is indexed; the walk then costs no processes at
 * all past the first.
 */
function processTable(): (pid: number) => ProcessRow | null {
  if (process.platform === 'linux') {
    return readProcStat;
  }
  const table = psSnapshot();
  return (pid) => table.get(pid) ?? null;
}

/**
 * Read one process's parent and name from /proc/<pid>/stat.
 *
 * The comm field is parenthesized and may itself contain spaces and
 * parentheses, so the split starts after the last ')' rather than at the
 * second field.
 */
function readProcStat(pid: number): ProcessRow | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
    const open = stat.indexOf('(');
    const close = stat.lastIndexOf(')');
    if (open < 0 || close < open) return null;
    const comm = stat.slice(open + 1, close);
    const fields = stat.slice(close + 2).split(' ');
    const ppid = Number.parseInt(fields[1] ?? '0', 10);
    return { ppid: Number.isNaN(ppid) ? 0 : ppid, comm };
  } catch {
    return null;
  }
}

/**
 * One `ps` listing every process, indexed by pid.
 *
 * @returns pid to (ppid, comm). Empty when `ps` is unavailable.
 */
function psSnapshot(): Map<number, ProcessRow> {
  const table = new Map<number, ProcessRow>();
  let output: string;
  try {
    output = execFileSync('ps', ['-Ao', 'pid=,ppid=,comm='], {
      encoding: 'utf-8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return table;
  }
  for (const line of output.split('\n')) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    if (!match) continue;
    table.set(Number(match[1]), { ppid: Number(match[2]), comm: (match[3] ?? '').trim() });
  }
  return table;
}

/**
 * Resolve the TTY identifier for the current process.
 *
 * On Linux /dev/fd/0 is a symlink into /proc and reading it costs no
 * process. macOS makes it a device file, so there the `tty` command is
 * still spawned; the result is cached per session either way, so it
 * happens once.
 *
 * @returns The TTY device path or null when there is no terminal.
 */
export function resolveTty(): string | null {
  try {
    const target = readlinkSync('/dev/fd/0');
    if (target.startsWith('/dev/')) return target;
    // A redirected stdin points at a file or a pipe, not a terminal.
    return null;
  } catch {
    // Not a symlink on this platform; ask `tty`.
  }
  try {
    const tty = execFileSync('tty', [], {
      encoding: 'utf-8',
      timeout: 2000,
      stdio: ['inherit', 'pipe', 'ignore'],
    }).trim();
    return tty || null;
  } catch {
    return null;
  }
}
