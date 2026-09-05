// packages/core/src/normalize/merge-kernel.ts
//
// Correlates kernel-witnessed execve records with the hook's intents.
//
// The hook only sees what Claude Code tells it. threat-model.md §6 lists
// what that misses: a command invoked by absolute path through a shim that
// was never on PATH, a Python subprocess.run with shell=False, a static
// binary that execs a child of its own. The eBPF collector sees all of
// them, because the kernel does.
//
// An execve that lines up with an intent (an ancestor in common, inside the
// match window) is attributed to it. One that does not is left standing on
// its own and gets a gap, so the difference between "the agent ran this"
// and "something in the agent's process tree ran this and no hook saw it"
// is visible in the timeline rather than silently absent.

import type {
  AgentId,
  Event,
  ShellCommandPrePayload,
  ProcessSpawnPayload,
  GapPayload,
} from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { buildEvent, truncateArgv } from './merge-support.js';

/** Options for the kernel correlation pass. */
export interface KernelCorrelationOptions {
  sessionId: string;
  agentId: AgentId;
  /** Seconds after an intent within which its execve is expected. */
  matchWindowSeconds: number;
}

/** What the pass produced. */
export interface KernelCorrelationResult {
  /** Gap events for execves no hook witnessed. */
  gaps: Event[];
  /** Execves attributed to a hook intent. */
  matchedCount: number;
  /** Execves with no hook intent to attribute them to. */
  unwitnessedCount: number;
}

/**
 * Attribute kernel execve events to hook intents, and report the ones that
 * cannot be attributed.
 *
 * Mutates matched execve payloads in place to record the intent id, then
 * recomputes their payload hashes so the chain pass sees the final form.
 *
 * @param sorted - The merged timeline, ordered by (wallTs, monoNs).
 * @param options - Session, agent, and the correlation window.
 * @returns Gap events plus the matched and unwitnessed counts.
 */
export function correlateKernelExecves(
  sorted: Event[],
  options: KernelCorrelationOptions
): KernelCorrelationResult {
  const execves = sorted.filter(
    (e) => e.type === 'process_spawn' && (e.payload as ProcessSpawnPayload).source === 'kernel'
  );
  if (execves.length === 0) {
    return { gaps: [], matchedCount: 0, unwitnessedCount: 0 };
  }

  const intents = sorted
    .filter((e) => e.type === 'shell_command_pre')
    .map((event) => ({
      event,
      pids: processTreePids(event.payload as ShellCommandPrePayload),
      atMs: Date.parse(event.wallTs),
    }));

  const gaps: Event[] = [];
  let matchedCount = 0;
  let unwitnessedCount = 0;
  const windowMs = options.matchWindowSeconds * 1000;

  for (const execve of execves) {
    const payload = execve.payload as ProcessSpawnPayload;
    const ancestry = new Set<number>([payload.pid, payload.ppid, ...(payload.ancestry ?? [])]);
    const atMs = Date.parse(execve.wallTs);

    let best: Event | undefined;
    let bestDelta = Number.POSITIVE_INFINITY;
    for (const candidate of intents) {
      const delta = atMs - candidate.atMs;
      // An execve precedes its intent only by clock skew, so the window is
      // asymmetric: a full window forward, a second of slack backward.
      if (delta > windowMs || delta < -1000 || Math.abs(delta) >= bestDelta) continue;
      if (!sharesAncestor(ancestry, candidate.pids)) continue;
      best = candidate.event;
      bestDelta = Math.abs(delta);
    }

    if (best) {
      payload.matchedIntentEventId = best.id;
      execve.payloadHash = sha256(payload);
      execve.correlation = { ...execve.correlation, linkedShellCommandPreId: best.id };
      matchedCount++;
      continue;
    }
    payload.matchedIntentEventId = null;
    execve.payloadHash = sha256(payload);
    gaps.push(unwitnessedExecve(execve, payload, options));
    unwitnessedCount++;
  }

  return { gaps, matchedCount, unwitnessedCount };
}

/** Every pid the hook recorded in the capturing process's ancestry. */
function processTreePids(payload: ShellCommandPrePayload): Set<number> {
  const pids = new Set<number>();
  for (const node of payload.parentProcessTree ?? []) {
    pids.add(node.pid);
    pids.add(node.ppid);
  }
  return pids;
}

function sharesAncestor(ancestry: Set<number>, intentPids: Set<number>): boolean {
  for (const pid of ancestry) {
    if (intentPids.has(pid)) return true;
  }
  return false;
}

function unwitnessedExecve(
  execve: Event,
  payload: ProcessSpawnPayload,
  options: KernelCorrelationOptions
): Event {
  const gap: GapPayload = {
    reason: 'kernel_execve_without_hook',
    affectedEventIds: [execve.id],
    detail:
      `The kernel witnessed ${truncateArgv(payload.argv.length > 0 ? payload.argv : [payload.exe])} ` +
      `(pid ${payload.pid}, parent ${payload.ppid}) in the agent's process tree at ${execve.wallTs}, ` +
      `and no hook or shim recorded it. This is a command that ran outside the capture surface.`,
  };
  return buildEvent({
    sessionId: options.sessionId,
    agentId: options.agentId,
    type: 'gap',
    parentEventId: execve.id,
    monoNs: execve.monoNs + 1n,
    wallTs: execve.wallTs,
    payload: gap,
  });
}
