// packages/core/src/normalize/capture-events.ts
//
// One capture-store record in, one Event out. The store holds four record
// kinds and they are told apart by their shape, not by their filename:
//
//   command       a ShellCommandPrePayload, the intent half of a tool call
//   effect        a ToolCallEffectPayload, the effect half that closes it
//   execve        an ExecveRecordPayload from the kernel collector
//   capture_failed  the hook or collector could not record at all
//
// Scoping (does this record belong to the session being reconstructed)
// lives in capture-scope.ts; the directory walk lives in capture.ts.

import type {
  AgentId,
  Event,
  CaptureFailedPayload,
  ToolCallEffectPayload,
  ExecveRecordPayload,
  ProcessSpawnPayload,
} from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import {
  upgradeRecord,
  readCaptureFailed,
  readEffectRecord,
  readExecveRecord,
  classify,
  type CaptureExclusionReason,
  type CaptureScope,
  type ScopeBounds,
} from './capture-scope.js';

/** Everything the record-to-event mapping needs beyond the record itself. */
export interface RecordContext {
  /** Session id stamped onto every event this bundle carries. */
  sessionId: string;
  agentId: AgentId;
  scope: CaptureScope | undefined;
  bounds: ScopeBounds | null;
  /** Tie-breaker for same-millisecond records; increments per accepted record. */
  monoNs: number;
}

/** What became of one record. */
export type RecordOutcome =
  | { kind: 'event'; event: Event }
  | { kind: 'excluded'; reason: CaptureExclusionReason; warning?: string };

/**
 * Convert one parsed capture-store record into an Event, or say why it was
 * left out.
 *
 * @param ulid - The record's ULID, which becomes the event id.
 * @param raw - Parsed JSON from the record file.
 * @param mtimeMs - The file's mtime, used to date v1 command records.
 * @param ctx - Session, agent, scope, and the monotonic tie-breaker.
 * @returns The event, or the exclusion reason with an optional warning.
 */
export function recordToEvent(
  ulid: string,
  raw: unknown,
  mtimeMs: number,
  ctx: RecordContext
): RecordOutcome {
  const failed = readCaptureFailed(raw);
  if (failed) {
    const decision = classify(failed, ctx.scope, ctx.bounds);
    if (decision !== 'include') return { kind: 'excluded', reason: decision };
    return { kind: 'event', event: captureFailedEvent(ulid, failed, ctx) };
  }

  const effect = readEffectRecord(raw);
  if (effect) {
    const decision = classify(effect, ctx.scope, ctx.bounds);
    if (decision !== 'include') return { kind: 'excluded', reason: decision };
    return { kind: 'event', event: baseEvent(ulid, effect.capturedAt, 'tool_call_effect', effect, ctx) };
  }

  const execve = readExecveRecord(raw);
  if (execve) {
    const decision = classify(execve, ctx.scope, ctx.bounds);
    if (decision !== 'include') return { kind: 'excluded', reason: decision };
    return { kind: 'event', event: execveEvent(ulid, execve, ctx) };
  }

  const command = upgradeRecord(raw, mtimeMs);
  if (!command) {
    return { kind: 'excluded', reason: 'malformed', warning: 'missing or invalid argv' };
  }
  const decision = classify(command, ctx.scope, ctx.bounds);
  if (decision !== 'include') return { kind: 'excluded', reason: decision };
  return {
    kind: 'event',
    event: {
      ...baseEvent(ulid, command.capturedAt, 'shell_command_pre', command, ctx),
      agentId: command.source === 'shell-shim' ? 'shell' : ctx.agentId,
    } as Event,
  };
}

/**
 * Build the gap-bound event for a hook or collector failure.
 *
 * @param id - The record's ULID.
 * @param payload - The validated capture_failed payload.
 * @param ctx - Session, agent, and the monotonic tie-breaker.
 * @returns A capture_failed event; the merge turns it into a gap.
 */
export function captureFailedEvent(
  id: string,
  payload: CaptureFailedPayload,
  ctx: RecordContext
): Event {
  return baseEvent(id, payload.capturedAt, 'capture_failed', payload, ctx);
}

/**
 * A kernel execve record becomes a process_spawn event tagged `kernel`.
 * The correlation to a hook intent happens later, in the merge.
 */
function execveEvent(id: string, record: ExecveRecordPayload, ctx: RecordContext): Event {
  const payload: ProcessSpawnPayload = {
    pid: record.pid,
    ppid: record.ppid,
    exe: record.exe,
    argv: record.argv,
    cwd: record.cwd,
    comm: record.comm,
    ancestry: record.ancestry,
    monoNs: record.monoNs,
    source: 'kernel',
    matchedIntentEventId: null,
  };
  return baseEvent(id, record.capturedAt, 'process_spawn', payload, ctx);
}

function baseEvent(
  id: string,
  wallTs: string,
  type: Event['type'],
  payload: ToolCallEffectPayload | CaptureFailedPayload | ProcessSpawnPayload | unknown,
  ctx: RecordContext
): Event {
  return {
    id,
    wallTs,
    // Tie-breaker only. Real ordering comes from wallTs; this keeps
    // same-millisecond captures stable, and files are read in ULID order,
    // which is capture order.
    monoNs: BigInt(ctx.monoNs),
    sessionId: ctx.sessionId,
    agentId: ctx.agentId,
    parentEventId: null,
    type,
    payload,
    payloadHash: sha256(payload),
  } as Event;
}
