// packages/core/src/normalize/merge-support.ts
//
// Small shared helpers for the merge pass: the event constructor, the
// binary search used to enter the correlation window, and argv rendering
// for gap messages.

import type { AgentId, Event, CaptureFailedPayload, GapPayload } from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { ulidFromTime } from '../events/ids.js';

// ── Event builder (shared) ───────────────────────────────────────────

interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: string;
  parentEventId: string | null;
  monoNs: number | bigint;
  wallTs: string;
  payload: unknown;
}

export function buildEvent(params: BuildEventParams): Event {
  const { sessionId, agentId, type, parentEventId, monoNs, wallTs, payload } = params;
  const id = ulidFromTime(new Date(wallTs).getTime());
  const payloadHash = sha256(payload);
  return {
    id,
    wallTs,
    monoNs: BigInt(monoNs),
    sessionId,
    agentId,
    parentEventId,
    type: type as Event['type'],
    payload,
    payloadHash,
  } as Event;
}
/**
 * Index of the first event in a time-sorted list whose wallTs is at or
 * after `targetMs`. Standard binary search lower bound.
 */
export function lowerBound(sorted: Event[], targetMs: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (Date.parse(sorted[mid]!.wallTs) < targetMs) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

/**
 * Render argv for a gap message, capped in length.
 *
 * The gap event names the pre-capture it describes in affectedEventIds, and
 * that event carries the full argv, so this string is a readable pointer and
 * not the record of the command. Uncapped it duplicated every command line
 * in the bundle, which on a contaminated run was a large share of a 47MB
 * events.jsonl.
 */
export function truncateArgv(argv: string[], maxChars = 200): string {
  const joined = argv.join(' ');
  if (joined.length <= maxChars) return joined;
  return `${joined.slice(0, maxChars)}... (${joined.length} chars, full argv in the linked event)`;
}


/**
 * Turn a capture_failed event into the gap event the timeline carries.
 *
 * The gap keeps the record's id so raw/captures/<id>.json in the bundle
 * is the source record for the gap, and the failure's own capture time so
 * it sorts where the lost capture would have been.
 *
 * @param event - A capture_failed event from the capture store.
 * @returns The equivalent gap event with reason `capture_failed`.
 */
export function captureFailedToGap(event: Event): Event {
  const failure = event.payload as CaptureFailedPayload;
  const tool = failure.toolName ? ` while capturing ${failure.toolName}` : '';
  const payload: GapPayload = {
    reason: 'capture_failed',
    affectedEventIds: [],
    detail:
      `The capture hook threw ${failure.errorClass} in phase "${failure.phase}"${tool} ` +
      `at ${failure.capturedAt} and wrote no capture record: ${failure.message}. ` +
      `Whatever the agent ran at that moment has no pre-execution record.`,
  };
  return {
    id: event.id,
    wallTs: event.wallTs,
    monoNs: event.monoNs,
    sessionId: event.sessionId,
    agentId: event.agentId,
    parentEventId: null,
    type: 'gap',
    payload,
    payloadHash: sha256(payload),
  };
}
