// packages/core/src/normalize/merge-support.ts
//
// Small shared helpers for the merge pass: the event constructor, the
// binary search used to enter the correlation window, and argv rendering
// for gap messages.

import type { AgentId, Event } from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { ulidFromTime } from '../events/ids.js';

// ── Event builder (shared) ───────────────────────────────────────────

interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: string;
  parentEventId: string | null;
  monoNs: number;
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
    monoNs,
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

