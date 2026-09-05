// packages/core/src/normalize/claude-code-build-event.ts
//
// Shared event constructor for the Claude Code normalizers. Both the flat
// and real-session paths build events the same way, so the id derivation
// and payload hashing live in one place.

import type { AgentId, Event, EventBase, EventType } from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { ulidFromTime } from '../events/ids.js';

// ── Event builder ────────────────────────────────────────────────────

export interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: EventType;
  parentEventId: string | null;
  monoNs: number | bigint;
  wallTs: string;
  payload: unknown;
}

export function buildEvent(params: BuildEventParams): Event {
  const { sessionId, agentId, type, parentEventId, monoNs, wallTs, payload } = params;
  // F-03: Use wallTs as the timestamp source instead of Date.now()
  const id = ulidFromTime(new Date(wallTs).getTime());
  const payloadHash = sha256(payload);
  const base: EventBase = {
    id,
    wallTs,
    monoNs: BigInt(monoNs),
    sessionId,
    agentId,
    parentEventId,
    type,
    payload,
    payloadHash,
  };
  return { ...base, type, payload } as Event;
}
