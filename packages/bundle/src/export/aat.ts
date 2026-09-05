// packages/bundle/src/export/aat.ts
//
// Export to draft-sharif-agent-audit-trail-00, the Agent Audit Trail.
//
// AAT is JSON Lines, one record per line, chained by
// prev_hash(N) = hex(SHA-256(JCS(record(N-1)))). DEPOSE has its own
// chain, so the export recomputes AAT's chain over the AAT records
// rather than carrying DEPOSE chain hashes across under a name that
// would mean something different.
//
// Two identifier mismatches are resolved rather than papered over. AAT
// wants UUIDs where DEPOSE has ULIDs, and it names version 4, which
// asserts randomness. The export emits UUIDv8 derived from the ULID
// (RFC 9562 §5.8, custom format) so a reader can recompute the mapping
// and tie a record back to the bundle. What has no AAT equivalent is
// listed in docs/export-mapping.md rather than smuggled into
// action_detail as if the format covered it.

import { canonicalJson, sha256String, type Event } from '@depose/core';
import type { LoadedBundle } from './read-bundle.js';
import {
  aatAction,
  aatOutcome,
  actionDetail,
  uuidFromUlid,
  UUID_NAMESPACE_EVENT,
  UUID_NAMESPACE_SESSION,
} from './aat-map.js';

/** One AAT record. Optional fields are omitted, never null-filled. */
export interface AatRecord {
  record_id: string;
  timestamp: string;
  agent_id: string;
  agent_version: string;
  session_id: string;
  action_type: string;
  action_detail: Record<string, unknown>;
  outcome: string;
  trust_level: string;
  parent_record_id: string | null;
  prev_hash: string | null;
  input_hash?: string;
  output_hash?: string;
  latency_ms?: number;
}

/**
 * Trust level asserted for every DEPOSE record.
 *
 * L2 is "operates under policy with logging", which is what a hook-observed
 * agent is. DEPOSE observes and never enforces, so it cannot honestly
 * assert a level that implies gating. The choice is recorded in
 * docs/export-mapping.md.
 */
export const DEPOSE_TRUST_LEVEL = 'L2';

/**
 * Convert a sealed bundle to AAT JSON Lines.
 *
 * Pure: the same bundle always produces the same bytes.
 *
 * @param bundle - The loaded bundle.
 * @returns The JSONL text, one AAT record per line, newline-terminated.
 */
export function exportAat(bundle: LoadedBundle): string {
  const records = aatRecords(bundle);
  return records.map((record) => JSON.stringify(record)).join('\n') + '\n';
}

/**
 * The AAT records for a bundle, before serialization.
 *
 * @param bundle - The loaded bundle.
 * @returns One record per event, chained in order.
 */
export function aatRecords(bundle: LoadedBundle): AatRecord[] {
  const sessionId = uuidFromUlid(UUID_NAMESPACE_SESSION, bundle.manifest.session.sessionId);
  const agentId = `urn:agent:${bundle.manifest.session.agentId}`;
  const version = bundle.manifest.producer.version;

  const records: AatRecord[] = [];
  let prevHash: string | null = null;
  for (const event of bundle.events) {
    const record = toRecord(event, { sessionId, agentId, version, prevHash });
    records.push(record);
    prevHash = sha256String(canonicalJson(record));
  }
  return records;
}

interface RecordContext {
  sessionId: string;
  agentId: string;
  version: string;
  prevHash: string | null;
}

function toRecord(event: Event, ctx: RecordContext): AatRecord {
  const record: AatRecord = {
    record_id: uuidFromUlid(UUID_NAMESPACE_EVENT, event.id),
    timestamp: event.wallTs,
    agent_id: ctx.agentId,
    agent_version: ctx.version,
    session_id: ctx.sessionId,
    action_type: aatAction(event),
    action_detail: actionDetail(event),
    outcome: aatOutcome(event),
    trust_level: DEPOSE_TRUST_LEVEL,
    parent_record_id: event.parentEventId ? uuidFromUlid(UUID_NAMESPACE_EVENT, event.parentEventId) : null,
    prev_hash: ctx.prevHash,
  };

  // AAT's input_hash and output_hash are per-record SHA-256 values with no
  // stated preimage, so DEPOSE puts its own payload hash in input_hash and
  // leaves output_hash to the records that actually have a result.
  record.input_hash = event.payloadHash;
  const latency = latencyOf(event);
  if (latency !== null) record.latency_ms = latency;
  const output = outputHashOf(event);
  if (output !== null) record.output_hash = output;
  return record;
}

function latencyOf(event: Event): number | null {
  if (event.type === 'tool_call_effect' || event.type === 'tool_call_executed') {
    const { durationMs } = event.payload as { durationMs: number | null };
    return durationMs;
  }
  if (event.type === 'shell_command_post') {
    return (event.payload as { durationMs: number }).durationMs;
  }
  return null;
}

function outputHashOf(event: Event): string | null {
  if (event.type === 'file_diff') {
    return (event.payload as { postHash: string | null }).postHash;
  }
  if (event.type === 'shell_command_post') {
    return (event.payload as { stdoutHash: string }).stdoutHash;
  }
  return null;
}
