// packages/bundle/src/export/aat-map.ts
//
// The DEPOSE-to-AAT field mapping: which event type becomes which
// action_type, what goes in action_detail, and how a ULID becomes a UUID.
//
// The mapping is deliberately lossy in one direction only. Every AAT
// field DEPOSE fills is filled from a signed DEPOSE field; nothing is
// inferred. DEPOSE fields with no AAT home are listed in
// docs/export-mapping.md, not folded into action_detail as though the
// format covered them.

import { sha256String, type Event } from '@depose/core';

/** Namespace bytes mixed into a derived event UUID. */
export const UUID_NAMESPACE_EVENT = 'depose:aat:event';

/** Namespace bytes mixed into a derived session UUID. */
export const UUID_NAMESPACE_SESSION = 'depose:aat:session';

/**
 * Derive a UUID from a DEPOSE identifier.
 *
 * AAT names UUID v4, which asserts the value was randomly generated. A
 * DEPOSE record's identity comes from its ULID, and inventing a random
 * UUID would sever the export from the bundle it was made from. So the
 * export emits version 8 (RFC 9562 §5.8, custom format) over
 * SHA-256(namespace + ':' + id), which is a well-formed RFC 9562 UUID,
 * is stable, and can be recomputed by anyone holding the bundle. See
 * docs/export-mapping.md.
 *
 * @param namespace - One of the UUID_NAMESPACE_* constants.
 * @param id - The DEPOSE ULID.
 * @returns A lowercase hyphenated UUIDv8.
 */
export function uuidFromUlid(namespace: string, id: string): string {
  const digest = Buffer.from(sha256String(`${namespace}:${id}`), 'hex');
  const bytes = Uint8Array.from(digest.subarray(0, 16));
  // Version 8 in the high nibble of octet 6; RFC 4122 variant in octet 8.
  bytes[6] = (bytes[6]! & 0x0f) | 0x80;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Buffer.from(bytes).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The AAT action_type for a DEPOSE event.
 *
 * @param event - The event to classify.
 * @returns One of AAT's seven action types.
 */
export function aatAction(event: Event): string {
  switch (event.type) {
    case 'prompt':
    case 'assistant_message':
      return 'decision';
    case 'tool_call_intent':
    case 'tool_call_executed':
    case 'shell_command_pre':
    case 'process_spawn':
      return 'tool_call';
    case 'tool_call_effect':
    case 'tool_result':
    case 'shell_command_post':
    case 'file_diff':
      return 'tool_response';
    case 'error':
      return 'error';
    case 'gap':
    case 'env_change':
    case 'capture_failed':
      return 'lifecycle';
    default:
      return 'lifecycle';
  }
}

/**
 * The AAT outcome for a DEPOSE event.
 *
 * A gap is reported as `failure`: AAT has no value for "we did not
 * observe this", and reporting a hole as a success would be the one
 * mapping choice that misleads a reader of the export alone.
 *
 * @param event - The event to classify.
 * @returns One of AAT's five outcomes.
 */
export function aatOutcome(event: Event): string {
  if (event.type === 'gap' || event.type === 'capture_failed' || event.type === 'error') {
    return 'failure';
  }
  const exitCode = exitCodeOf(event);
  if (exitCode !== null) {
    return exitCode === 0 ? 'success' : 'failure';
  }
  return 'success';
}

/**
 * The AAT action_detail for a DEPOSE event: the fields AAT's own
 * structure has room for, and nothing else.
 *
 * @param event - The event to describe.
 * @returns The action_detail object.
 */
export function actionDetail(event: Event): Record<string, unknown> {
  const base = { depose_event_type: event.type, depose_event_id: event.id };
  switch (event.type) {
    case 'prompt':
      return { ...base, event: 'user_prompt' };
    case 'assistant_message':
      return { ...base, event: 'agent_message' };
    case 'tool_call_intent':
    case 'tool_call_executed': {
      const p = event.payload as { toolName: string };
      return { ...base, tool: p.toolName };
    }
    case 'tool_result': {
      const p = event.payload as { toolName: string; exitCode: number | null };
      return { ...base, tool: p.toolName, exit_code: p.exitCode };
    }
    case 'tool_call_effect': {
      const p = event.payload as {
        toolName: string;
        exitCode: number | null;
        intentEventId: string | null;
        files: Array<{ path: string; change: string }>;
      };
      return {
        ...base,
        tool: p.toolName,
        exit_code: p.exitCode,
        closes_record_id: p.intentEventId ? uuidFromUlid(UUID_NAMESPACE_EVENT, p.intentEventId) : null,
        files_changed: p.files.filter((f) => f.change !== 'unchanged').map((f) => ({ path: f.path, change: f.change })),
      };
    }
    case 'shell_command_pre': {
      const p = event.payload as { argv: string[]; cwd: string; source: string };
      return { ...base, tool: 'shell', argv: p.argv, cwd: p.cwd, capture_source: p.source };
    }
    case 'shell_command_post': {
      const p = event.payload as { exitCode: number };
      return { ...base, tool: 'shell', exit_code: p.exitCode };
    }
    case 'file_diff': {
      const p = event.payload as { path: string };
      return { ...base, tool: 'file', path: p.path };
    }
    case 'process_spawn': {
      const p = event.payload as { argv: string[]; pid: number; source?: string };
      return { ...base, tool: 'process', argv: p.argv, pid: p.pid, capture_source: p.source ?? 'reconstructed' };
    }
    case 'env_change': {
      const p = event.payload as { key: string };
      return { ...base, event: 'env_change', key: p.key };
    }
    case 'error': {
      const p = event.payload as { message: string; code: string | null };
      return { ...base, event: 'error', message: p.message, code: p.code };
    }
    case 'gap': {
      const p = event.payload as { reason: string; affectedEventIds: string[] };
      return {
        ...base,
        event: 'coverage_gap',
        reason: p.reason,
        affected_record_ids: p.affectedEventIds.map((id) => uuidFromUlid(UUID_NAMESPACE_EVENT, id)),
      };
    }
    default:
      return base;
  }
}

function exitCodeOf(event: Event): number | null {
  if (event.type === 'tool_result' || event.type === 'tool_call_executed' || event.type === 'tool_call_effect') {
    return (event.payload as { exitCode: number | null }).exitCode;
  }
  if (event.type === 'shell_command_post') {
    return (event.payload as { exitCode: number }).exitCode;
  }
  return null;
}
