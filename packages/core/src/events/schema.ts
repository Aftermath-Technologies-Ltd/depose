// packages/core/src/events/schema.ts
//
// Authoritative event type union for DEPOSE evidence records.
// Every event in a .depo bundle conforms to this schema.
// Payload shapes live in payloads.ts. See docs/bundle-format.md#event-schema.

/**
 * All event types that can appear in a DEPOSE evidence timeline.
 * Each type has a corresponding payload shape (see §4.2).
 */
export type EventType =
  | 'prompt'
  | 'assistant_message'
  | 'tool_call_intent'
  | 'tool_call_executed'
  | 'tool_result'
  | 'file_diff'
  | 'shell_command_pre'
  | 'shell_command_post'
  | 'env_change'
  | 'process_spawn'
  | 'error'
  | 'gap'
  | 'capture_failed';

import type {
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolCallExecutedPayload,
  ToolResultPayload,
  FileDiffPayload,
  ShellCommandPrePayload,
  ShellCommandPostPayload,
  EnvChangePayload,
  ProcessSpawnPayload,
  ErrorPayload,
  GapPayload,
  CaptureFailedPayload,
} from './payloads.js';

export type {
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolCallExecutedPayload,
  ToolResultPayload,
  FileDiffPayload,
  ShellCommandPrePayload,
  ShellCommandPostPayload,
  EnvChangePayload,
  ProcessSpawnPayload,
  ErrorPayload,
  GapPayload,
  CaptureFailedPayload,
  ProcessNode,
} from './payloads.js';

/**
 * Agent source identifiers.
 * claude-code and codex are first-party sources.
 * cursor is a planned third-party source (schema-ready).
 * shell is from shell history or shell shim capture.
 * unknown is a fallback when the source cannot be determined.
 */
export type AgentId = 'claude-code' | 'codex' | 'cursor' | 'shell' | 'unknown';

/**
 * Source of a shell command pre-capture event.
 * claude-pretooluse: captured from Claude Code's PreToolUse hook.
 * shell-shim: captured from the DEPOSE shell shim.
 * reconstructed: inferred from JSONL logs during passive reconstruction.
 */
export type ShellCommandSource = 'claude-pretooluse' | 'shell-shim' | 'reconstructed';

/**
 * Base shape for every event.
 * chainHash is populated by the chain pass (Phase 2), not by normalizers.
 */
/**
 * Correlation metadata for linking events across sources.
 * Lives outside payload so it does not affect payloadHash.
 */
export interface EventCorrelation {
  /** Cross-link to a shell_command_pre event matched during merge */
  linkedShellCommandPreId?: string;
}

export interface EventBase {
  /** ULID, sortable by time (time-sortable because ULIDs embed a timestamp) */
  id: string;
  /** ISO 8601 UTC wall clock timestamp (e.g. "2025-05-18T15:30:00.000Z") */
  wallTs: string;
  /**
   * Monotonic nanoseconds since session start (for ordering within the
   * same wallTs). A bigint in memory, a decimal string on the wire; see
   * event-io.ts.
   */
  monoNs: bigint;
  /** Session identifier (ULID or session-specific ID) */
  sessionId: string;
  /** Which agent/tool produced this event */
  agentId: AgentId;
  /** ID of the parent event (null for root events) */
  parentEventId: string | null;
  /** Discriminated type tag */
  type: EventType;
  /** Type-narrowed payload (see §4.2 for per-type shapes) */
  payload: unknown;
  /** SHA-256 hex digest of canonical (JCS) JSON serialization of payload */
  payloadHash: string;
  /** Correlation metadata (outside payload, not hashed into payloadHash) */
  correlation?: EventCorrelation;
  /** Chain hash (populated by chain pass, not by normalizers) */
  chainHash?: string;
}

// ── Discriminated union ──────────────────────────────────────────────

/**
 * Full event type, a discriminated union of EventBase with per-type payloads.
 * TypeScript narrows `payload` based on `type`.
 */
export type Event =
  | (EventBase & { type: 'prompt'; payload: PromptPayload })
  | (EventBase & { type: 'assistant_message'; payload: AssistantMessagePayload })
  | (EventBase & { type: 'tool_call_intent'; payload: ToolCallIntentPayload })
  | (EventBase & { type: 'tool_call_executed'; payload: ToolCallExecutedPayload })
  | (EventBase & { type: 'tool_result'; payload: ToolResultPayload })
  | (EventBase & { type: 'file_diff'; payload: FileDiffPayload })
  | (EventBase & { type: 'shell_command_pre'; payload: ShellCommandPrePayload })
  | (EventBase & { type: 'shell_command_post'; payload: ShellCommandPostPayload })
  | (EventBase & { type: 'env_change'; payload: EnvChangePayload })
  | (EventBase & { type: 'process_spawn'; payload: ProcessSpawnPayload })
  | (EventBase & { type: 'error'; payload: ErrorPayload })
  | (EventBase & { type: 'gap'; payload: GapPayload })
  | (EventBase & { type: 'capture_failed'; payload: CaptureFailedPayload });

/**
 * Type guard: narrow an EventBase to a specific EventType.
 */
export function isEventType(event: EventBase, type: EventType): event is Event {
  return event.type === type;
}
