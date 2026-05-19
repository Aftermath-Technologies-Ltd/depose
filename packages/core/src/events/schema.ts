// packages/core/src/events/schema.ts
//
// Authoritative event type union for DEPOSE evidence records.
// Every event in a .depo bundle conforms to this schema.
// See BUILD_PLAN.md §4.1 and §4.2.

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
  | 'gap';

/**
 * Agent source identifiers.
 * claude-code and codex are first-party sources.
 * cursor is a planned third-party source (schema-ready).
 * shell is from shell history or shell shim capture.
 * unknown is a fallback when the source cannot be determined.
 */
export type AgentId = 'claude-code' | 'codex' | 'cursor' | 'shell' | 'unknown';

/**
 * Base shape for every event.
 * chainHash is populated by the chain pass (Phase 2), not by normalizers.
 */
export interface EventBase {
  /** ULID, sortable by time (time-sortable because ULIDs embed a timestamp) */
  id: string;
  /** ISO 8601 UTC wall clock timestamp (e.g. "2025-05-18T15:30:00.000Z") */
  wallTs: string;
  /** Monotonic nanoseconds since session start (for ordering within same wallTs) */
  monoNs: number;
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
  /** Chain hash (populated by chain pass, not by normalizers) */
  chainHash?: string;
}

// ── Payload shapes (see BUILD_PLAN.md §4.2) ──────────────────────────

/**
 * Represents a user prompt sent to the agent.
 */
export interface PromptPayload {
  text: string;
  /** Files attached to this prompt (paths, not content) */
  attachedFiles?: string[];
  /** Tool calls triggered by this prompt (if any) */
  triggeredToolCalls?: string[];
}

/**
 * Represents an assistant (agent) message in the conversation.
 */
export interface AssistantMessagePayload {
  content: string;
  /** Tool calls embedded in this message (tool_call_intent events created from these) */
  toolCalls?: Array<{
    toolName: string;
    toolInput: unknown;
  }>;
}

/**
 * Represents the agent's intent to call a tool (captured from JSONL or hook).
 */
export interface ToolCallIntentPayload {
  toolName: string;
  toolInput: unknown;
  /** Cross-link to a shell_command_pre event if matched */
  linkedShellCommandPreId: string | null;
}

/**
 * Represents a tool call that was actually executed (post-execution capture).
 */
export interface ToolCallExecutedPayload {
  toolName: string;
  toolInput: unknown;
  exitCode: number | null;
  durationMs: number | null;
  /** Cross-link to a shell_command_pre event if matched */
  linkedShellCommandPreId: string | null;
}

/**
 * Represents a tool result (output from a tool call).
 */
export interface ToolResultPayload {
  toolName: string;
  output: string;
  exitCode: number | null;
  error?: string;
  /** Cross-link to a shell_command_pre event if matched */
  linkedShellCommandPreId: string | null;
}

/**
 * Represents a file diff (Edit/Write tool output).
 */
export interface FileDiffPayload {
  path: string;
  /** SHA-256 of file before (null if file didn't exist) */
  preHash: string | null;
  /** SHA-256 of file after (null if file was deleted) */
  postHash: string | null;
  /** Unified diff (truncated to 10KB for bundle size) */
  diff: string;
  /** Actual file content after (if opted in and under size limit) */
  contentPost?: string;
}

/**
 * Represents a shell command before execution (pre-execution capture).
 * Source is either the Claude Code PreToolUse hook or the shell shim.
 */
export interface ShellCommandPrePayload {
  argv: string[];
  cwd: string;
  envHash: string;
  envSubset: Record<string, string>;
  ttyId: string | null;
  user: string;
  hostname: string;
  parentProcessTree: ProcessNode[];
  fileArgs: Array<{
    path: string;
    preSha256: string | null;
    sizeBytes: number | null;
  }>;
  source: 'claude-pretooluse' | 'shell-shim';
  captureSchemaVersion: 1;
}

/**
 * Represents a shell command after execution (post-execution capture from shim).
 */
export interface ShellCommandPostPayload {
  exitCode: number;
  durationMs: number;
  stdoutHash: string;
  stderrHash: string;
  signalReceived: string | null;
}

/**
 * Represents an environment variable change (detected from env_diff or env_change events).
 */
export interface EnvChangePayload {
  key: string;
  oldValue: string | null;
  newValue: string | null;
  source: 'shell' | 'hook' | 'reflog';
}

/**
 * Represents a process spawn (detected from shell history or shim).
 */
export interface ProcessSpawnPayload {
  pid: number;
  ppid: number;
  exe: string;
  argv: string[];
  cwd: string;
}

/**
 * Represents an error event (unhandled exception, tool failure, etc.).
 */
export interface ErrorPayload {
  message: string;
  code: string | null;
  stack?: string;
  context: Record<string, unknown>;
}

/**
 * Represents a gap in coverage — something happened that we did not capture.
 * See BUILD_PLAN.md §4.2 for reason variants.
 */
export interface GapPayload {
  reason:
    | 'tool_result_without_pre_capture'
    | 'shell_history_without_jsonl_correlation'
    | 'reflog_change_without_command'
    | 'pre_capture_without_tool_result';
  affectedEventIds: string[];
  detail: string;
}

/**
 * Represents a process tree node (used in ShellCommandPrePayload.parentProcessTree).
 */
export interface ProcessNode {
  pid: number;
  ppid: number;
  exe: string;
  argv0: string;
}

// ── Discriminated union ──────────────────────────────────────────────

/**
 * Full event type — a discriminated union of EventBase with per-type payloads.
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
  | (EventBase & { type: 'gap'; payload: GapPayload });

/**
 * Type guard: narrow an EventBase to a specific EventType.
 */
export function isEventType(event: EventBase, type: EventType): event is Event {
  return event.type === type;
}
