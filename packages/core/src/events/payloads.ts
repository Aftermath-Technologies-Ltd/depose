// packages/core/src/events/payloads.ts
//
// Per-type payload shapes for DEPOSE events. The event envelope and the
// discriminated union live in schema.ts; this file holds only the
// payload contracts so each can be read on its own.
// See docs/bundle-format.md#event-schema.

// ── Payload shapes ────────────────────────────────────────────────────

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
  /** Tool use ID for correlation with tool_result events (Claude Code real-session format) */
  toolUseId?: string;
}

/**
 * Represents a tool call that was actually executed (post-execution capture).
 */
export interface ToolCallExecutedPayload {
  toolName: string;
  toolInput: unknown;
  exitCode: number | null;
  durationMs: number | null;
}

/**
 * Represents a tool result (output from a tool call).
 */
export interface ToolResultPayload {
  toolName: string;
  output: string;
  exitCode: number | null;
  error?: string;
  /** Tool use ID for correlation back to the parent tool_call_intent */
  toolUseId?: string;
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
 *
 * This is the v2 shape, which is what enters a bundle. v1 records on
 * disk carry neither `capturedAt` nor `sessionId`; normalizeCaptureRecords
 * upgrades them on read (deriving the time from the ULID filename) so
 * everything downstream sees one shape.
 *
 * v1 recorded no capture time at all, which forced the normalizer to
 * stamp events with the bundle production time. That put every capture
 * event minutes to months away from the command it described, so the
 * plus or minus 5s correlation window in mergeEvents could never match
 * and active capture linked nothing in real post-incident use.
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
  source: 'claude-pretooluse' | 'shell-shim' | 'reconstructed';
  captureSchemaVersion: 1 | 2;
  /**
   * ISO 8601 time the capture was taken, not the time the bundle was
   * produced. Added in v2.
   */
  capturedAt: string;
  /**
   * Provenance of `capturedAt`. A derived or reconstructed time is weaker
   * evidence than a recorded one, and a bundle must never present them as
   * equal.
   *
   *   recorded            written by the hook or shim at capture time
   *   derived-from-mtime  v1 record, time taken from the file's mtime
   *   reconstructed       no capture happened; time comes from the
   *                       session log line this payload was rebuilt from
   */
  capturedAtSource: 'recorded' | 'derived-from-mtime' | 'reconstructed';
  /**
   * Agent session this capture belongs to, used to scope captures to the
   * session being reconstructed. Null for shell-shim records, which have
   * no agent session, and for upgraded v1 records, which predate the field.
   */
  sessionId: string | null;
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
 * Represents a gap in coverage, something happened that we did not capture.
 * See docs/bundle-format.md#gap-events for the reason variants.
 */
export interface GapPayload {
  reason:
    | 'tool_result_without_pre_capture'
    | 'shell_history_without_jsonl_correlation'
    | 'reflog_change_without_command'
    | 'pre_capture_without_tool_result'
    | 'jsonl_line_unparseable'
    | 'unknown_jsonl_line_type'
    | 'capture_failed';
  affectedEventIds: string[];
  detail: string;
}

/**
 * The capture hook hit an exception and could not write a capture record.
 *
 * Written by the hook itself before it exits 0, so a lost capture leaves a
 * trace instead of a clean-looking timeline. The merger turns each one into
 * a `gap` event with reason `capture_failed`.
 */
export interface CaptureFailedPayload {
  /** Discriminator so the capture-store reader can tell it from a command record. */
  kind: 'capture_failed';
  /** Hook phase that threw (read-input, parse-input, env, file-hash, process-tree, write-record). */
  phase: string;
  /** Error constructor name, e.g. "TypeError" or "SyntaxError". */
  errorClass: string;
  /** First line of the error message, control characters stripped, capped in length. */
  message: string;
  /** process.hrtime.bigint() at failure, as a decimal string. */
  monoNs: string;
  /** ISO 8601 time the failure was recorded. */
  capturedAt: string;
  /** Agent session the hook was serving, when the input got far enough to know it. */
  sessionId: string | null;
  /** Tool the hook was capturing, when known. */
  toolName: string | null;
  source: 'claude-pretooluse';
  captureSchemaVersion: 3;
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
