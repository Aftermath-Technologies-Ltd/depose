// packages/core/src/events/payloads.ts
//
// Per-type payload shapes for the conversation side of a session: what
// the user asked, what the agent said, what it meant to run, and what came
// back. The capture layer's own shapes (pre-execution, post-execution,
// kernel, and hook failures) live in payloads-capture.ts. The event
// envelope and the discriminated union live in schema.ts.
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
 * Represents an environment variable change (detected from env_diff or env_change events).
 */
export interface EnvChangePayload {
  key: string;
  oldValue: string | null;
  newValue: string | null;
  source: 'shell' | 'hook' | 'reflog';
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
    | 'capture_failed'
    | 'intent_without_effect'
    | 'effect_without_intent'
    | 'unwitnessed_file_change'
    | 'kernel_execve_without_hook';
  affectedEventIds: string[];
  detail: string;
}
