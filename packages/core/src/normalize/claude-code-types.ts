// packages/core/src/normalize/claude-code-types.ts
//
// Line shapes and option/result types for Claude Code JSONL normalization.
// Split out of claude-code.ts, which had grown to 818 lines holding the
// schema, two format-specific normalizers, and the event builder.

import type { AgentId, Event } from '../events/schema.js';

// ── Claude Code JSONL line shape (best-effort reconstruction) ────────
//
// Claude Code writes JSONL lines with varying shapes across versions.
// We handle the common patterns and emit gap events for unknown shapes.
//
// Expected flat shapes (synthetic / older versions):
//
//   { "type": "user", "content": "...", "timestamp": "..." }
//   { "type": "assistant", "content": "...", "tool_calls": [...], "timestamp": "..." }
//   { "type": "tool", "tool_name": "...", "input": {...}, "output": "...", "timestamp": "..." }
//   { "type": "error", "message": "...", "timestamp": "..." }
//   { "type": "file_edit", "path": "...", "diff": "...", "timestamp": "..." }
//
// Real session shapes (Claude Code v1+):
//
//   { "type": "user", "message": { "role": "user", "content": [{ "type": "text", "text": "..." }] }, "timestamp": "..." }
//   { "type": "assistant", "message": { "role": "assistant", "content": [{ "type": "text" }, { "type": "thinking" }, { "type": "tool_use", "id": "...", "name": "...", "input": {...} }] }, "timestamp": "..." }
//   { "type": "tool_result", "message": { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "...", "content": "..." }] }, "timestamp": "..." }
//
// Unknown types are emitted as gap events.

/**
 * A single line from a Claude Code JSONL session file.
 * Shape is intentionally loose; we normalize aggressively.
 */
export interface ClaudeCodeLine {
  type: string;
  content?: string;
  tool_name?: string;
  toolName?: string;
  input?: unknown;
  output?: string | unknown;
  error?: string;
  timestamp?: string;
  session_id?: string;
  /** Real Claude Code sessions use camelCase and carry the working dir. */
  sessionId?: string;
  cwd?: string;
  tool_calls?: Array<{
    tool_name?: string;
    toolName?: string;
    input?: unknown;
  }>;
  // Real session format: nested message with typed content blocks
  message?: {
    role?: string;
    content?: ContentBlock[];
  };
  path?: string;
  diff?: string;
  exit_code?: number;
  exitCode?: number;
  duration_ms?: number;
  durationMs?: number;
  [key: string]: unknown;
}

/**
 * A typed content block from a real Claude Code session.
 */
export type ContentBlock =
  | { type: 'text'; text: string }
  | { type: 'thinking'; thinking: string }
  | { type: 'tool_use'; id: string; name: string; input: unknown }
  | { type: 'tool_result'; tool_use_id: string; content: string | ContentBlock[] }
  | { type: string; [key: string]: unknown };

/**
 * Options for Claude Code JSONL normalization.
 */
export interface ClaudeCodeNormalizeOptions {
  /** Session ID (ULID). If not provided, a new one is generated. */
  sessionId?: string;
  /** Agent ID (default: 'claude-code'). */
  agentId?: AgentId;
  /**
   * Fixed timestamp (ISO 8601) to use as session start.
   * If not provided, uses the first line's timestamp or Date.now().
   */
  sessionStart?: string;
  /**
   * Monotonic counter for ordering events within the same timestamp.
   * Starts at 0 and increments per event.
   */
  monoOffset?: number;
}

/**
 * Result of normalizing a Claude Code JSONL session.
 */
export interface ClaudeCodeNormalizationResult {
  /** The normalized events in chronological order. */
  events: Event[];
  /** Warnings about lines that could not be parsed. */
  warnings: string[];
  /** The session ID used (generated or provided). */
  sessionId: string;
  /**
   * The agent's own session id as written in the JSONL, or null if the
   * file carries none. This is what capture records are matched against
   * to scope a bundle to one session; `sessionId` above is DEPOSE's
   * internal id and means nothing to the agent.
   */
  agentSessionId: string | null;
  /** Distinct working directories the session touched, in first-seen order. */
  cwds: string[];
}

/**
 * Per-line context shared by both format normalizers: the session and
 * agent the line belongs to, its timestamp, and the ordering counter.
 */
export interface NormalizeLineOptions {
  sessionId: string;
  agentId: AgentId;
  wallTs: string;
  monoNs: number;
  lastParentId: string | null;
}
