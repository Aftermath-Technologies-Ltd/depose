// packages/core/src/normalize/claude-code.ts
//
// Normalize Claude Code JSONL session transcripts into DEPOSE Event[].
//
// Claude Code (Claude CLI) writes a JSONL file per session (typically
// in ~/.claude/CLAUDE_JSON_LOG or a project-local path). Each line
// is a JSON object representing a conversation turn.
//
// This normalizer reads that JSONL and emits a sequence of Events
// (prompt, assistant_message, tool_call_intent, tool_result, file_diff,
// shell_command_pre/post, error, gap).
//
// See BUILD_PLAN.md §4.1 for the Event schema.
// See BUILD_PLAN.md §5 (Phase 1) for scope: passive reconstruction only.

import type {
  AgentId,
  Event,
  EventBase,
  EventType,
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolResultPayload,
  FileDiffPayload,
  ShellCommandPrePayload,
  ShellCommandPostPayload,
  ErrorPayload,
  GapPayload,
} from '../events/schema.js';
import { sha256 } from '../events/canonical-json.js';
import { generateUlid, ulidFromTime } from '../events/ids.js';

// ── Claude Code JSONL line shape (best-effort reconstruction) ────────
//
// Claude Code writes JSONL lines with varying shapes across versions.
// We handle the common patterns and emit gap events for unknown shapes.
//
// Expected shapes (based on Claude Code's actual output):
//
//   { "type": "user", "content": "...", "timestamp": "..." }
//   { "type": "assistant", "content": "...", "tool_calls": [...], "timestamp": "..." }
//   { "type": "tool", "tool_name": "...", "input": {...}, "output": "...", "timestamp": "..." }
//   { "type": "error", "message": "...", "timestamp": "..." }
//   { "type": "file_edit", "path": "...", "diff": "...", "timestamp": "..." }
//
// Unknown types are emitted as gap events.

/**
 * A single line from a Claude Code JSONL session file.
 * Shape is intentionally loose — we normalize aggressively.
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
  tool_calls?: Array<{
    tool_name?: string;
    toolName?: string;
    input?: unknown;
  }>;
  path?: string;
  diff?: string;
  exit_code?: number;
  exitCode?: number;
  duration_ms?: number;
  durationMs?: number;
  [key: string]: unknown;
}

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
}

// ── Main normalizer ──────────────────────────────────────────────────

/**
 * Parse a Claude Code JSONL session file (as a string) into Events.
 *
 * Each line is parsed as JSON. Lines that fail to parse are skipped
 * and recorded as warnings (not errors — we never silently drop data
 * per BUILD_PLAN.md §8.8).
 *
 * Events are emitted in order:
 *   1. prompt (from "user" lines)
 *   2. assistant_message (from "assistant" lines)
 *   3. tool_call_intent (extracted from assistant tool_calls)
 *   4. tool_result (from "tool" lines)
 *   5. file_diff (from "file_edit" lines)
 *   6. error (from "error" lines)
 *   7. gap (for unrecognized types or missing correlations)
 */
export function normalizeClaudeCodeJsonl(
  jsonl: string,
  options: ClaudeCodeNormalizeOptions = {}
): ClaudeCodeNormalizationResult {
  const {
    sessionId = generateUlid(),
    agentId = 'claude-code',
    sessionStart = new Date().toISOString(),
    monoOffset = 0,
  } = options;

  const lines = jsonl.split('\n').filter((l) => l.trim().length > 0);
  const events: Event[] = [];
  const warnings: string[] = [];
  let mono = monoOffset;
  let lastParentId: string | null = null;
  let sessionStartTime = sessionStart;

  // First pass: find the earliest timestamp to establish session start
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as ClaudeCodeLine;
      if (parsed.timestamp) {
        const ts = new Date(parsed.timestamp);
        if (!isNaN(ts.getTime()) && ts < new Date(sessionStartTime)) {
          sessionStartTime = parsed.timestamp;
        }
      }
    } catch {
      // Skip unparseable lines (will be caught in second pass too)
    }
  }

  // Second pass: normalize each line
  for (const line of lines) {
    let parsed: ClaudeCodeLine;
    try {
      parsed = JSON.parse(line) as ClaudeCodeLine;
    } catch {
      warnings.push(`Failed to parse JSONL line (not valid JSON): ${line.slice(0, 100)}`);
      // Emit a gap event for unparseable lines
      const gap: Event = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: lastParentId,
        monoNs: mono++,
        wallTs: sessionStartTime,
        payload: {
          reason: 'shell_history_without_jsonl_correlation' as const,
          affectedEventIds: [],
          detail: `Unparseable JSONL line: ${line.slice(0, 200)}`,
        },
      });
      events.push(gap);
      continue;
    }

    const lineTs = parsed.timestamp || sessionStartTime;
    const lineMono = mono++;

    try {
      const lineEvents = normalizeClaudeCodeLine(parsed, {
        sessionId,
        agentId,
        wallTs: lineTs,
        monoNs: lineMono,
        lastParentId,
      });
      events.push(...lineEvents);
      // Update parent for next iteration
      if (lineEvents.length > 0) {
        lastParentId = lineEvents[lineEvents.length - 1]?.id ?? lastParentId;
      }
    } catch (err) {
      const errorStr = err instanceof Error ? err.message : String(err);
      warnings.push(`Error normalizing line: ${errorStr}`);
      const gap: Event = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: lastParentId,
        monoNs: lineMono,
        wallTs: lineTs,
        payload: {
          reason: 'shell_history_without_jsonl_correlation' as const,
          affectedEventIds: [],
          detail: `Normalization error: ${errorStr}`,
        },
      });
      events.push(gap);
    }
  }

  return { events, warnings, sessionId };
}

// ── Line-level normalization ─────────────────────────────────────────

interface NormalizeLineOptions {
  sessionId: string;
  agentId: AgentId;
  wallTs: string;
  monoNs: number;
  lastParentId: string | null;
}

function normalizeClaudeCodeLine(
  line: ClaudeCodeLine,
  opts: NormalizeLineOptions
): Event[] {
  const { sessionId, agentId, wallTs, monoNs, lastParentId } = opts;
  const events: Event[] = [];
  const type = (line.type || '').toLowerCase();

  switch (type) {
    case 'user':
    case 'prompt':
    case 'human': {
      const payload: PromptPayload = {
        text: typeof line.content === 'string' ? line.content : JSON.stringify(line.content),
        attachedFiles: line.attachedFiles ? (line.attachedFiles as string[]) : undefined,
      };
      const event = buildEvent({
        sessionId,
        agentId,
        type: 'prompt',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload,
      });
      events.push(event);
      break;
    }

    case 'assistant':
    case 'ai': {
      const toolCalls = (line.tool_calls || [])
        .map((tc) => ({
          toolName: (tc.tool_name || tc.toolName || 'unknown') as string,
          toolInput: tc.input,
        }))
        .filter((tc) => tc.toolName !== 'unknown' || tc.toolInput !== undefined);

      const payload: AssistantMessagePayload = {
        content: typeof line.content === 'string' ? line.content : '',
        toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      };
      const event = buildEvent({
        sessionId,
        agentId,
        type: 'assistant_message',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload,
      });
      events.push(event);

      // Emit tool_call_intent for each tool call
      for (const tc of toolCalls) {
        const tcPayload: ToolCallIntentPayload = {
          toolName: tc.toolName,
          toolInput: tc.toolInput,
          linkedShellCommandPreId: null,
        };
        const tcEvent = buildEvent({
          sessionId,
          agentId,
          type: 'tool_call_intent',
          parentEventId: event.id,
          monoNs: monoNs + 1,
          wallTs,
          payload: tcPayload,
        });
        events.push(tcEvent);
      }
      break;
    }

    case 'tool':
    case 'tool_result': {
      const toolName = (line.tool_name || line.toolName || 'unknown') as string;
      const outputStr =
        typeof line.output === 'string'
          ? line.output
          : line.output !== undefined
          ? JSON.stringify(line.output)
          : '';
      const exitCode =
        line.exit_code !== undefined
          ? line.exit_code
          : line.exitCode !== undefined
          ? line.exitCode
          : null;

      const payload: ToolResultPayload = {
        toolName,
        output: outputStr,
        exitCode,
        error: line.error || undefined,
        linkedShellCommandPreId: null,
      };
      const event = buildEvent({
        sessionId,
        agentId,
        type: 'tool_result',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload,
      });
      events.push(event);
      break;
    }

    case 'file_edit':
    case 'file_diff':
    case 'edit': {
      const payload: FileDiffPayload = {
        path: (line.path || 'unknown') as string,
        preHash: null,
        postHash: null,
        diff: (line.diff || '') as string,
      };
      const event = buildEvent({
        sessionId,
        agentId,
        type: 'file_diff',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload,
      });
      events.push(event);
      break;
    }

    case 'error': {
      const payload: ErrorPayload = {
        message: (line.error || line.content || 'Unknown error') as string,
        code: null,
        context: {},
      };
      const event = buildEvent({
        sessionId,
        agentId,
        type: 'error',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload,
      });
      events.push(event);
      break;
    }

    case 'shell_command':
    case 'command': {
      // Some Claude Code versions emit shell commands as a separate type
      const argv = typeof line.input === 'string' ? [line.input] : (line.input as string[]) || [];
      const _outputStr =
        typeof line.output === 'string'
          ? line.output
          : line.output !== undefined
          ? JSON.stringify(line.output)
          : '';
      const exitCode =
        line.exit_code !== undefined
          ? line.exit_code
          : line.exitCode !== undefined
          ? line.exitCode
          : 0 as number | null;
      const durationMs =
        line.duration_ms !== undefined
          ? line.duration_ms
          : line.durationMs !== undefined
          ? line.durationMs
          : 0 as number | null;

      // shell_command_pre
      const prePayload: ShellCommandPrePayload = {
        argv: Array.isArray(argv) ? argv : [String(argv)],
        cwd: process.cwd(),
        envHash: '',
        envSubset: {},
        ttyId: null,
        user: process.env.USER || '',
        hostname: process.env.HOSTNAME || '',
        parentProcessTree: [],
        fileArgs: [],
        source: 'claude-pretooluse',
        captureSchemaVersion: 1,
      };
      const preEvent = buildEvent({
        sessionId,
        agentId,
        type: 'shell_command_pre',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload: prePayload,
      });
      events.push(preEvent);

      // shell_command_post
      const postPayload: ShellCommandPostPayload = {
        exitCode: exitCode ?? 0,
        durationMs: (durationMs ?? 0) as number,
        stdoutHash: '',
        stderrHash: '',
        signalReceived: null,
      };
      const postEvent = buildEvent({
        sessionId,
        agentId,
        type: 'shell_command_post',
        parentEventId: preEvent.id,
        monoNs: monoNs + 1,
        wallTs,
        payload: postPayload,
      });
      events.push(postEvent);
      break;
    }

    default:
      // Unknown line type — emit gap
      const gapPayload: GapPayload = {
        reason: 'shell_history_without_jsonl_correlation' as const,
        affectedEventIds: [],
        detail: `Unrecognized Claude Code JSONL line type: "${line.type}"`,
      };
      const gap = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: lastParentId,
        monoNs,
        wallTs,
        payload: gapPayload,
      });
      events.push(gap);
      break;
  }

  return events;
}

// ── Event builder ────────────────────────────────────────────────────

interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: EventType;
  parentEventId: string | null;
  monoNs: number;
  wallTs: string;
  payload: unknown;
}

function buildEvent(params: BuildEventParams): Event {
  const { sessionId, agentId, type, parentEventId, monoNs, wallTs, payload } = params;
  const id = ulidFromTime(Date.now());
  const payloadHash = sha256(payload);
  const base: EventBase = {
    id,
    wallTs,
    monoNs,
    sessionId,
    agentId,
    parentEventId,
    type,
    payload,
    payloadHash,
  };
  return { ...base, type, payload } as Event;
}
