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
// Two formats are supported:
//   1. Flat format (legacy/synthetic): { type, content, tool_calls }
//   2. Real session format: { type, message: { role, content: [...] }, timestamp }
//
// See BUILD_PLAN.md §4.1 for the Event schema.
// See BUILD_PLAN.md §5 (Phase 1) for scope: passive reconstruction only.

import type {
  AgentId,
  Event,
  EventBase,
  EventType,
  ShellCommandSource,
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
 *   3. tool_call_intent (extracted from assistant tool_calls or tool_use blocks)
 *   4. tool_result (from "tool" lines or tool_result content blocks)
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
          reason: 'jsonl_line_unparseable' as const,
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
          reason: 'jsonl_line_unparseable' as const,
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

  // ── Real session format: line.message.content is an array ──
  // When line.message exists, we descend into the content blocks.
  if (line.message && Array.isArray(line.message.content)) {
    return normalizeRealSessionLine(line, opts);
  }

  // ── Legacy flat format ──
  switch (type) {
    case 'user':
    case 'prompt':
    case 'human': {
      // Check if this is a real session format user message with tool_result blocks
      if (line.message && Array.isArray(line.message.content)) {
        return normalizeRealSessionLine(line, opts);
      }
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
      for (let i = 0; i < toolCalls.length; i++) {
        const tc = toolCalls[i]!;
        const tcPayload: ToolCallIntentPayload = {
          toolName: tc.toolName,
          toolInput: tc.toolInput,
        };
        const tcEvent = buildEvent({
          sessionId,
          agentId,
          type: 'tool_call_intent',
          parentEventId: event.id,
          monoNs: monoNs + 1 + i,
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

      // shell_command_pre — source is 'reconstructed' because this event
      // was parsed from JSONL history, not captured from a live session.
      // cwd, user, and hostname are empty strings: we don't have real
      // session host info for reconstructed events and should not pretend
      // we do by using the current process's values.
      const prePayload: ShellCommandPrePayload = {
        argv: Array.isArray(argv) ? argv : [String(argv)],
        cwd: '',
        envHash: '',
        envSubset: {},
        ttyId: null,
        user: '',
        hostname: '',
        parentProcessTree: [],
        fileArgs: [],
        source: 'reconstructed' as ShellCommandSource,
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
        reason: 'unknown_jsonl_line_type' as const,
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

// ── Real session format normalizer ──────────────────────────────────

/**
 * Normalize a line that uses the real Claude Code session format:
 * { type, message: { role, content: ContentBlock[] }, timestamp }
 *
 * Content blocks can be:
 *   - { type: "text", text } → assistant_message
 *   - { type: "thinking", thinking } → assistant_message with metadata variant
 *   - { type: "tool_use", id, name, input } → tool_call_intent
 *   - { type: "tool_result", tool_use_id, content } → tool_result (via user role)
 */
function normalizeRealSessionLine(
  line: ClaudeCodeLine,
  opts: NormalizeLineOptions
): Event[] {
  const { sessionId, agentId, monoNs, lastParentId } = opts;
  const events: Event[] = [];
  const wallTs = line.timestamp || opts.wallTs;
  const message = line.message!;
  const contentBlocks = message.content || [];
  const role = (message.role || '').toLowerCase();
  const lineType = (line.type || '').toLowerCase();

  // For user messages, check for tool_result blocks
  if (role === 'user' || lineType === 'user') {
    let hasToolResult = false;

    for (let i = 0; i < contentBlocks.length; i++) {
      const block = contentBlocks[i]!;
      if (typeof block !== 'object' || block === null) continue;

      if (block.type === 'tool_result') {
        hasToolResult = true;
        const blockAny = block as Record<string, unknown>;
        const toolUseId = (blockAny.tool_use_id || blockAny.tool_useId || '') as string;
        const toolContent = blockAny.content;
        const toolName = (blockAny.name || blockAny.tool_name || 'unknown') as string;
        const isError = blockAny.is_error === true;
        const outputStr = typeof toolContent === 'string'
          ? toolContent
          : toolContent !== undefined
          ? JSON.stringify(toolContent)
          : '';

        const payload: ToolResultPayload = {
          toolName,
          output: outputStr,
          exitCode: isError ? 1 : null,
          error: isError ? 'Tool returned an error' : undefined,
          // Tool use ID for correlation back to tool_call_intent
          ...(toolUseId ? { toolUseId } : {}),
        };

        const event = buildEvent({
          sessionId,
          agentId,
          type: 'tool_result',
          parentEventId: lastParentId,
          monoNs: monoNs + i,
          wallTs,
          payload,
        });
        events.push(event);
      } else if (block.type === 'text') {
        const blockAny = block as Record<string, unknown>;
        const text = (blockAny.text || '') as string;
        if (text.trim()) {
          const payload: PromptPayload = {
            text,
          };
          const event = buildEvent({
            sessionId,
            agentId,
            type: 'prompt',
            parentEventId: lastParentId,
            monoNs: monoNs + i,
            wallTs,
            payload,
          });
          events.push(event);
        }
      }
    }

    // If no tool_result blocks and no text blocks produced events,
    // emit a generic prompt from the entire content
    if (!hasToolResult && events.length === 0) {
      const payload: PromptPayload = {
        text: JSON.stringify(contentBlocks),
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
    }

    return events;
  }

  // For assistant messages, process content blocks
  if (role === 'assistant' || lineType === 'assistant') {
    // Collect text and thinking content for the assistant_message event
    let textContent = '';
    let hasThinking = false;
    let thinkingContent = '';
    let parentEventId: string | null = lastParentId;

    for (let i = 0; i < contentBlocks.length; i++) {
      const block = contentBlocks[i]!;
      if (typeof block !== 'object' || block === null) continue;

      if (block.type === 'text') {
        const blockAny = block as Record<string, unknown>;
        textContent += (blockAny.text || '') as string;
      } else if (block.type === 'thinking') {
        const blockAny = block as Record<string, unknown>;
        hasThinking = true;
        thinkingContent += (blockAny.thinking || '') as string;
      }
    }

    // Emit assistant_message with the text content
    // If there's thinking content, we emit a separate assistant_message for it
    // marked with metadata indicating it's a thinking block.
    if (textContent || hasThinking) {
      // Emit thinking as a separate assistant_message with metadata
      if (hasThinking) {
        const thinkingPayload: AssistantMessagePayload & { metadata?: { variant: string } } = {
          content: thinkingContent,
        };
        (thinkingPayload as AssistantMessagePayload & { metadata?: { variant: string } }).metadata = { variant: 'thinking' };
        const thinkingEvent = buildEvent({
          sessionId,
          agentId,
          type: 'assistant_message',
          parentEventId: lastParentId,
          monoNs,
          wallTs,
          payload: thinkingPayload,
        });
        events.push(thinkingEvent);
        parentEventId = thinkingEvent.id;
      }

      // Emit the text content as assistant_message
      if (textContent) {
        const payload: AssistantMessagePayload = {
          content: textContent,
        };
        const event = buildEvent({
          sessionId,
          agentId,
          type: 'assistant_message',
          parentEventId,
          monoNs: hasThinking ? monoNs + 1 : monoNs,
          wallTs,
          payload,
        });
        events.push(event);
        parentEventId = event.id;
      }
    }

    // Now emit tool_call_intent events for each tool_use block
    let toolUseIndex = 0;
    const assistantMonoBase = monoNs + (hasThinking ? 1 : 0) + (textContent ? 1 : 0);
    for (let i = 0; i < contentBlocks.length; i++) {
      const block = contentBlocks[i]!;
      if (typeof block !== 'object' || block === null) continue;

      if (block.type === 'tool_use') {
        const blockAny = block as Record<string, unknown>;
        const toolUseId = (blockAny.id || '') as string;
        const toolName = (blockAny.name || 'unknown') as string;
        const toolInput = blockAny.input;

        const tcPayload: ToolCallIntentPayload = {
          toolName,
          toolInput,
          ...(toolUseId ? { toolUseId } : {}),
        };

        const tcEvent = buildEvent({
          sessionId,
          agentId,
          type: 'tool_call_intent',
          parentEventId,
          monoNs: assistantMonoBase + toolUseIndex,
          wallTs,
          payload: tcPayload,
        });
        events.push(tcEvent);
        toolUseIndex++;
      }
    }

    // If nothing was emitted at all, emit a fallback
    if (events.length === 0) {
      const payload: AssistantMessagePayload = {
        content: JSON.stringify(contentBlocks),
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
    }

    return events;
  }

  // Fallback: unknown role, emit as gap
  const gapPayload: GapPayload = {
    reason: 'unknown_jsonl_line_type' as const,
    affectedEventIds: [],
    detail: `Unrecognized message role: "${role}" in line type: "${line.type}"`,
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
  // F-03: Use wallTs as the timestamp source instead of Date.now()
  const id = ulidFromTime(new Date(wallTs).getTime());
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