// packages/core/src/normalize/claude-code-flat.ts
//
// Normalizer for the flat JSONL shape used by synthetic fixtures and older
// Claude Code versions: { type, content, tool_calls, ... }.
// The nested real-session shape is handled in claude-code-real.ts.

import type {
  Event,
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
import type { ClaudeCodeLine, NormalizeLineOptions } from './claude-code-types.js';
import { buildEvent } from './claude-code-build-event.js';
import { normalizeRealSessionLine } from './claude-code-real.js';

// ── Line-level normalization ─────────────────────────────────────────


export function normalizeClaudeCodeLine(
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

      // shell_command_pre; source is 'reconstructed' because this event
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
        captureSchemaVersion: 2,
        // No capture happened, so this is the session log's own timestamp
        // for the line, labelled as reconstructed rather than recorded.
        capturedAt: wallTs,
        capturedAtSource: 'reconstructed',
        sessionId,
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
      // Unknown line type, emit gap
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

