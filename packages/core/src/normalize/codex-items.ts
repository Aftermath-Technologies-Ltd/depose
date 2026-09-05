// packages/core/src/normalize/codex-items.ts
//
// One Codex response item to zero or more DEPOSE events.
//
// The mapping the rest of the pipeline depends on:
//
//   message role=user        prompt
//   message role=assistant   assistant_message
//   function_call            tool_call_intent, plus shell_command_pre for
//                            the shell tool, so destructive-rule matching
//                            and capture correlation work the same way
//                            they do on the Claude path
//   function_call_output     tool_result
//
// `call_id` is the correlation key on both halves, which is what the
// merge already uses under the name `toolUseId`.

import type { AgentId, Event } from '../events/schema.js';
import type {
  PromptPayload,
  AssistantMessagePayload,
  ToolCallIntentPayload,
  ToolResultPayload,
  ShellCommandPrePayload,
} from '../events/schema.js';
import { buildEvent } from './claude-code-build-event.js';
import type { CodexResponseItem } from './codex-types.js';

/** Where one item sits in the file and the session. */
export interface CodexItemContext {
  sessionId: string;
  agentId: AgentId;
  wallTs: string;
  monoNs: number;
  lastParentId: string | null;
  lineNumber: number;
}

/** The events one item produced, and anything worth disclosing about it. */
export interface CodexItemResult {
  events: Event[];
  warnings: string[];
}

/** Codex tool names that run a shell command. */
const SHELL_TOOLS = new Set(['shell', 'exec_command', 'local_shell', 'container.exec']);

/**
 * Turn one response item into events.
 *
 * @param item - The item, already stripped of any envelope.
 * @param ctx - Session, agent, time, and ordering.
 * @returns The events, in the order they belong in the timeline.
 */
export function itemToEvents(item: CodexResponseItem, ctx: CodexItemContext): CodexItemResult {
  switch (item.type) {
    case 'message':
      return messageEvents(item, ctx);
    case 'function_call':
    case 'local_shell_call':
      return callEvents(item, ctx);
    case 'function_call_output':
    case 'local_shell_call_output':
      return outputEvents(item, ctx);
    case 'reasoning':
      // Codex records the model's own reasoning trace. It is not an
      // action and it is not a message the user saw, so it is left out
      // rather than presented as either.
      return { events: [], warnings: [] };
    default:
      return {
        events: [],
        warnings: [`Codex rollout line ${ctx.lineNumber}: unrecognized response item type "${item.type}"`],
      };
  }
}

function messageEvents(item: CodexResponseItem, ctx: CodexItemContext): CodexItemResult {
  const text = readContentText(item.content);
  if (item.role === 'user') {
    const payload: PromptPayload = { text };
    return { events: [event(ctx, 'prompt', null, payload)], warnings: [] };
  }
  if (item.role === 'assistant') {
    const payload: AssistantMessagePayload = { content: text };
    return { events: [event(ctx, 'assistant_message', ctx.lastParentId, payload)], warnings: [] };
  }
  // A system or developer message is instruction, not conversation, and
  // Codex repeats it on every turn; recording it as a prompt would put
  // the same text in the timeline dozens of times.
  return { events: [], warnings: [] };
}

function callEvents(item: CodexResponseItem, ctx: CodexItemContext): CodexItemResult {
  const toolName = typeof item.name === 'string' ? item.name : 'unknown';
  const parsed = parseArguments(item.arguments);
  const intent: ToolCallIntentPayload = {
    toolName,
    toolInput: parsed.value,
    ...(typeof item.call_id === 'string' ? { toolUseId: item.call_id } : {}),
  };
  const events = [event(ctx, 'tool_call_intent', ctx.lastParentId, intent)];
  const warnings = parsed.warning ? [`Codex rollout line ${ctx.lineNumber}: ${parsed.warning}`] : [];

  const argv = shellArgv(toolName, parsed.value);
  if (argv) {
    const pre: ShellCommandPrePayload = {
      argv,
      cwd: readString(parsed.value, 'workdir') ?? readString(parsed.value, 'cwd') ?? '',
      envHash: '',
      envSubset: {},
      ttyId: null,
      user: '',
      hostname: '',
      parentProcessTree: [],
      fileArgs: [],
      source: 'reconstructed',
      captureSchemaVersion: 3,
      // Rebuilt from a rollout line, so the time is the line's, not an
      // observation made at capture time.
      capturedAt: ctx.wallTs,
      capturedAtSource: 'reconstructed',
      sessionId: null,
    };
    events.push(
      buildEvent({
        sessionId: ctx.sessionId,
        agentId: ctx.agentId,
        type: 'shell_command_pre',
        parentEventId: events[0]!.id,
        monoNs: ctx.monoNs + 1,
        wallTs: ctx.wallTs,
        payload: pre,
      })
    );
  }
  return { events, warnings };
}

function outputEvents(item: CodexResponseItem, ctx: CodexItemContext): CodexItemResult {
  const output = readOutputText(item.output);
  const payload: ToolResultPayload = {
    toolName: typeof item.name === 'string' ? item.name : 'unknown',
    output: output.text,
    exitCode: output.exitCode,
    ...(output.error !== null ? { error: output.error } : {}),
    ...(typeof item.call_id === 'string' ? { toolUseId: item.call_id } : {}),
  };
  return { events: [event(ctx, 'tool_result', ctx.lastParentId, payload)], warnings: [] };
}

/**
 * The argv a shell tool call runs, or null when the tool is not a shell.
 *
 * Codex passes the command as an array under `command`; older builds and
 * some providers pass a single string. A string is wrapped the same way
 * the Claude hook wraps one, so the shell-aware rule matcher sees the
 * same shape from both agents.
 */
function shellArgv(toolName: string, input: unknown): string[] | null {
  if (!SHELL_TOOLS.has(toolName)) return null;
  if (typeof input !== 'object' || input === null) return null;
  const command = (input as Record<string, unknown>)['command'];
  if (Array.isArray(command)) {
    const argv = command.filter((part): part is string => typeof part === 'string');
    return argv.length > 0 ? argv : null;
  }
  if (typeof command === 'string' && command.length > 0) {
    return ['bash', '-c', command];
  }
  return null;
}

/** Codex serializes tool arguments as a JSON string, not an object. */
function parseArguments(raw: unknown): { value: unknown; warning: string | null } {
  if (raw === undefined || raw === null) return { value: {}, warning: null };
  if (typeof raw !== 'string') return { value: raw, warning: null };
  try {
    return { value: JSON.parse(raw), warning: null };
  } catch {
    // The raw string is kept: an unparseable argument list is still what
    // the agent asked for, and dropping it would lose the command.
    return { value: { raw }, warning: 'tool arguments are not JSON; kept verbatim under "raw"' };
  }
}

/** Content is an array of typed parts in every format seen so far. */
function readContentText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === 'string') {
      parts.push(part);
      continue;
    }
    if (typeof part === 'object' && part !== null) {
      const text = (part as Record<string, unknown>)['text'];
      if (typeof text === 'string') parts.push(text);
    }
  }
  return parts.join('');
}

/** Tool output arrives as a string, or as a JSON string with metadata. */
function readOutputText(output: unknown): { text: string; exitCode: number | null; error: string | null } {
  if (typeof output === 'string') {
    try {
      const parsed = JSON.parse(output) as Record<string, unknown>;
      if (typeof parsed === 'object' && parsed !== null && 'output' in parsed) {
        return {
          text: typeof parsed['output'] === 'string' ? parsed['output'] : output,
          exitCode: readExitCode(parsed['metadata']),
          error: typeof parsed['error'] === 'string' ? parsed['error'] : null,
        };
      }
    } catch {
      // A plain string output is the common case.
    }
    return { text: output, exitCode: null, error: null };
  }
  if (typeof output === 'object' && output !== null) {
    const record = output as Record<string, unknown>;
    return {
      text: typeof record['output'] === 'string' ? record['output'] : readContentText(record['content']),
      exitCode: readExitCode(record['metadata']),
      error: typeof record['error'] === 'string' ? record['error'] : null,
    };
  }
  return { text: '', exitCode: null, error: null };
}

function readExitCode(metadata: unknown): number | null {
  if (typeof metadata !== 'object' || metadata === null) return null;
  const code = (metadata as Record<string, unknown>)['exit_code'];
  return typeof code === 'number' ? code : null;
}

function readString(value: unknown, key: string): string | null {
  if (typeof value !== 'object' || value === null) return null;
  const found = (value as Record<string, unknown>)[key];
  return typeof found === 'string' ? found : null;
}

function event(ctx: CodexItemContext, type: Event['type'], parentEventId: string | null, payload: unknown): Event {
  return buildEvent({
    sessionId: ctx.sessionId,
    agentId: ctx.agentId,
    type,
    parentEventId,
    monoNs: ctx.monoNs,
    wallTs: ctx.wallTs,
    payload,
  });
}
