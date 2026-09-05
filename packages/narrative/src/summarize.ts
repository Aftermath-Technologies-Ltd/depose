// packages/narrative/src/summarize.ts
//
// One line of prose per event, derived only from what the event records.
// No inference, no hedging language, no LLM: the narrative has to say the
// same thing every time it is rendered from the same timeline, and every
// claim in it has to be traceable to a field in events.jsonl.

import type {
  Event,
  ShellCommandPrePayload,
  ToolCallIntentPayload,
  ToolCallExecutedPayload,
  ToolCallEffectPayload,
  ToolResultPayload,
  FileDiffPayload,
  ProcessSpawnPayload,
  GapPayload,
  PromptPayload,
  AssistantMessagePayload,
  ErrorPayload,
  CaptureFailedPayload,
} from '@depose/core';

// ── Event summarization (deterministic, no inference) ──────────────

/**
 * Summarize an event for narrative display.
 * Deterministic: same event always produces the same summary.
 * Conservative: only states what the event directly records, no inference.
 */
export function summarizeEvent(event: Event): { summary: string; detail: string } {
  switch (event.type) {
    case 'prompt': {
      const p = event.payload as PromptPayload;
      const text = p.text.length > 120 ? p.text.slice(0, 117) + '...' : p.text;
      return { summary: `User prompt: "${text}"`, detail: '' };
    }
    case 'assistant_message': {
      const p = event.payload as AssistantMessagePayload;
      const content = p.content.length > 120 ? p.content.slice(0, 117) + '...' : p.content;
      const toolCount = p.toolCalls?.length ?? 0;
      const toolNote = toolCount > 0 ? ` (${toolCount} tool call(s) attached)` : '';
      return { summary: `Assistant response: "${content}"${toolNote}`, detail: '' };
    }
    case 'tool_call_intent': {
      const p = event.payload as ToolCallIntentPayload;
      const linked = event.correlation?.linkedShellCommandPreId
        ? ` → linked to shell_command_pre [#evt-${event.correlation.linkedShellCommandPreId}]`
        : '';
      return {
        summary: `Tool call intent: ${p.toolName}`,
        detail: `Input: ${JSON.stringify(p.toolInput).slice(0, 200)}${linked}`,
      };
    }
    case 'tool_call_executed': {
      const p = event.payload as ToolCallExecutedPayload;
      const exitInfo = p.exitCode !== null ? ` (exit ${p.exitCode})` : '';
      const durationInfo = p.durationMs !== null ? ` in ${p.durationMs}ms` : '';
      return {
        summary: `Tool executed: ${p.toolName}${exitInfo}${durationInfo}`,
        detail: event.correlation?.linkedShellCommandPreId
          ? `Pre-capture linked: [#evt-${event.correlation.linkedShellCommandPreId}]`
          : '',
      };
    }
    case 'tool_result': {
      const p = event.payload as ToolResultPayload;
      const output = p.output.length > 100 ? p.output.slice(0, 97) + '...' : p.output;
      const exitInfo = p.exitCode !== null ? ` (exit ${p.exitCode})` : '';
      const linked = event.correlation?.linkedShellCommandPreId
        ? ` | Pre-capture: [#evt-${event.correlation.linkedShellCommandPreId}]`
        : '';
      return {
        summary: `Tool result${exitInfo}: ${p.toolName}`,
        detail: `Output: "${output}"${linked}`,
      };
    }
    case 'file_diff': {
      const p = event.payload as FileDiffPayload;
      const pre = p.preHash ? `exists (sha256:${p.preHash.slice(0, 12)}...)` : 'did not exist';
      const post = p.postHash ? `sha256:${p.postHash.slice(0, 12)}...` : 'deleted';
      return {
        summary: `File modified: ${p.path}`,
        detail: `Before: ${pre}; After: ${post}`,
      };
    }
    case 'shell_command_pre': {
      const p = event.payload as ShellCommandPrePayload;
      const cmd = p.argv.join(' ');
      const fileCount = p.fileArgs.length;
      const files = fileCount > 0 ? `; ${fileCount} file arg(s) hashed` : '';
      return {
        summary: `Pre-capture (${p.source}): ${cmd.length > 80 ? cmd.slice(0, 77) + '...' : cmd}`,
        detail: `cwd=${p.cwd} user=${p.user}${files}`,
      };
    }
    case 'tool_call_effect': {
      const p = event.payload as ToolCallEffectPayload;
      const exitInfo = p.exitCode !== null ? ` (exit ${p.exitCode})` : '';
      const duration = p.durationMs !== null ? ` in ${p.durationMs}ms` : '';
      const changed = p.files.filter((f) => f.change !== 'unchanged');
      const files = changed.length > 0
        ? changed.map((f) => `${f.path} ${f.change}`).join(', ')
        : 'no declared file changed';
      const intent = p.intentEventId
        ? `Closes [#evt-${p.intentEventId}]${p.intentEventIdSource === 'correlated' ? ' (matched on input hash, not recorded by the hook)' : ''}`
        : 'No intent record; what the agent meant to run is not in this bundle';
      return {
        summary: `Outcome: ${p.toolName}${exitInfo}${duration}`,
        detail: `${intent}; ${files}`,
      };
    }
    case 'shell_command_post': {
      return { summary: 'Post-capture: command completed', detail: '' };
    }
    case 'env_change': {
      return { summary: 'Environment change detected', detail: '' };
    }
    case 'process_spawn': {
      const p = event.payload as ProcessSpawnPayload;
      if (p.source !== 'kernel') {
        return { summary: 'Process spawned', detail: '' };
      }
      const cmd = p.argv.length > 0 ? p.argv.join(' ') : p.exe;
      const witnessed = p.matchedIntentEventId
        ? `Matches hook intent [#evt-${p.matchedIntentEventId}]`
        : 'No hook or shim recorded this command';
      return {
        summary: `Kernel execve: ${cmd.length > 80 ? cmd.slice(0, 77) + '...' : cmd}`,
        detail: `pid=${p.pid} ppid=${p.ppid} comm=${p.comm ?? ''}; ${witnessed}`,
      };
    }
    case 'error': {
      const p = event.payload as ErrorPayload;
      return { summary: `Error: ${p.message}`, detail: p.code ? `Code: ${p.code}` : '' };
    }
    case 'gap': {
      const p = event.payload as GapPayload;
      return {
        summary: `Gap: ${p.reason.replace(/_/g, ' ')}`,
        detail: p.detail.length > 200 ? p.detail.slice(0, 197) + '...' : p.detail,
      };
    }
    case 'capture_failed': {
      const p = event.payload as CaptureFailedPayload;
      return {
        summary: `Capture failed: ${p.errorClass} in ${p.phase}`,
        detail: p.message,
      };
    }
    default: {
      return { summary: `Unknown event type: ${(event as Event).type}`, detail: '' };
    }
  }
}
