// packages/core/src/normalize/claude-code-real.ts
//
// Normalizer for the real Claude Code session shape (v1+): a nested
// `message` object holding typed content blocks (text, thinking, tool_use,
// tool_result). The flat shape is handled in claude-code-flat.ts.

import type {
  Event,
  ToolCallIntentPayload,
  ToolResultPayload,
  PromptPayload,
  AssistantMessagePayload,
  GapPayload,
} from '../events/schema.js';
import type { ClaudeCodeLine, NormalizeLineOptions } from './claude-code-types.js';
import { buildEvent } from './claude-code-build-event.js';

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
export function normalizeRealSessionLine(
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

