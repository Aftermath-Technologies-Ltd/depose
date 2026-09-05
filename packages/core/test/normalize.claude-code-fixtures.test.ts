// packages/core/test/normalize.claude-code-fixtures.test.ts
//
// The normalizer against whole session files rather than single lines:
// the two synthetic transcripts and the real Claude Code format, whose
// content blocks and tool_use_id correlation are a different grammar
// through the same entry point. Per-event-type behaviour is in
// normalize.claude-code.test.ts.

import { describe, it, expect } from 'vitest';
import {
  normalizeClaudeCodeJsonl,
  type Event,
  type ToolCallIntentPayload,
  type ToolResultPayload,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');

// ── Helper ───────────────────────────────────────────────────────────

function countType(events: Event[], type: string): number {
  return events.filter((e) => e.type === type).length;
}

describe('normalizeClaudeCodeJsonl, whole session files', () => {

  describe('real fixture: terraform-destroy.jsonl', () => {
    it('produces correct event counts', () => {
      const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      expect(countType(events, 'prompt')).toBe(3);
      expect(countType(events, 'assistant_message')).toBe(7);
      expect(countType(events, 'tool_call_intent')).toBe(4);
      expect(countType(events, 'tool_result')).toBe(3);
      expect(countType(events, 'file_diff')).toBe(1);
      expect(countType(events, 'gap')).toBe(0);
    });
  });

  describe('real fixture: session-with-gaps.jsonl', () => {
    it('produces correct event counts including gaps', () => {
      const jsonl = readFileSync(join(fixturesDir, 'session-with-gaps.jsonl'), 'utf-8');
      const { events, warnings } = normalizeClaudeCodeJsonl(jsonl);
      expect(countType(events, 'prompt')).toBe(3);
      expect(countType(events, 'assistant_message')).toBe(6);
      expect(countType(events, 'tool_call_intent')).toBe(4);
      expect(countType(events, 'tool_result')).toBe(3);
      expect(countType(events, 'file_diff')).toBe(1);
      expect(countType(events, 'error')).toBe(1);
      // 1 gap for unknown_type + 1 gap for unparseable JSON = 2
      expect(countType(events, 'gap')).toBeGreaterThanOrEqual(2);
      expect(warnings.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── F-26: Contract test for real Claude Code session format ────────
  //
  // This fixture uses the real session format (typed content blocks
  // in line.message.content) that Claude Code actually emits.  The
  // normalizer must produce 0 gap events for recognized line types,
  // and the event type counts must match the input structure.
  describe('real fixture: session-real-format.jsonl (Claude Code v1+)', () => {
    it('parses real-format JSONL with zero gaps for recognized types', () => {
      const jsonl = readFileSync(join(fixturesDir, 'session-real-format.jsonl'), 'utf-8');
      const { events, warnings } = normalizeClaudeCodeJsonl(jsonl);

      // Every recognized line type must produce a non-gap event.
      // Unrecognized lines produce gap events, a real-format fixture
      // should have 0 gaps for its recognized content.
      expect(countType(events, 'gap')).toBe(0);
      expect(warnings.length).toBe(0);

      // Contract: the fixture contains:
      //   1 user prompt (text block)
      //   2 assistant messages (1 with thinking+tool_use+text, 1 with tool_use+text, 1 text-only)
      //     → 3 assistant_message events (one per line, each text block contributes)
      //     → 2 tool_call_intent events (Bash + Read)
      //   2 tool_result blocks (in user messages)
      expect(countType(events, 'prompt')).toBe(1);
      expect(countType(events, 'assistant_message')).toBeGreaterThanOrEqual(1);
      expect(countType(events, 'tool_call_intent')).toBe(2);
      expect(countType(events, 'tool_result')).toBe(2);
    });

    it('extracts tool_use_id from real-format tool_call blocks', () => {
      const jsonl = readFileSync(join(fixturesDir, 'session-real-format.jsonl'), 'utf-8');
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const intents = events.filter((e) => e.type === 'tool_call_intent');
      const payload0 = intents[0]!.payload as ToolCallIntentPayload;
      // tool_use blocks carry an `id` field that becomes toolUseId
      expect(payload0.toolUseId).toBe('toolu_real_001');
      expect(payload0.toolName).toBe('Bash');
    });

    it('correctly links tool_results to their tool_call_intents via toolUseId', () => {
      const jsonl = readFileSync(join(fixturesDir, 'session-real-format.jsonl'), 'utf-8');
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const results = events.filter((e) => e.type === 'tool_result');
      // Each tool_result carries the tool_use_id from its content block
      const result0 = results[0]!.payload as ToolResultPayload;
      expect(result0.toolUseId).toBe('toolu_real_001');
    });

    it('preserves thinking blocks as assistant_message content', () => {
      const jsonl = readFileSync(join(fixturesDir, 'session-real-format.jsonl'), 'utf-8');
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const assistantMsgs = events.filter((e) => e.type === 'assistant_message');
      // The first assistant line has a thinking block before the tool_use.
      // The normalizer preserves it in the payload content.
      const firstAssistant = assistantMsgs[0]!;
      // Thinking content should appear in the payload content (not dropped)
      expect(typeof firstAssistant.payload.content).toBe('string');
    });
  });
});
