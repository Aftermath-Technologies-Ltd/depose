// packages/core/test/normalize.claude-code.test.ts
//
// Tests for Claude Code JSONL normalizer.
// BUILD_PLAN.md §5 (Phase 1): passive reconstruction.
//
// Tests exercise:
//   1. Single terraform destroy session (no gaps)
//   2. Session with tool results (tool_result events created)
//   3. Session with file edits (file_diff events created)
//   4. Session with error and unknown types (gap events created)
//   5. Unparseable JSONL lines (gap events created)
//   6. Tool call intent extraction from assistant messages
//   7. Real fixture: terraform-destroy.jsonl
//   8. Real fixture: session-with-gaps.jsonl

import { describe, it, expect } from 'vitest';
import {
  normalizeClaudeCodeJsonl,
  type Event,
  type ToolCallIntentPayload,
  type ToolResultPayload,
  type FileDiffPayload,
  type GapPayload,
  type ErrorPayload,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');

// ── Helper ───────────────────────────────────────────────────────────

function countType(events: Event[], type: string): number {
  return events.filter((e) => e.type === type).length;
}

// ── Tests ────────────────────────────────────────────────────────────

describe('normalizeClaudeCodeJsonl', () => {
  describe('prompt events', () => {
    it('extracts prompt events from user lines', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'Deploy the app',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const prompts = events.filter((e) => e.type === 'prompt');
      expect(prompts.length).toBe(1);
      expect(prompts[0].payload).toEqual({ text: 'Deploy the app' });
    });
  });

  describe('assistant_message events', () => {
    it('extracts assistant messages', () => {
      const jsonl = JSON.stringify({
        type: 'assistant',
        content: 'I will help you',
        timestamp: '2025-05-18T15:30:05.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const assistants = events.filter((e) => e.type === 'assistant_message');
      expect(assistants.length).toBe(1);
      expect(assistants[0].payload.content).toBe('I will help you');
    });
  });

  describe('tool_call_intent events', () => {
    it('extracts tool_call_intent from assistant tool_calls', () => {
      const jsonl = JSON.stringify({
        type: 'assistant',
        content: 'Running terraform',
        timestamp: '2025-05-18T15:30:05.000Z',
        tool_calls: [
          {
            tool_name: 'Bash',
            input: { command: 'terraform plan' },
          },
        ],
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      // Assistant line with tool_calls should emit BOTH assistant_message AND tool_call_intent
      const assistants = events.filter((e) => e.type === 'assistant_message');
      expect(assistants.length).toBe(1);
      expect(assistants[0].payload.content).toBe('Running terraform');
      const intents = events.filter((e) => e.type === 'tool_call_intent');
      expect(intents.length).toBe(1);
      const payload = intents[0].payload as ToolCallIntentPayload;
      expect(payload.toolName).toBe('Bash');
      expect(payload.toolInput).toEqual({ command: 'terraform plan' });
      expect(payload.linkedShellCommandPreId).toBeNull();
    });

    it('extracts multiple tool_call_intents', () => {
      const jsonl = JSON.stringify({
        type: 'assistant',
        content: 'Running two commands',
        timestamp: '2025-05-18T15:30:05.000Z',
        tool_calls: [
          { tool_name: 'Bash', input: { command: 'ls' } },
          { tool_name: 'Bash', input: { command: 'pwd' } },
        ],
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const intents = events.filter((e) => e.type === 'tool_call_intent');
      expect(intents.length).toBe(2);
    });
  });

  describe('tool_result events', () => {
    it('extracts tool_result from tool lines', () => {
      const jsonl = JSON.stringify({
        type: 'tool',
        tool_name: 'Bash',
        input: { command: 'terraform plan' },
        output: 'No changes.',
        timestamp: '2025-05-18T15:30:15.000Z',
        exit_code: 0,
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const results = events.filter((e) => e.type === 'tool_result');
      expect(results.length).toBe(1);
      const payload = results[0].payload as ToolResultPayload;
      expect(payload.toolName).toBe('Bash');
      expect(payload.output).toBe('No changes.');
      expect(payload.exitCode).toBe(0);
      expect(payload.linkedShellCommandPreId).toBeNull();
    });
  });

  describe('file_diff events', () => {
    it('extracts file_diff from file_edit lines', () => {
      const jsonl = JSON.stringify({
        type: 'file_edit',
        path: 'README.md',
        diff: '@@ -1 +1 @@\n-old\n+new',
        timestamp: '2025-05-18T15:32:10.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const diffs = events.filter((e) => e.type === 'file_diff');
      expect(diffs.length).toBe(1);
      const payload = diffs[0].payload as FileDiffPayload;
      expect(payload.path).toBe('README.md');
      expect(payload.diff).toBe('@@ -1 +1 @@\n-old\n+new');
    });
  });

  describe('error events', () => {
    it('extracts error from error lines', () => {
      const jsonl = JSON.stringify({
        type: 'error',
        error: 'Connection refused',
        timestamp: '2025-05-18T15:33:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const errors = events.filter((e) => e.type === 'error');
      expect(errors.length).toBe(1);
      const payload = errors[0].payload as ErrorPayload;
      expect(payload.message).toBe('Connection refused');
    });
  });

  describe('gap events', () => {
    it('emits gap for unknown line types', () => {
      const jsonl = JSON.stringify({
        type: 'unknown_type',
        content: 'Something',
        timestamp: '2025-05-18T15:33:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const gaps = events.filter((e) => e.type === 'gap');
      expect(gaps.length).toBe(1);
      const payload = gaps[0].payload as GapPayload;
      expect(payload.reason).toBe('shell_history_without_jsonl_correlation');
    });

    it('emits gap for unparseable JSON lines', () => {
      const jsonl = 'not valid json\n{"type":"user","content":"hello","timestamp":"2025-05-18T15:30:00.000Z"}';
      const { events, warnings } = normalizeClaudeCodeJsonl(jsonl);
      const gaps = events.filter((e) => e.type === 'gap');
      expect(gaps.length).toBe(1);
      expect(warnings.length).toBe(1);
    });
  });

  describe('event structure', () => {
    it('produces events with correct base fields', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events } = normalizeClaudeCodeJsonl(jsonl);
      const event = events[0];
      expect(event.id).toHaveLength(26); // ULID
      expect(event.wallTs).toBe('2025-05-18T15:30:00.000Z');
      expect(event.monoNs).toBe(0);
      expect(event.agentId).toBe('claude-code');
      expect(event.parentEventId).toBeNull();
      expect(event.type).toBe('prompt');
      expect(event.payloadHash).toHaveLength(64); // SHA-256 hex
    });

    it('produces events with correct sessionId', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events, sessionId } = normalizeClaudeCodeJsonl(jsonl, {
        sessionId: '01JABC12345678901234567890',
      });
      expect(sessionId).toBe('01JABC12345678901234567890');
      expect(events[0].sessionId).toBe('01JABC12345678901234567890');
    });
  });

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
});
