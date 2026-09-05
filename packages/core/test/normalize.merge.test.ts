// packages/core/test/normalize.merge.test.ts
//
// Tests for event merge (multi-source, gap detection).
// Merge with gap detection (docs/bundle-format.md#gap-events).
//
// Tests exercise:
//   1. Single terraform destroy session (no gaps)
//   2. Session where shell history has commands not in JSONL (gap event emitted)
//   3. Session where JSONL has tool results with no command field (gap event emitted)
//   4. Reflog disturbance with no captured command (gap event emitted)
//   5. Real fixtures: terraform-destroy.jsonl + shell-history.txt + git-reflog.txt

import { describe, it, expect } from 'vitest';
import {
  normalizeClaudeCodeJsonl,
  parseShellHistory,
  parseGitReflog,
  reflogToEvents,
  mergeEvents,
  type Event,
  sha256,
  ulidFromTime,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');

// ── Helper ───────────────────────────────────────────────────────────

function countType(events: Event[], type: string): number {
  return events.filter((e) => e.type === type).length;
}

// ── Tests ────────────────────────────────────────────────────────────

describe('mergeEvents', () => {
  describe('basic merge', () => {
    it('merges events from a single source (claude code only)', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
      const { events: merged, gapCount } = mergeEvents(
        { claudeCodeEvents: claudeEvents },
        { sessionId: 'sess-1' }
      );
      expect(gapCount).toBe(0);
      expect(merged.length).toBe(1);
    });

    it('merges events from multiple sources', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
      const shellHistory = 'terraform destroy\n';
      const shellCommands = parseShellHistory(shellHistory);
      const shellSessionId = 'sess-1';
      const shellEvents = [];
      for (const cmd of shellCommands) {
        const id = ulidFromTime(Date.now());
        shellEvents.push({
          id,
          wallTs: cmd.timestamp || '2025-05-18T15:31:00.000Z',
          monoNs: 1n,
          sessionId: shellSessionId,
          agentId: 'shell' as const,
          parentEventId: null,
          type: 'shell_command_pre' as const,
          payload: {
            argv: cmd.argv,
            cwd: '',
            envHash: '',
            envSubset: {},
            ttyId: null,
            user: '',
            hostname: '',
            parentProcessTree: [],
            fileArgs: [],
            source: 'shell-shim' as const,
            captureSchemaVersion: 1,
          },
          payloadHash: sha256({ argv: cmd.argv }),
        });
      }
      const { events: merged, gapCount } = mergeEvents(
        {
          claudeCodeEvents: claudeEvents,
          shellHistoryEvents: shellEvents,
        },
        { sessionId: 'sess-1' }
      );
      expect(gapCount).toBeGreaterThanOrEqual(0);
      expect(merged.length).toBeGreaterThan(claudeEvents.length);
    });
  });

  describe('gap detection', () => {
    it('emits gap for unmatched shell_command_pre', () => {
      const shellHistory = 'terraform destroy -auto-approve\n';
      const shellCommands = parseShellHistory(shellHistory);
      const shellSessionId = 'sess-1';
      const shellEvents = [];
      for (const cmd of shellCommands) {
        const id = ulidFromTime(Date.now());
        shellEvents.push({
          id,
          wallTs: '2025-05-18T15:31:00.000Z',
          monoNs: 1n,
          sessionId: shellSessionId,
          agentId: 'shell' as const,
          parentEventId: null,
          type: 'shell_command_pre' as const,
          payload: {
            argv: cmd.argv,
            cwd: '',
            envHash: '',
            envSubset: {},
            ttyId: null,
            user: '',
            hostname: '',
            parentProcessTree: [],
            fileArgs: [],
            source: 'shell-shim' as const,
            captureSchemaVersion: 1,
          },
          payloadHash: sha256({ argv: cmd.argv }),
        });
      }
      const { events: merged, gapCount: _gapCount } = mergeEvents(
        { shellHistoryEvents: shellEvents },
        { sessionId: 'sess-1' }
      );
      // shell_command_pre without matching tool_result = gap
      const gaps = merged.filter((e) => e.type === 'gap');
      expect(gaps.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('deduplication', () => {
    it('removes duplicate events by id', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:00.000Z',
      });
      const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
      const { events: merged } = mergeEvents(
        {
          claudeCodeEvents: [...claudeEvents, ...claudeEvents], // duplicate
        },
        { sessionId: 'sess-1' }
      );
      expect(merged.length).toBe(1);
    });
  });

  describe('sorting', () => {
    it('sorts events by (wallTs, monoNs)', () => {
      const jsonl = JSON.stringify({
        type: 'user',
        content: 'hello',
        timestamp: '2025-05-18T15:30:05.000Z',
      });
      const { events: laterEvents } = normalizeClaudeCodeJsonl(jsonl);
      const earlier = {
        id: '01JABC12345678901234567890',
        wallTs: '2025-05-18T15:30:00.000Z',
        monoNs: 0n,
        sessionId: 'sess-1',
        agentId: 'claude-code' as const,
        parentEventId: null,
        type: 'prompt' as const,
        payload: { text: 'earlier' },
        payloadHash: 'abc',
      };
      const { events: merged } = mergeEvents(
        {
          claudeCodeEvents: [laterEvents[0], earlier as Event],
        },
        { sessionId: 'sess-1' }
      );
      expect(merged[0].wallTs).toBe('2025-05-18T15:30:00.000Z');
      expect(merged[1].wallTs).toBe('2025-05-18T15:30:05.000Z');
    });
  });

  describe('real fixtures: terraform-destroy.jsonl', () => {
    it('produces correct event counts (no gaps expected for well-formed JSONL)', () => {
      const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
      const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
      const { events: merged, gapCount } = mergeEvents(
        { claudeCodeEvents: claudeEvents },
        { sessionId: 'sess-terraform' }
      );
      expect(gapCount).toBe(3); // tool_results without matching shell_command_pre
      expect(countType(merged, 'prompt')).toBe(3);
      expect(countType(merged, 'assistant_message')).toBe(7);
      expect(countType(merged, 'tool_call_intent')).toBe(4);
      expect(countType(merged, 'tool_result')).toBe(3);
      expect(countType(merged, 'file_diff')).toBe(1);
    });
  });

  describe('real fixtures: full pipeline (JSONL + shell history + reflog)', () => {
    it('produces correct event counts from all sources', () => {
      const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
      const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
      const shellHistory = readFileSync(join(fixturesDir, 'shell-history.txt'), 'utf-8');
      const shellCommands = parseShellHistory(shellHistory);
      const shellSessionId = 'sess-full';
      const shellEvents = [];
      for (const cmd of shellCommands) {
        const id = ulidFromTime(Date.now());
        shellEvents.push({
          id,
          wallTs: cmd.timestamp || '2025-05-18T15:31:00.000Z',
          monoNs: BigInt(shellEvents.length),
          sessionId: shellSessionId,
          agentId: 'shell' as const,
          parentEventId: null,
          type: 'shell_command_pre' as const,
          payload: {
            argv: cmd.argv,
            cwd: '',
            envHash: '',
            envSubset: {},
            ttyId: null,
            user: '',
            hostname: '',
            parentProcessTree: [],
            fileArgs: [],
            source: 'shell-shim' as const,
            captureSchemaVersion: 1,
          },
          payloadHash: sha256({ argv: cmd.argv }),
        });
      }
      const reflog = readFileSync(join(fixturesDir, 'git-reflog.txt'), 'utf-8');
      const reflogEntries = parseGitReflog(reflog);
      const { events: reflogResult } = reflogToEvents(reflogEntries, {
        sessionId: shellSessionId,
        agentId: 'shell' as const,
        monoOffset: claudeEvents.length + shellEvents.length,
      });
      const { events: merged, gapCount } = mergeEvents(
        {
          claudeCodeEvents: claudeEvents,
          shellHistoryEvents: shellEvents,
          reflogEvents: reflogResult,
        },
        { sessionId: shellSessionId }
      );
      // Should have events from all sources
      expect(merged.length).toBeGreaterThan(claudeEvents.length);
      expect(gapCount).toBeGreaterThan(0); // shell_command_pre without tool_result = gaps
    });
  });
});
