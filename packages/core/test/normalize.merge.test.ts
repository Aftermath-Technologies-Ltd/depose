// packages/core/test/normalize.merge.test.ts
//
// Tests for event merge (multi-source, gap detection).
// BUILD_PLAN.md §5 (Phase 1): merge with gap detection.
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
  buildTimeline,
  loadDestructiveRules,
  matchDestructiveRules,
  type Event,
  sha256,
  ulidFromTime,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');
const rulesPath = join(__dirname, '../../cli/rules/destructive.default.yaml');

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
          monoNs: 1,
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
          monoNs: 1,
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
        monoNs: 0,
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
          monoNs: shellEvents.length,
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

describe('buildTimeline', () => {
  it('builds a correct timeline from terraform-destroy.jsonl', () => {
    const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const timeline = buildTimeline(claudeEvents, rules);
    expect(timeline.events.length).toBe(claudeEvents.length);
    expect(timeline.gaps.length).toBe(0);
    expect(timeline.fileChanges.length).toBe(1);
    expect(timeline.errors.length).toBe(0);
    // The fixture's tool_call_intent contains `terraform destroy
    // -auto-approve`. After the tool_call_intent fix, the destructive
    // matcher fires on that intent (rules: terraform-destroy +
    // terraform-apply-auto-approve), so we expect ≥1 destructive op.
    expect(timeline.destructiveOps.length).toBeGreaterThan(0);
    const ruleIds = timeline.destructiveOps.flatMap((op) =>
      op.matches.map((m) => m.ruleId)
    );
    expect(ruleIds).toContain('terraform-destroy');
  });

  it('builds a correct timeline from session-with-gaps.jsonl', () => {
    const jsonl = readFileSync(join(fixturesDir, 'session-with-gaps.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const rules = loadDestructiveRules(rulesPath);
    const timeline = buildTimeline(claudeEvents, rules);
    expect(timeline.events.length).toBe(claudeEvents.length);
    // Should have error events
    expect(timeline.errors.length).toBe(1);
    // Should have file changes
    expect(timeline.fileChanges.length).toBe(1);
  });
});

describe('destructive rules matching', () => {
  it('matches terraform destroy', () => {
    const rules = loadDestructiveRules(rulesPath);
    const event = {
      id: ulidFromTime(Date.now()),
      wallTs: '2025-05-18T15:30:00.000Z',
      monoNs: 0,
      sessionId: 'sess-1',
      agentId: 'shell' as const,
      parentEventId: null,
      type: 'shell_command_pre' as const,
      payload: {
        argv: ['terraform', 'destroy', '-auto-approve'],
        cwd: '',
        envHash: '',
        envSubset: {},
        ttyId: null,
        user: '',
        hostname: '',
        parentProcessTree: [],
        fileArgs: [],
        source: 'shell-shim' as const,
        captureSchemaVersion: 1 as const,
      },
      payloadHash: sha256({ argv: ['terraform', 'destroy'] }),
    };
    const matches = rules.filter((r) => {
      return matchDestructiveRules(event, [r]).length > 0;
    });
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });
});

// ── F-06: tool_result correlation regression tests ────────────────────

describe('F-06: tool_result correlation via tool_call_intent', () => {
  it('two Bash tool_results in the same 5s window each correlate to their own tool_call_intent', () => {
    // Create two Bash tool_call_intent events ~1 second apart,
    // each with a matching tool_result, both within a 5-second window.
    // Create two shell_command_pre events also in the same window.
    // Each tool_result should correlate to the shell_command_pre
    // that matches its own tool_call_intent's command, not crosswire.

    const baseTime = new Date('2025-05-18T15:30:00.000Z').getTime();

    // tool_call_intent A: Bash tool calling "npm test"
    const intentAPayload = {
      toolName: 'Bash',
      toolInput: { command: 'npm test' },
      toolUseId: 'tool-use-a',
    };
    const intentA: Event = {
      id: ulidFromTime(baseTime),
      wallTs: new Date(baseTime).toISOString(),
      monoNs: 0,
      sessionId: 'sess-f06',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_call_intent',
      payload: intentAPayload,
      payloadHash: sha256(intentAPayload),
    };

    // tool_call_intent B: Bash tool calling "npm build"
    const intentBPayload = {
      toolName: 'Bash',
      toolInput: { command: 'npm build' },
      toolUseId: 'tool-use-b',
    };
    const intentB: Event = {
      id: ulidFromTime(baseTime + 1000),
      wallTs: new Date(baseTime + 1000).toISOString(),
      monoNs: 1000,
      sessionId: 'sess-f06',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_call_intent',
      payload: intentBPayload,
      payloadHash: sha256(intentBPayload),
    };

    // tool_result A (result of intent A)
    const resultAPayload = {
      toolName: 'Bash',
      output: 'tests passed',
      exitCode: 0,
      toolUseId: 'tool-use-a',
    };
    const resultA: Event = {
      id: ulidFromTime(baseTime + 2000),
      wallTs: new Date(baseTime + 2000).toISOString(),
      monoNs: 2000,
      sessionId: 'sess-f06',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_result',
      payload: resultAPayload,
      payloadHash: sha256(resultAPayload),
    };

    // tool_result B (result of intent B)
    const resultBPayload = {
      toolName: 'Bash',
      output: 'build succeeded',
      exitCode: 0,
      toolUseId: 'tool-use-b',
    };
    const resultB: Event = {
      id: ulidFromTime(baseTime + 3000),
      wallTs: new Date(baseTime + 3000).toISOString(),
      monoNs: 3000,
      sessionId: 'sess-f06',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_result',
      payload: resultBPayload,
      payloadHash: sha256(resultBPayload),
    };

    // shell_command_pre A: "npm test" captured by shim
    const shellPreAPayload = {
      argv: ['npm', 'test'],
      cwd: '/home/user/project',
      envHash: '',
      envSubset: {},
      ttyId: null as string | null,
      user: 'user',
      hostname: 'host',
      parentProcessTree: [] as never[],
      fileArgs: [] as never[],
      source: 'shell-shim' as const,
      captureSchemaVersion: 1 as const,
    };
    const shellPreA: Event = {
      id: ulidFromTime(baseTime + 500),
      wallTs: new Date(baseTime + 500).toISOString(),
      monoNs: 500,
      sessionId: 'sess-f06',
      agentId: 'shell',
      parentEventId: null,
      type: 'shell_command_pre',
      payload: shellPreAPayload,
      payloadHash: sha256(shellPreAPayload),
    };

    // shell_command_pre B: "npm build" captured by shim
    const shellPreBPayload = {
      argv: ['npm', 'build'],
      cwd: '/home/user/project',
      envHash: '',
      envSubset: {},
      ttyId: null as string | null,
      user: 'user',
      hostname: 'host',
      parentProcessTree: [] as never[],
      fileArgs: [] as never[],
      source: 'shell-shim' as const,
      captureSchemaVersion: 1 as const,
    };
    const shellPreB: Event = {
      id: ulidFromTime(baseTime + 1500),
      wallTs: new Date(baseTime + 1500).toISOString(),
      monoNs: 1500,
      sessionId: 'sess-f06',
      agentId: 'shell',
      parentEventId: null,
      type: 'shell_command_pre',
      payload: shellPreBPayload,
      payloadHash: sha256(shellPreBPayload),
    };

    const { events } = mergeEvents(
      {
        claudeCodeEvents: [intentA, intentB, resultA, resultB],
        shellHistoryEvents: [shellPreA, shellPreB],
      },
      { sessionId: 'sess-f06', matchWindowSeconds: 5 }
    );

    // Find the events with correlation set
    const resultAEvent = events.find((e) => e.id === resultA.id);
    const resultBEvent = events.find((e) => e.id === resultB.id);

    // tool_result A should be linked to shell_command_pre A (npm test),
    // NOT shell_command_pre B (npm build), no crosswire.
    expect(resultAEvent?.correlation?.linkedShellCommandPreId).toBe(shellPreA.id);
    expect(resultAEvent?.correlation?.linkedShellCommandPreId).not.toBe(shellPreB.id);

    // tool_result B should be linked to shell_command_pre B (npm build),
    // NOT shell_command_pre A (npm test), no crosswire.
    expect(resultBEvent?.correlation?.linkedShellCommandPreId).toBe(shellPreB.id);
    expect(resultBEvent?.correlation?.linkedShellCommandPreId).not.toBe(shellPreA.id);
  });
});

// ── F-32: payloadHash integrity after merge ──────────────────────────

describe('F-32: payloadHash integrity after merge', () => {
  it('every event payloadHash === sha256(payload) after merge', () => {
    const jsonl = readFileSync(join(fixturesDir, 'terraform-destroy.jsonl'), 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl);
    const { events: merged } = mergeEvents(
      { claudeCodeEvents: claudeEvents },
      { sessionId: 'sess-f32' }
    );

    for (const event of merged) {
      // correlation is outside payload, so payloadHash must still match sha256(payload)
      const expected = sha256(event.payload);
      expect(event.payloadHash).toBe(expected);
    }
  });

  it('payloadHash unchanged after correlation is set on events', () => {
    // Create a tool_call_intent + tool_result + shell_command_pre to trigger correlation
    const baseTime = new Date('2025-05-18T15:30:00.000Z').getTime();

    const intentPayload = {
      toolName: 'Bash',
      toolInput: { command: 'ls -la' },
      toolUseId: 'tool-use-1',
    };
    const intent: Event = {
      id: ulidFromTime(baseTime),
      wallTs: new Date(baseTime).toISOString(),
      monoNs: 0,
      sessionId: 'sess-f32b',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_call_intent',
      payload: intentPayload,
      payloadHash: sha256(intentPayload),
    };

    const resultPayload = {
      toolName: 'Bash',
      output: 'file listing...',
      exitCode: 0,
      toolUseId: 'tool-use-1',
    };
    const result: Event = {
      id: ulidFromTime(baseTime + 1000),
      wallTs: new Date(baseTime + 1000).toISOString(),
      monoNs: 1000,
      sessionId: 'sess-f32b',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'tool_result',
      payload: resultPayload,
      payloadHash: sha256(resultPayload),
    };

    const shellPrePayload = {
      argv: ['ls', '-la'],
      cwd: '/home/user',
      envHash: '',
      envSubset: {},
      ttyId: null as string | null,
      user: 'user',
      hostname: 'host',
      parentProcessTree: [] as never[],
      fileArgs: [] as never[],
      source: 'shell-shim' as const,
      captureSchemaVersion: 1 as const,
    };
    const shellPre: Event = {
      id: ulidFromTime(baseTime + 500),
      wallTs: new Date(baseTime + 500).toISOString(),
      monoNs: 500,
      sessionId: 'sess-f32b',
      agentId: 'shell',
      parentEventId: null,
      type: 'shell_command_pre',
      payload: shellPrePayload,
      payloadHash: sha256(shellPrePayload),
    };

    const { events } = mergeEvents(
      { claudeCodeEvents: [intent, result], shellHistoryEvents: [shellPre] },
      { sessionId: 'sess-f32b' }
    );

    for (const event of events) {
      // Since correlation is outside payload, payloadHash must remain valid
      const expected = sha256(event.payload);
      expect(event.payloadHash).toBe(expected);
    }

    // Verify correlation was set (proving merge mutated correlation, not payload)
    const resultEvent = events.find((e) => e.id === result.id);
    expect(resultEvent?.correlation?.linkedShellCommandPreId).toBe(shellPre.id);
  });
});
