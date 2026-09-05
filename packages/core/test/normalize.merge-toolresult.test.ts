// packages/core/test/normalize.merge-toolresult.test.ts
//
// Correlating a tool_result back to the pre-capture that started it, and
// keeping every payloadHash intact while doing so. Both were regressions:
// the first because a result with a tool_use_id used to find nothing, the
// second because writing the correlation into the payload changed the
// hash the chain had already committed to.

import { describe, it, expect } from 'vitest';
import {
  normalizeClaudeCodeJsonl,
  mergeEvents,
  sha256,
  ulidFromTime,
  type Event,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');

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
      monoNs: 0n,
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
      monoNs: 1000n,
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
      monoNs: 2000n,
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
      monoNs: 3000n,
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
      monoNs: 500n,
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
      monoNs: 1500n,
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
      monoNs: 0n,
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
      monoNs: 1000n,
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
      monoNs: 500n,
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
