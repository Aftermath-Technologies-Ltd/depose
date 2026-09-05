// packages/core/test/normalize.intent-effect.test.ts
//
// The two merge passes that pair a tool call's halves and attribute
// kernel execves. The end-to-end fixture in
// packages/cli/test/hook-intent-effect-bundle.test.ts drives these
// through the real hook; here they are exercised on the cases the hook
// path cannot reach on demand: a lost pending marker, a stale marker
// pointing at the wrong call, and execves just inside and just outside
// the correlation window.

import { describe, it, expect } from 'vitest';
import { bindIntentAndEffect } from '../src/normalize/merge-intent-effect.js';
import { correlateKernelExecves } from '../src/normalize/merge-kernel.js';
import { sha256 } from '../src/events/canonical-json.js';
import type {
  Event,
  GapPayload,
  ProcessSpawnPayload,
  ShellCommandPrePayload,
  ToolCallEffectPayload,
} from '../src/events/schema.js';

const SESSION = 'sess-pairing';
const BASE = Date.UTC(2025, 4, 18, 15, 30, 0);
const options = { sessionId: SESSION, agentId: 'claude-code' as const, matchWindowSeconds: 5 };

function at(seconds: number): string {
  return new Date(BASE + seconds * 1000).toISOString();
}

function intent(
  id: string,
  seconds: number,
  overrides: Partial<ShellCommandPrePayload> = {}
): Event {
  const payload: ShellCommandPrePayload = {
    argv: ['bash', '-c', 'terraform destroy'],
    cwd: '/srv',
    envHash: '',
    envSubset: {},
    ttyId: null,
    user: 'depose',
    hostname: 'host',
    parentProcessTree: [{ pid: 4242, ppid: 4200, exe: '/usr/bin/node', argv0: 'node' }],
    fileArgs: [],
    source: 'claude-pretooluse',
    captureSchemaVersion: 3,
    inputHash: 'hash-a',
    capturedAt: at(seconds),
    capturedAtSource: 'recorded',
    sessionId: SESSION,
    ...overrides,
  };
  return event(id, seconds, 'shell_command_pre', payload);
}

function effect(
  id: string,
  seconds: number,
  overrides: Partial<ToolCallEffectPayload> = {}
): Event {
  const payload: ToolCallEffectPayload = {
    kind: 'effect',
    toolName: 'Bash',
    cwd: '/srv',
    exitCode: 0,
    durationMs: 120,
    intentEventId: null,
    intentEventIdSource: 'none',
    inputHash: 'hash-a',
    files: [],
    source: 'claude-posttooluse',
    captureSchemaVersion: 3,
    capturedAt: at(seconds),
    capturedAtSource: 'recorded',
    monoNs: String(seconds * 1_000_000_000),
    sessionId: SESSION,
    ...overrides,
  };
  return event(id, seconds, 'tool_call_effect', payload);
}

function execve(id: string, seconds: number, ancestry: number[], argv: string[]): Event {
  const payload: ProcessSpawnPayload = {
    pid: 5100,
    ppid: ancestry[0] ?? 1,
    exe: argv[0]!,
    argv,
    cwd: '/srv',
    comm: 'terraform',
    ancestry,
    monoNs: String(seconds * 1_000_000_000),
    source: 'kernel',
    matchedIntentEventId: null,
  };
  return event(id, seconds, 'process_spawn', payload);
}

function event(id: string, seconds: number, type: Event['type'], payload: unknown): Event {
  return {
    id,
    wallTs: at(seconds),
    monoNs: BigInt(seconds),
    sessionId: SESSION,
    agentId: 'claude-code',
    parentEventId: null,
    type,
    payload,
    payloadHash: sha256(payload),
  } as Event;
}

function reasons(gaps: Event[]): string[] {
  return gaps.map((g) => (g.payload as GapPayload).reason);
}

describe('bindIntentAndEffect', () => {
  it('does nothing when the session has no post-execution records', () => {
    const result = bindIntentAndEffect([intent('01A', 0), intent('01B', 5)], options);
    expect(result.gaps).toEqual([]);
    expect(result.linkedCount).toBe(0);
  });

  it('links a pair by the intent id the hook recorded', () => {
    const i = intent('01A', 0);
    const e = effect('01B', 2, { intentEventId: '01A', intentEventIdSource: 'recorded' });
    const result = bindIntentAndEffect([i, e], options);

    expect(result.linkedCount).toBe(1);
    expect(result.gaps).toEqual([]);
    expect(i.correlation?.linkedEffectId).toBe('01B');
    expect(e.correlation?.linkedIntentId).toBe('01A');
    expect((e.payload as ToolCallEffectPayload).intentEventIdSource).toBe('recorded');
  });

  it('falls back to the input hash when the pending marker was lost, and says the link was matched', () => {
    const i = intent('01A', 0);
    const e = effect('01B', 2);
    const before = e.payloadHash;
    const result = bindIntentAndEffect([i, e], options);

    expect(result.linkedCount).toBe(1);
    const payload = e.payload as ToolCallEffectPayload;
    expect(payload.intentEventId).toBe('01A');
    expect(payload.intentEventIdSource).toBe('correlated');
    expect(e.payloadHash).not.toBe(before);
    expect(e.payloadHash).toBe(sha256(payload));
  });

  it('prefers the nearest candidate when two intents share an input hash', () => {
    const far = intent('01A', 0);
    const near = intent('01B', 3);
    const e = effect('01C', 4);
    bindIntentAndEffect([far, near, e], options);

    expect((e.payload as ToolCallEffectPayload).intentEventId).toBe('01B');
    expect(far.correlation?.linkedEffectId).toBeUndefined();
  });

  it('reports an effect it cannot place as a gap rather than guessing', () => {
    const i = intent('01A', 0, { inputHash: 'hash-b' });
    const e = effect('01B', 60);
    const result = bindIntentAndEffect([i, e], options);

    expect(reasons(result.gaps)).toEqual(['effect_without_intent', 'intent_without_effect']);
    expect((e.payload as ToolCallEffectPayload).intentEventId).toBeNull();
  });

  it('reports an intent with no outcome, and names the command in the gap', () => {
    const lost = intent('01A', 0, { argv: ['bash', '-c', 'rm -rf /srv/data'], inputHash: 'hash-z' });
    const paired = intent('01B', 10);
    const e = effect('01C', 11, { intentEventId: '01B', intentEventIdSource: 'recorded' });
    const result = bindIntentAndEffect([lost, paired, e], options);

    const gaps = result.gaps.filter((g) => (g.payload as GapPayload).reason === 'intent_without_effect');
    expect(gaps).toHaveLength(1);
    const payload = gaps[0]!.payload as GapPayload;
    expect(payload.affectedEventIds).toEqual(['01A']);
    expect(payload.detail).toContain('rm -rf /srv/data');
  });

  it('leaves a reconstructed intent alone; only hook captures promise an outcome', () => {
    const reconstructed = intent('01A', 0, { source: 'reconstructed', inputHash: 'hash-z' });
    const paired = intent('01B', 10);
    const e = effect('01C', 11, { intentEventId: '01B', intentEventIdSource: 'recorded' });
    const result = bindIntentAndEffect([reconstructed, paired, e], options);

    expect(reasons(result.gaps)).toEqual([]);
  });

  it('reports a file whose hash moved between one outcome and the next pre-state', () => {
    const first = intent('01A', 0);
    const closed = effect('01B', 1, {
      intentEventId: '01A',
      intentEventIdSource: 'recorded',
      files: [{ path: '/srv/main.tf', preSha256: 'aa', postSha256: 'bb', sizeBytes: 10, change: 'modified' }],
    });
    const next = intent('01C', 10, {
      inputHash: 'hash-c',
      fileArgs: [{ path: '/srv/main.tf', preSha256: 'cc', sizeBytes: 12 }],
    });
    const closing = effect('01D', 11, { intentEventId: '01C', intentEventIdSource: 'recorded', inputHash: 'hash-c' });
    const result = bindIntentAndEffect([first, closed, next, closing], options);

    const gaps = result.gaps.filter((g) => (g.payload as GapPayload).reason === 'unwitnessed_file_change');
    expect(gaps).toHaveLength(1);
    const payload = gaps[0]!.payload as GapPayload;
    expect(payload.affectedEventIds).toEqual(['01B', '01C']);
    expect(payload.detail).toContain('/srv/main.tf');
  });

  it('stays quiet when the next pre-state matches the recorded outcome', () => {
    const first = intent('01A', 0);
    const closed = effect('01B', 1, {
      intentEventId: '01A',
      intentEventIdSource: 'recorded',
      files: [{ path: '/srv/main.tf', preSha256: 'aa', postSha256: 'bb', sizeBytes: 10, change: 'modified' }],
    });
    const next = intent('01C', 10, {
      inputHash: 'hash-c',
      fileArgs: [{ path: '/srv/main.tf', preSha256: 'bb', sizeBytes: 10 }],
    });
    const closing = effect('01D', 11, { intentEventId: '01C', intentEventIdSource: 'recorded', inputHash: 'hash-c' });
    const result = bindIntentAndEffect([first, closed, next, closing], options);

    expect(reasons(result.gaps)).toEqual([]);
  });
});

describe('correlateKernelExecves', () => {
  it('does nothing when the collector was not running', () => {
    const result = correlateKernelExecves([intent('01A', 0)], options);
    expect(result).toEqual({ gaps: [], matchedCount: 0, unwitnessedCount: 0 });
  });

  it('attributes an execve that shares an ancestor and lands inside the window', () => {
    const i = intent('01A', 0);
    const e = execve('01B', 3, [4242, 4200], ['/usr/bin/terraform', 'destroy']);
    const result = correlateKernelExecves([i, e], options);

    expect(result.matchedCount).toBe(1);
    expect(result.gaps).toEqual([]);
    expect((e.payload as ProcessSpawnPayload).matchedIntentEventId).toBe('01A');
    expect(e.correlation?.linkedShellCommandPreId).toBe('01A');
  });

  it('leaves an execve from an unrelated process tree unattributed and disclosed', () => {
    const i = intent('01A', 0);
    const e = execve('01B', 3, [9001, 9000], ['/usr/local/bin/aws', 's3', 'rb', 's3://prod']);
    const result = correlateKernelExecves([i, e], options);

    expect(result.unwitnessedCount).toBe(1);
    expect(reasons(result.gaps)).toEqual(['kernel_execve_without_hook']);
    expect((result.gaps[0]!.payload as GapPayload).detail).toContain('s3://prod');
    expect((e.payload as ProcessSpawnPayload).matchedIntentEventId).toBeNull();
  });

  it('does not reach past the window to find an intent', () => {
    const i = intent('01A', 0);
    const e = execve('01B', 30, [4242, 4200], ['/usr/bin/terraform', 'destroy']);
    const result = correlateKernelExecves([i, e], options);

    expect(result.matchedCount).toBe(0);
    expect(result.unwitnessedCount).toBe(1);
  });

  it('does not attribute an execve that ran well before its supposed intent', () => {
    const i = intent('01A', 10);
    const e = execve('01B', 0, [4242, 4200], ['/usr/bin/terraform', 'destroy']);
    const result = correlateKernelExecves([i, e], options);

    expect(result.matchedCount).toBe(0);
    expect(result.unwitnessedCount).toBe(1);
  });

  it('rewrites the payload hash after recording the attribution', () => {
    const i = intent('01A', 0);
    const e = execve('01B', 3, [4242, 4200], ['/usr/bin/terraform', 'destroy']);
    const before = e.payloadHash;
    correlateKernelExecves([i, e], options);

    expect(e.payloadHash).not.toBe(before);
    expect(e.payloadHash).toBe(sha256(e.payload));
  });
});
