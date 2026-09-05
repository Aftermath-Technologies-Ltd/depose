// packages/capture-claude/test/capture-failed.test.ts
//
// A hook failure must leave evidence. These tests force an exception in
// each phase of runHook and check that exactly one capture_failed record
// lands in the store, that the record names the phase, and that the
// sidecar fallback engages when the record file cannot be written.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readdirSync, readFileSync, chmodSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { CAPTURE_FAILED_SIDECAR, type CaptureFailedPayload } from '@depose/core';
import { runHook, clearProcessTreeCache, type HookDeps } from '../src/hook-entry.js';
import { writeCaptureFailedRecord, sanitizeErrorMessage } from '../src/capture-failed.js';

const GOOD_INPUT = JSON.stringify({
  tool_name: 'Bash',
  tool_input: { command: 'rm -rf /data/training' },
  cwd: '/home/user',
  session_id: 'sess-cf',
});

let captureDir: string;

beforeEach(() => {
  captureDir = mkdtempSync(join(tmpdir(), 'depose-capture-failed-'));
  process.env.DEPOSE_CAPTURE_DIR = captureDir;
  clearProcessTreeCache();
});

afterEach(() => {
  chmodSync(captureDir, 0o700);
  rmSync(captureDir, { recursive: true, force: true });
});

function quietDeps(overrides: Partial<HookDeps>): Partial<HookDeps> {
  return {
    readStdin: async () => GOOD_INPUT,
    walkProcessTree: () => [],
    resolveTty: () => null,
    ...overrides,
  };
}

function recordFiles(): string[] {
  return readdirSync(captureDir).filter((f) => f.endsWith('.json'));
}

function storedFailures(): CaptureFailedPayload[] {
  return recordFiles()
    .map((f) => JSON.parse(readFileSync(join(captureDir, f), 'utf-8')) as { kind?: string })
    .filter((r): r is CaptureFailedPayload => r.kind === 'capture_failed');
}

const boom = (): never => {
  throw new RangeError('forced failure\nsecond line should be dropped');
};

describe('runHook leaves a capture_failed record for a failure in each phase', () => {
  const phases: Array<[string, Partial<HookDeps>, string | null]> = [
    ['read-input', { readStdin: async () => boom() }, null],
    ['parse-input', { readStdin: async () => '{not json' }, null],
    ['env', { env: () => boom() }, 'sess-cf'],
    ['file-hash', { hashFileArgs: () => boom() }, 'sess-cf'],
    ['process-tree', { walkProcessTree: () => boom() }, 'sess-cf'],
    ['tty', { resolveTty: () => boom() }, 'sess-cf'],
    ['write-record', { writeCaptureRecord: () => boom() }, 'sess-cf'],
  ];

  it.each(phases)('%s', async (phase, overrides, expectedSession) => {
    const outcome = await runHook(quietDeps(overrides));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.phase).toBe(phase);
    expect(outcome.failure.written).toBe('record');

    const failures = storedFailures();
    expect(failures).toHaveLength(1);
    expect(recordFiles()).toHaveLength(1);
    const record = failures[0]!;
    expect(record.phase).toBe(phase);
    expect(record.sessionId).toBe(expectedSession);
    expect(record.errorClass).toBe(phase === 'parse-input' ? 'SyntaxError' : 'RangeError');
    expect(record.message).not.toContain('\n');
    expect(record.monoNs).toMatch(/^\d+$/);
    expect(Date.parse(record.capturedAt)).not.toBeNaN();
  });

  it('writes a normal record and no failure when nothing throws', async () => {
    const outcome = await runHook(quietDeps({}));
    expect(outcome.ok).toBe(true);
    expect(storedFailures()).toHaveLength(0);
    expect(recordFiles()).toHaveLength(1);
  });
});

describe('writeCaptureFailedRecord fallback', () => {
  it('appends to the sidecar when the record file cannot be created', () => {
    if (process.getuid && process.getuid() === 0) return; // root ignores directory modes
    const sidecar = join(captureDir, CAPTURE_FAILED_SIDECAR);
    writeFileSync(sidecar, '', { mode: 0o600 });
    chmodSync(captureDir, 0o500);

    const outcome = writeCaptureFailedRecord({
      phase: 'write-record',
      error: new Error('disk full'),
      sessionId: 'sess-cf',
      toolName: 'Bash',
    });
    expect(outcome.written).toBe('sidecar');
    const lines = readFileSync(sidecar, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]!) as { ulid: string; payload: CaptureFailedPayload };
    expect(entry.ulid).toBe(outcome.ulid);
    expect(entry.payload.kind).toBe('capture_failed');
    expect(entry.payload.message).toBe('disk full');
  });
});

describe('sanitizeErrorMessage', () => {
  it('keeps the first line, strips control characters, and caps length', () => {
    expect(sanitizeErrorMessage('a\tb\u0001c\nmore')).toBe('a b c');
    expect(sanitizeErrorMessage('x'.repeat(400))).toHaveLength(300);
  });
});
