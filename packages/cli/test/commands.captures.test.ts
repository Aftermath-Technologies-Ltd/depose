// packages/cli/test/commands.captures.test.ts
//
// The capture store grew to 9,617 records over three months with no way to
// see it and no supported way to trim it. Pruning removes forensic records,
// so the safety properties matter more than the happy path: an explicit
// window is required, and nothing is deleted without --yes.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, readdirSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseDuration,
  statCaptureStore,
  captureStoreWarning,
  handleCapturesPrune,
  CAPTURE_STORE_WARN_RECORDS,
} from '../src/commands/captures.js';

let captureDir: string;

const DAY_MS = 86_400_000;

function writeRecord(name: string, ageDays: number): string {
  const path = join(captureDir, `${name}.json`);
  writeFileSync(path, JSON.stringify({ argv: ['rm', '-rf', '/data'] }), 'utf-8');
  const seconds = (Date.now() - ageDays * DAY_MS) / 1000;
  utimesSync(path, seconds, seconds);
  return path;
}

beforeEach(() => {
  captureDir = join(tmpdir(), `depose-captures-${process.pid}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(captureDir, { recursive: true });
});

afterEach(() => {
  rmSync(captureDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('parseDuration', () => {
  it('parses days, hours, minutes, and seconds', () => {
    expect(parseDuration('90d')).toBe(90 * DAY_MS);
    expect(parseDuration('12h')).toBe(12 * 3_600_000);
    expect(parseDuration('30m')).toBe(30 * 60_000);
    expect(parseDuration('45s')).toBe(45_000);
  });

  it('rejects a duration with no unit', () => {
    expect(() => parseDuration('90')).toThrow(/Invalid duration/);
  });

  it('rejects an unsupported unit', () => {
    expect(() => parseDuration('3w')).toThrow(/Invalid duration/);
  });

  it('names the accepted units in the error so the fix is obvious', () => {
    expect(() => parseDuration('soon')).toThrow(/s, m, h, or d/);
  });
});

describe('statCaptureStore', () => {
  it('counts records and reports the age range', () => {
    writeRecord('01JOLD00000000000000000001', 100);
    writeRecord('01JMID00000000000000000001', 50);
    writeRecord('01JNEW00000000000000000001', 1);

    const stats = statCaptureStore(captureDir);

    expect(stats.records).toBe(3);
    expect(stats.bytes).toBeGreaterThan(0);
    expect(stats.oldest!.getTime()).toBeLessThan(stats.newest!.getTime());
  });

  it('returns zeroes for a store that does not exist', () => {
    const stats = statCaptureStore(join(captureDir, 'nope'));
    expect(stats).toEqual({ records: 0, bytes: 0, oldest: null, newest: null });
  });

  it('ignores files that are not capture records', () => {
    writeRecord('01JREAL0000000000000000001', 1);
    writeFileSync(join(captureDir, 'README.txt'), 'not a record', 'utf-8');

    expect(statCaptureStore(captureDir).records).toBe(1);
  });
});

describe('captureStoreWarning', () => {
  it('stays quiet for a small store', () => {
    writeRecord('01JSMALL000000000000000001', 1);
    expect(captureStoreWarning(captureDir)).toBeNull();
  });

  it('warns once the store passes the record threshold', () => {
    for (let i = 0; i < CAPTURE_STORE_WARN_RECORDS; i++) {
      writeFileSync(join(captureDir, `rec-${i}.json`), '{}', 'utf-8');
    }
    expect(captureStoreWarning(captureDir)).toContain('captures prune');
  });
});

describe('depose captures prune', () => {
  it('deletes nothing without --yes', () => {
    writeRecord('01JOLD00000000000000000001', 200);
    writeRecord('01JOLD00000000000000000002', 200);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    handleCapturesPrune({ 'capture-dir': captureDir, 'older-than': '90d' });

    expect(readdirSync(captureDir)).toHaveLength(2);
  });

  it('reports what a dry run would remove', () => {
    writeRecord('01JOLD00000000000000000001', 200);
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      logs.push(args.join(' '));
    });

    handleCapturesPrune({ 'capture-dir': captureDir, 'older-than': '90d' });

    expect(logs.join('\n')).toContain('Would remove 1 record(s)');
    expect(logs.join('\n')).toContain('dry run');
  });

  it('removes only records older than the window when --yes is given', () => {
    writeRecord('01JOLD00000000000000000001', 200);
    writeRecord('01JOLD00000000000000000002', 120);
    writeRecord('01JNEW00000000000000000001', 10);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    handleCapturesPrune({ 'capture-dir': captureDir, 'older-than': '90d', yes: true });

    const left = readdirSync(captureDir);
    expect(left).toEqual(['01JNEW00000000000000000001.json']);
  });

  it('keeps everything when nothing is old enough', () => {
    writeRecord('01JNEW00000000000000000001', 5);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    handleCapturesPrune({ 'capture-dir': captureDir, 'older-than': '90d', yes: true });

    expect(readdirSync(captureDir)).toHaveLength(1);
  });

  it('refuses to run without an explicit retention window', () => {
    writeRecord('01JOLD00000000000000000001', 200);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);

    handleCapturesPrune({ 'capture-dir': captureDir });

    expect(exit).toHaveBeenCalledWith(1);
    expect(readdirSync(captureDir)).toHaveLength(1);
  });
});
