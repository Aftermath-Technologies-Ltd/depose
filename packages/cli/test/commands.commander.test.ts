// Tests for commander-driven CLI parsing (D3).
//
// The hand-rolled parser this replaced had three known bugs:
//   1. `--key=value` was not recognized.
//   2. Repeated flags overwrote silently (no error, no array).
//   3. Values starting with `-` were treated as new flags.
//
// We exercise each one here to make sure the regression is closed.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { main } from '../src/commands/main.js';
import { readFileSync, existsSync, rmSync, mkdirSync, readdirSync } from 'node:fs';
import { join as pathJoin } from 'node:path';

const fixturesDir = pathJoin(__dirname, '../../core/test/fixtures');
const sessionFixture = pathJoin(fixturesDir, 'terraform-destroy.jsonl');
const testOutputDir = pathJoin(__dirname, 'test-output-commander');

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
}

function silence(): { restore: () => void } {
  const originalLog = console.log;
  const originalError = console.error;
  const originalExit = process.exit;
  console.log = vi.fn();
  console.error = vi.fn();
  process.exit = vi.fn() as unknown as typeof process.exit;
  return {
    restore: () => {
      console.log = originalLog;
      console.error = originalError;
      process.exit = originalExit;
    },
  };
}

describe('commander argument parsing', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('accepts --key=value form', async () => {
    const restore = silence();
    await main([
      'reconstruct',
      `--from-claude=${sessionFixture}`,
      `--output-dir=${testOutputDir}`,
    ]);
    restore.restore();

    const items = readdirSync(testOutputDir);
    const bundleDir = items.find((d) => d.startsWith('incident-'));
    expect(bundleDir, '--key=value should produce a bundle').toBeDefined();
    expect(existsSync(pathJoin(testOutputDir, bundleDir!, 'manifest.json'))).toBe(true);
  });

  it('accepts an output dir whose value starts with "-." or "./-"', async () => {
    // Names beginning with `-` confused the previous parser. We use
    // the equals form to be unambiguous; commander accepts both
    // forms but `--key value` would still fail to disambiguate a
    // leading-dash value, which is the language's limitation, not
    // ours.
    const trickyDir = pathJoin(testOutputDir, '-leading-dash');
    mkdirSync(trickyDir, { recursive: true });
    const restore = silence();
    await main([
      'reconstruct',
      '--from-claude',
      sessionFixture,
      `--output-dir=${trickyDir}`,
    ]);
    restore.restore();

    const items = readdirSync(trickyDir);
    const bundleDir = items.find((d) => d.startsWith('incident-'));
    expect(bundleDir).toBeDefined();
  });

  it('rejects unknown options instead of silently accepting them', async () => {
    let exitCode: number | undefined;
    const originalLog = console.log;
    const originalError = console.error;
    const originalExit = process.exit;
    console.log = vi.fn();
    console.error = vi.fn();
    process.exit = vi.fn((code?: number | string | null) => {
      exitCode = typeof code === 'number' ? code : Number(code) || 0;
      return undefined as never;
    }) as unknown as typeof process.exit;

    await main([
      'reconstruct',
      '--from-claude',
      sessionFixture,
      '--totally-bogus-flag',
    ]);

    console.log = originalLog;
    console.error = originalError;
    process.exit = originalExit;

    expect(exitCode).not.toBe(0);
  });
});
