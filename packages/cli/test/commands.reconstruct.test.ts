// packages/cli/test/commands.reconstruct.test.ts
//
// Tests for `depose reconstruct` CLI command.
// BUILD_PLAN.md §6 (Phase 1): `depose reconstruct --from-claude <session-id>`
// produces an unsigned `.depo` directory.
//
// Tests exercise:
//   1. `depose reconstruct --from-claude <fixture>` on terraform-destroy.jsonl
//   2. `depose reconstruct --from-claude <fixture>` on session-with-gaps.jsonl
//   3. Output directory contains manifest.json
//   4. Output directory contains events.jsonl
//   5. Manifest.rootHash is empty (Phase 1: unsigned)
//   6. Error: missing --from-claude argument
//   7. Error: non-existent input file
//   8. Error: unknown command
//   9. Help output

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { main } from '../src/commands/main.js';
import { readFileSync, existsSync, rmSync, mkdirSync, readdirSync } from 'node:fs';
import { join as pathJoin } from 'node:path';

const fixturesDir = pathJoin(__dirname, '../../core/test/fixtures');
const rulesPath = pathJoin(__dirname, '../rules/destructive.default.yaml');
const testOutputDir = pathJoin(__dirname, 'test-output-cli');

// ── Helper ───────────────────────────────────────────────────────────

function captureOutput(): { logs: string[]; errors: string[]; restore: () => void } {
  const logs: string[] = [];
  const errors: string[] = [];
  const originalLog = console.log;
  const originalError = console.error;
  const originalExit = process.exit;

  console.log = vi.fn((...args: unknown[]) => {
    logs.push(args.join(' '));
    originalLog(...args);
  });
  console.error = vi.fn((...args: unknown[]) => {
    errors.push(args.join(' '));
    originalError(...args);
  });
  process.exit = vi.fn() as unknown as typeof process.exit;

  return {
    logs,
    errors,
    restore: () => {
      console.log = originalLog;
      console.error = originalError;
      process.exit = originalExit;
    },
  };
}

function cleanup(): void {
  try {
    rmSync(testOutputDir, { recursive: true, force: true });
  } catch {
    // ignore
  }
  mkdirSync(testOutputDir, { recursive: true });
}

// ── Tests ────────────────────────────────────────────────────────────

describe('depose reconstruct', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('produces a bundle from terraform-destroy.jsonl', () => {
    const capture = captureOutput();

    main([
      'reconstruct',
      '--from-claude',
      pathJoin(fixturesDir, 'terraform-destroy.jsonl'),
      '--rules',
      rulesPath,
      '--output-dir',
      testOutputDir,
    ]);

    // Check that process.exit was not called (or called with 0)
    const _exitCode = process.exit as unknown as typeof process.exit & { mock?: { calls: number[][] } };

    // Find the output directory
    const outputDir = pathJoin(testOutputDir);
    const items = readdirSync(outputDir);
    const bundleDir = items.find((d: string) => d.startsWith('incident-'));
    expect(bundleDir).toBeDefined();
    expect(existsSync(pathJoin(outputDir, bundleDir!, 'manifest.json'))).toBe(true);
    expect(existsSync(pathJoin(outputDir, bundleDir!, 'events.jsonl'))).toBe(true);

    // Verify manifest
    const manifest = JSON.parse(
      readFileSync(pathJoin(outputDir, bundleDir!, 'manifest.json'), 'utf-8'),
    );
    expect(manifest.schemaVersion).toBe(2);
    expect(manifest.rootHash).toBe(''); // Phase 1: unsigned
    // Exact counts, not `> 0`. A lower bound passed on a machine with the
    // capture hook installed even when the bundle had absorbed 18,000
    // unrelated events, so it asserted nothing about this fixture.
    expect(manifest.counts.events).toBe(55);
    expect(manifest.counts.destructiveOperations).toBe(11);
    expect(manifest.counts.gaps).toBe(20);

    capture.restore();
  });

  it('produces a bundle from session-with-gaps.jsonl (with gaps)', () => {
    const capture = captureOutput();

    main([
      'reconstruct',
      '--from-claude',
      pathJoin(fixturesDir, 'session-with-gaps.jsonl'),
      '--rules',
      rulesPath,
      '--output-dir',
      testOutputDir,
    ]);

    const outputDir = pathJoin(testOutputDir);
    const items = readdirSync(outputDir);
    const bundleDir = items.find((d: string) => d.startsWith('incident-'));
    expect(bundleDir).toBeDefined();

    const manifest = JSON.parse(
      readFileSync(pathJoin(outputDir, bundleDir!, 'manifest.json'), 'utf-8'),
    );
    // session-with-gaps.jsonl carries error and unknown line types, which
    // become gap events. `>= 0` was vacuous; pin the real shape.
    expect(manifest.counts.events).toBe(57);
    expect(manifest.counts.destructiveOperations).toBe(9);
    expect(manifest.counts.gaps).toBe(22);

    capture.restore();
  });
});

describe('depose error cases', () => {
  let originalExit: typeof process.exit;

  beforeEach(() => {
    originalExit = process.exit;
    process.exit = vi.fn() as unknown as typeof process.exit;
  });

  afterEach(() => {
    process.exit = originalExit;
  });

  it('errors on missing --from-claude argument', () => {
    main(['reconstruct']);
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it('errors on non-existent input file', () => {
    main([
      'reconstruct',
      '--from-claude',
      '/nonexistent/file.jsonl',
    ]);
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it('errors on unknown command', () => {
    main(['foobar']);
    expect(process.exit).toHaveBeenCalledWith(1);
  });
});

describe('depose help', () => {
  let originalExit: typeof process.exit;

  beforeEach(() => {
    originalExit = process.exit;
    process.exit = vi.fn() as unknown as typeof process.exit;
  });

  afterEach(() => {
    process.exit = originalExit;
  });

  it('shows help on --help', () => {
    main(['--help']);
    // --help should not call process.exit (it returns normally)
  });
});
