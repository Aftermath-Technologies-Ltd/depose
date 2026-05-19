// Tests that the default destructive ruleset resolves against the CLI
// package (via import.meta.url), not against the process CWD. A bundle
// produced from a session containing `terraform destroy` must flag a
// destructive operation regardless of where the CLI is invoked from.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { main } from '../src/commands/main.js';
import { readFileSync, existsSync, rmSync, mkdirSync, readdirSync, mkdtempSync } from 'node:fs';
import { join as pathJoin } from 'node:path';
import { tmpdir } from 'node:os';

const fixturesDir = pathJoin(__dirname, '../../core/test/fixtures');
const sessionFixture = pathJoin(fixturesDir, 'terraform-destroy.jsonl');
const testOutputDir = pathJoin(__dirname, 'test-output-rules-default');

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

function readManifest(outDir: string): { counts: { destructiveOperations: number; events: number } } {
  const items = readdirSync(outDir);
  const bundleDir = items.find((d) => d.startsWith('incident-'));
  expect(bundleDir, `expected an incident-* directory in ${outDir}`).toBeDefined();
  expect(existsSync(pathJoin(outDir, bundleDir!, 'manifest.json'))).toBe(true);
  return JSON.parse(readFileSync(pathJoin(outDir, bundleDir!, 'manifest.json'), 'utf-8'));
}

describe('default ruleset resolution', () => {
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    cleanup();
  });

  afterEach(() => {
    process.chdir(originalCwd);
    cleanup();
  });

  it.each([
    ['repo root', () => pathJoin(__dirname, '../../..')],
    ['system tmp', () => mkdtempSync(pathJoin(tmpdir(), 'depose-cwd-'))],
    ['cli package dir', () => pathJoin(__dirname, '..')],
  ])('flags destructive operations when invoked from %s', async (_label, getCwd) => {
    const cwd = getCwd();
    process.chdir(cwd);
    const outDir = pathJoin(testOutputDir, _label.replace(/\s+/g, '-'));
    mkdirSync(outDir, { recursive: true });

    const restore = silence();
    await main([
      'reconstruct',
      '--from-claude',
      sessionFixture,
      '--output-dir',
      outDir,
    ]);
    restore.restore();

    const manifest = readManifest(outDir);
    expect(manifest.counts.events).toBeGreaterThan(0);
    expect(manifest.counts.destructiveOperations).toBeGreaterThan(0);
  });
});
