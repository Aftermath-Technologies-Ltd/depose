// packages/cli/test/hook-capture-failed-bundle.test.ts
//
// End to end: a forced hook failure in each phase becomes exactly one
// gap event (reason capture_failed) in the bundle built from that
// session, counted in the signed manifest and named in the narrative.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runHook, clearProcessTreeCache, type HookDeps } from '@depose/capture-claude';
import { loadDestructiveRules, type GapPayload } from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { loadAndMergeEvents } from '../src/pipeline.js';
import { DEFAULT_RULES_PATH } from '../src/rules-default.js';

let workDir: string;
let captureDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'depose-cf-bundle-'));
  captureDir = join(workDir, 'captures');
  process.env.DEPOSE_CAPTURE_DIR = captureDir;
  clearProcessTreeCache();
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

const boom = (): never => {
  throw new TypeError('forced');
};

const phases: Array<[string, Partial<HookDeps>]> = [
  ['read-input', { readStdin: async () => boom() }],
  ['parse-input', { readStdin: async () => 'nope' }],
  ['env', { env: () => boom() }],
  ['file-hash', { hashFileArgs: () => boom() }],
  ['process-tree', { walkProcessTree: () => boom() }],
  ['tty', { resolveTty: () => boom() }],
  ['write-record', { writeCaptureRecord: () => boom() }],
];

describe('a hook failure surfaces as one capture_failed gap in the bundle', () => {
  it.each(phases)('%s', async (phase, overrides) => {
    // A session with a single prompt and no tool results, so the only gap
    // the merger can emit is the capture failure. Timestamps are now, so
    // an unattributed failure (read-input, parse-input) still falls
    // inside the session window when unscoped captures are included.
    const now = Date.now();
    const jsonlPath = join(workDir, 'session.jsonl');
    writeFileSync(
      jsonlPath,
      JSON.stringify({ type: 'user', content: 'hi', timestamp: new Date(now - 1000).toISOString(), session_id: 'sess-cf' }) + '\n' +
        JSON.stringify({ type: 'assistant', content: 'ok', timestamp: new Date(now + 60_000).toISOString(), session_id: 'sess-cf' }) + '\n'
    );
    const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: '/', session_id: 'sess-cf' });
    const outcome = await runHook({
      readStdin: async () => input,
      walkProcessTree: () => [],
      resolveTty: () => null,
      ...overrides,
    });
    expect(outcome.ok).toBe(false);

    const merged = loadAndMergeEvents({
      jsonlPath,
      agentId: 'claude-code',
      captureDir,
      includeUnscopedCaptures: phase === 'read-input' || phase === 'parse-input',
    });
    const gaps = merged.events.filter((e) => e.type === 'gap');
    expect(gaps).toHaveLength(1);
    expect((gaps[0]!.payload as GapPayload).reason).toBe('capture_failed');
    expect((gaps[0]!.payload as GapPayload).detail).toContain(`phase "${phase}"`);
    expect(merged.events.filter((e) => e.type === 'capture_failed')).toHaveLength(0);

    const rules = loadDestructiveRules(DEFAULT_RULES_PATH);
    const { manifest, depopPath } = await writeBundle(merged.events, rules, {
      sessionId: 'sess-cf-bundle',
      agentId: 'claude-code',
      version: '0.0.0',
      producedAt: new Date(now + 120_000).toISOString(),
      sessionStartedAt: merged.events[0]!.wallTs,
      sessionEndedAt: merged.events[merged.events.length - 1]!.wallTs,
      rules,
      rulesetBytes: readFileSync(DEFAULT_RULES_PATH),
      outputDir: join(workDir, 'out'),
      mode: 'dev-unsigned',
      captureSourceDir: captureDir,
    });
    expect(manifest.counts.gaps).toBe(1);
    const narrative = readFileSync(join(depopPath, 'narrative.md'), 'utf-8');
    expect(narrative).toContain('capture failed');
    expect(narrative).toContain(`phase "${phase}"`);
    // The failure record itself travels with the bundle as source material.
    expect(manifest.files[`raw/captures/${gaps[0]!.id}.json`]).toBeDefined();
  });
});
