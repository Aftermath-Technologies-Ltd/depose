// packages/cli/test/hook-intent-effect-bundle.test.ts
//
// The intent and effect pair, end to end through the real hook path.
//
// A session runs five tool calls against files on disk. Four are closed by
// the PostToolUse hook; one is not, because the outcome was lost. Between
// two of them a file is changed by something outside the session, and two
// kernel execve records land in the capture store, one inside the hook's
// process tree and one outside it.
//
// The bundle that comes out has to disclose all three holes as gaps and
// pass depose-verify. The same builder writes the Go verifier's golden
// fixture; regenerate it with:
//
//   DEPOSE_WRITE_GOLDEN=1 npx vitest run packages/cli/test/hook-intent-effect-bundle.test.ts

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, readFileSync, readdirSync, existsSync, cpSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { clearProcessTreeCache } from '@depose/capture-claude';
import {
  setFixedUlidSeed,
  clearFixedUlidSeed,
  type ProcessSpawnPayload,
  type ToolCallEffectPayload,
} from '@depose/core';
import {
  BASE_MS,
  CAPTURE_DIR,
  GOLDEN_DIR,
  MAIN_TF,
  WORK_DIR,
  buildSession,
  gapsOf,
  resetClock,
  verifyBinary,
} from './hook-intent-effect-session.js';

describe('intent and effect through the hook path', () => {
  beforeEach(() => {
    rmSync(WORK_DIR, { recursive: true, force: true });
    mkdirSync(CAPTURE_DIR, { recursive: true });
    process.env.DEPOSE_CAPTURE_DIR = CAPTURE_DIR;
    clearProcessTreeCache();
    setFixedUlidSeed(BASE_MS);
    resetClock();
  });

  afterEach(() => {
    clearFixedUlidSeed();
    delete process.env.DEPOSE_CAPTURE_DIR;
    rmSync(WORK_DIR, { recursive: true, force: true });
  });

  it('binds each pair, reports the lost outcome, the unwitnessed change, and the unwitnessed execve', async () => {
    const { events, depopPath } = await buildSession();

    const effects = events.filter((e) => e.type === 'tool_call_effect');
    expect(effects).toHaveLength(4);
    for (const effect of effects) {
      const payload = effect.payload as ToolCallEffectPayload;
      expect(payload.intentEventId).toBeTruthy();
      expect(payload.intentEventIdSource).toBe('recorded');
      const intent = events.find((e) => e.id === payload.intentEventId);
      expect(intent?.type).toBe('shell_command_pre');
      expect(intent?.correlation?.linkedEffectId).toBe(effect.id);
    }

    // The Edit that renamed the bucket reports the file as modified, with
    // both hashes recorded.
    const edited = (effects[0]!.payload as ToolCallEffectPayload).files.find((f) => f.path === MAIN_TF);
    expect(edited?.change).toBe('modified');
    expect(edited?.preSha256).not.toBe(edited?.postSha256);
    expect(edited?.preSha256).toBeTruthy();
    expect(edited?.postSha256).toBeTruthy();

    expect(gapsOf(events, 'intent_without_effect')).toHaveLength(1);
    expect(gapsOf(events, 'unwitnessed_file_change')).toHaveLength(1);
    expect(gapsOf(events, 'kernel_execve_without_hook')).toHaveLength(1);

    const kernelSpawns = events.filter(
      (e) => e.type === 'process_spawn' && (e.payload as ProcessSpawnPayload).source === 'kernel'
    );
    expect(kernelSpawns).toHaveLength(2);
    const matched = kernelSpawns.filter((e) => (e.payload as ProcessSpawnPayload).matchedIntentEventId !== null);
    expect(matched).toHaveLength(1);
    expect((matched[0]!.payload as ProcessSpawnPayload).argv[0]).toBe('/usr/bin/terraform');

    const narrative = readFileSync(join(depopPath, 'narrative.md'), 'utf-8');
    expect(narrative).toContain('Lost Outcomes');
    expect(narrative).toContain('1 tool call(s) ran with no recorded outcome');
    expect(narrative).toContain('Unwitnessed Commands');
  });

  it('the bundle passes every verifier check, including intent-effect and file-continuity', async () => {
    if (!existsSync(verifyBinary)) return;
    const { depopPath } = await buildSession();
    if (process.env.DEPOSE_WRITE_GOLDEN === '1') {
      rmSync(GOLDEN_DIR, { recursive: true, force: true });
      cpSync(depopPath, GOLDEN_DIR, { recursive: true });
    }
    const stdout = execFileSync(verifyBinary, ['verify', depopPath], { encoding: 'utf-8' });
    expect(stdout).toMatch(/\] intent-effect: PASS/);
    expect(stdout).toMatch(/\] file-continuity: PASS/);
    expect(stdout).toContain('RESULT: PASS');
  });

  it('is byte-identical across two runs, so the checked-in golden stays reproducible', async () => {
    const first = await buildSession();
    const firstEvents = readFileSync(join(first.depopPath, 'events.jsonl'), 'utf-8');
    const firstManifest = readFileSync(join(first.depopPath, 'manifest.json'), 'utf-8');

    rmSync(WORK_DIR, { recursive: true, force: true });
    mkdirSync(CAPTURE_DIR, { recursive: true });
    clearProcessTreeCache();
    setFixedUlidSeed(BASE_MS);
    resetClock();

    const second = await buildSession();
    expect(readFileSync(join(second.depopPath, 'events.jsonl'), 'utf-8')).toBe(firstEvents);
    expect(readFileSync(join(second.depopPath, 'manifest.json'), 'utf-8')).toBe(firstManifest);
  });

  it('leaves no pending marker behind for a closed call', async () => {
    await buildSession();
    const pendingDir = join(CAPTURE_DIR, 'pending');
    const left = existsSync(pendingDir) ? readdirSync(pendingDir) : [];
    // Only the intent whose outcome was lost still has a marker.
    expect(left).toHaveLength(1);
    expect(statSync(join(pendingDir, left[0]!)).isFile()).toBe(true);
  });
});
