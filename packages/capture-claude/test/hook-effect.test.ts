// packages/capture-claude/test/hook-effect.test.ts
//
// The PostToolUse half: taking the marker the pre half left, classifying
// what happened to each declared path, and leaving a capture_failed record
// when the post hook itself throws.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { CaptureFailedPayload, ToolCallEffectPayload } from '@depose/core';
import { handlePostToolUse, mergeFileStates } from '../src/hook-effect.js';
import { canonicalInputHash } from '../src/hook-input.js';
import { writePendingIntent, takePendingIntent, getPendingDir } from '../src/pending.js';
import { runHook, clearProcessTreeCache } from '../src/hook-entry.js';

let captureDir: string;

beforeEach(() => {
  captureDir = mkdtempSync(join(tmpdir(), 'depose-effect-'));
  process.env.DEPOSE_CAPTURE_DIR = captureDir;
  clearProcessTreeCache();
});

afterEach(() => {
  delete process.env.DEPOSE_CAPTURE_DIR;
  rmSync(captureDir, { recursive: true, force: true });
});

function storedRecords(): Array<Record<string, unknown>> {
  return readdirSync(captureDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => JSON.parse(readFileSync(join(captureDir, f), 'utf-8')) as Record<string, unknown>);
}

describe('pending intent markers', () => {
  it('hands the intent id from the pre half to the post half exactly once', () => {
    const hash = canonicalInputHash('Bash', { command: 'ls' });
    writePendingIntent('sess-1', hash, { ulid: '01INTENT', capturedAt: '2025-05-18T15:30:00.000Z', files: [] });

    expect(takePendingIntent('sess-1', hash)?.ulid).toBe('01INTENT');
    expect(takePendingIntent('sess-1', hash)).toBeNull();
  });

  it('keeps sessions apart and survives a session id with path characters in it', () => {
    const hash = canonicalInputHash('Bash', { command: 'ls' });
    writePendingIntent('../../escape', hash, { ulid: '01ESCAPE', capturedAt: '2025-05-18T15:30:00.000Z', files: [] });

    expect(readdirSync(getPendingDir()).every((f) => !f.includes('/'))).toBe(true);
    expect(takePendingIntent('sess-other', hash)).toBeNull();
    expect(takePendingIntent('../../escape', hash)?.ulid).toBe('01ESCAPE');
  });
});

describe('mergeFileStates', () => {
  const pending = (files: Array<{ path: string; preSha256: string | null }>) => ({
    ulid: '01INTENT',
    capturedAt: '2025-05-18T15:30:00.000Z',
    files: files.map((f) => ({ ...f, sizeBytes: f.preSha256 ? 4 : null })),
  });

  it('classifies a file that gained content as created', () => {
    const [entry] = mergeFileStates(pending([{ path: '/tmp/a', preSha256: null }]), [
      { path: '/tmp/a', preSha256: 'bb', sizeBytes: 4 },
    ]);
    expect(entry).toMatchObject({ change: 'created', preSha256: null, postSha256: 'bb' });
  });

  it('classifies a file that lost content as deleted', () => {
    const [entry] = mergeFileStates(pending([{ path: '/tmp/a', preSha256: 'aa' }]), [
      { path: '/tmp/a', preSha256: null, sizeBytes: null },
    ]);
    expect(entry).toMatchObject({ change: 'deleted', postSha256: null });
  });

  it('classifies an identical hash as unchanged and a different one as modified', () => {
    const same = mergeFileStates(pending([{ path: '/tmp/a', preSha256: 'aa' }]), [
      { path: '/tmp/a', preSha256: 'aa', sizeBytes: 4 },
    ]);
    const different = mergeFileStates(pending([{ path: '/tmp/a', preSha256: 'aa' }]), [
      { path: '/tmp/a', preSha256: 'bb', sizeBytes: 4 },
    ]);
    expect(same[0]!.change).toBe('unchanged');
    expect(different[0]!.change).toBe('modified');
  });

  it('will not claim creation for a path the intent never recorded', () => {
    const [entry] = mergeFileStates(null, [{ path: '/tmp/a', preSha256: 'bb', sizeBytes: 4 }]);
    expect(entry).toMatchObject({ change: 'modified', preSha256: null });
  });

  it('reports paths in a stable order whichever half named them', () => {
    const entries = mergeFileStates(pending([{ path: '/tmp/z', preSha256: 'aa' }]), [
      { path: '/tmp/a', preSha256: 'bb', sizeBytes: 4 },
    ]);
    expect(entries.map((e) => e.path)).toEqual(['/tmp/a', '/tmp/z']);
  });
});

describe('handlePostToolUse', () => {
  const input = {
    tool_name: 'Bash',
    tool_input: { command: 'terraform destroy' },
    cwd: '/srv',
    session_id: 'sess-post',
    tool_response: { exit_code: 2, stdout: 'error' },
  };

  it('records the exit status, the duration, and the intent it closed', () => {
    const hash = canonicalInputHash(input.tool_name, input.tool_input);
    writePendingIntent(input.session_id, hash, {
      ulid: '01INTENT',
      capturedAt: '2025-05-18T15:30:00.000Z',
      files: [],
    });

    handlePostToolUse(input, {
      hashFileArgs: () => [],
      now: () => new Date('2025-05-18T15:30:04.000Z'),
      monoNs: () => 42n,
    });

    const effect = storedRecords().find((r) => r['kind'] === 'effect') as unknown as ToolCallEffectPayload;
    expect(effect.exitCode).toBe(2);
    expect(effect.durationMs).toBe(4000);
    expect(effect.intentEventId).toBe('01INTENT');
    expect(effect.intentEventIdSource).toBe('recorded');
    expect(effect.inputHash).toBe(hash);
    expect(effect.monoNs).toBe('42');
  });

  it('says the intent is unknown rather than inventing one when the marker is gone', () => {
    handlePostToolUse(input, { hashFileArgs: () => [], monoNs: () => 1n });

    const effect = storedRecords().find((r) => r['kind'] === 'effect') as unknown as ToolCallEffectPayload;
    expect(effect.intentEventId).toBeNull();
    expect(effect.intentEventIdSource).toBe('none');
    expect(effect.durationMs).toBeNull();
  });

  it('reports no exit status for a tool that does not have one', () => {
    handlePostToolUse(
      { ...input, tool_response: { success: true } },
      { hashFileArgs: () => [], monoNs: () => 1n }
    );

    const effect = storedRecords().find((r) => r['kind'] === 'effect') as unknown as ToolCallEffectPayload;
    expect(effect.exitCode).toBeNull();
  });
});

describe('a failing post hook still leaves evidence and exits cleanly', () => {
  it('writes a capture_failed record tagged as the post half', async () => {
    const boom = (): never => {
      throw new RangeError('post hook exploded');
    };
    const outcome = await runHook(
      {
        readStdin: async () =>
          JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: '/', session_id: 'sess-post' }),
      },
      'post',
      { hashFileArgs: boom }
    );

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.phase).toBe('file-hash');

    const failure = storedRecords().find((r) => r['kind'] === 'capture_failed') as unknown as CaptureFailedPayload;
    expect(failure.source).toBe('claude-posttooluse');
    expect(failure.errorClass).toBe('RangeError');
    expect(failure.sessionId).toBe('sess-post');
    expect(failure.toolName).toBe('Bash');
  });
});

describe('the pre half leaves a marker the post half can find', () => {
  it('round-trips one tool call through both halves', async () => {
    const target = join(captureDir, 'target.txt');
    writeFileSync(target, 'before');
    const toolInput = { file_path: target, old_string: 'before', new_string: 'after' };
    const stdin = JSON.stringify({
      tool_name: 'Write',
      tool_input: toolInput,
      cwd: captureDir,
      session_id: 'sess-round',
    });

    const pre = await runHook({
      readStdin: async () => stdin,
      walkProcessTree: () => [],
      resolveTty: () => null,
    });
    expect(pre.ok).toBe(true);
    expect(existsSync(getPendingDir())).toBe(true);

    writeFileSync(target, 'after');
    const post = await runHook({ readStdin: async () => stdin }, 'post');
    expect(post.ok).toBe(true);

    const effect = storedRecords().find((r) => r['kind'] === 'effect') as unknown as ToolCallEffectPayload;
    expect(effect.intentEventId).toBe(pre.ok ? pre.ulid : null);
    const file = effect.files.find((f) => f.path === target);
    expect(file?.change).toBe('modified');
    expect(file?.preSha256).not.toBe(file?.postSha256);
    expect(readdirSync(getPendingDir())).toHaveLength(0);
  });
});
