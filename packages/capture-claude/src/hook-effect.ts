// packages/capture-claude/src/hook-effect.ts
//
// Claude Code PostToolUse hook handler: the effect half of a tool call.
//
// It hashes the same paths the intent named, now that the tool has
// returned, and records the intent's event id so the pair is bound inside
// signed payload data rather than in an index alongside it.
//
// What it cannot see: a file the command created that the tool input never
// named. The paths come from tool_input, so `depose` reports outcomes for
// the files the call declared and the kernel collector is what covers the
// rest. This limit is stated in docs/bundle-format.md#intent-and-effect
// rather than papered over with a directory scan that would be wrong in a
// different way.

import { generateUlid } from '@depose/core';
import type { ToolCallEffectPayload, FileEffect } from '@depose/core';
import { hashFileArgs, type FileArg } from './file-hash.js';
import { writeEffectRecord } from './capture-record.js';
import { takePendingIntent, type PendingIntent } from './pending.js';
import { canonicalInputHash, readExitCode, type HookInput } from './hook-input.js';
import type { HookPhase } from './capture-failed.js';

/** The I/O the post hook performs, injectable for tests. */
export interface EffectDeps {
  hashFileArgs: (toolName: string, toolInput: Record<string, unknown>) => FileArg[];
  takePendingIntent: (sessionId: string, inputHash: string) => PendingIntent | null;
  writeEffectRecord: (ulid: string, payload: ToolCallEffectPayload) => string;
  now: () => Date;
  /** Monotonic clock. Injectable so a fixture reproduces byte for byte. */
  monoNs: () => bigint;
}

const DEFAULT_EFFECT_DEPS: EffectDeps = {
  hashFileArgs,
  takePendingIntent,
  writeEffectRecord,
  now: () => new Date(),
  monoNs: () => process.hrtime.bigint(),
};

/**
 * Process a PostToolUse hook invocation.
 *
 * @param input - The parsed hook payload, including tool_response.
 * @param deps - I/O overrides; defaults to the real host.
 * @param phase - Mutable phase marker so a throw says where it happened.
 * @returns The record path and its ULID.
 * @throws Whatever the injected I/O throws; runHook records it as capture_failed.
 */
export function handlePostToolUse(
  input: HookInput,
  deps: Partial<EffectDeps> = {},
  phase: { current: HookPhase } = { current: 'pending' }
): { capturePath: string; ulid: string } {
  const io = { ...DEFAULT_EFFECT_DEPS, ...deps };
  const ulid = generateUlid();
  const inputHash = canonicalInputHash(input.tool_name, input.tool_input);

  phase.current = 'pending';
  const pending = io.takePendingIntent(input.session_id, inputHash);

  phase.current = 'file-hash';
  const post = io.hashFileArgs(input.tool_name, input.tool_input);

  const capturedAt = io.now();
  const payload: ToolCallEffectPayload = {
    kind: 'effect',
    toolName: input.tool_name,
    cwd: input.cwd,
    exitCode: readExitCode(input.tool_response),
    durationMs: pending ? durationMs(pending.capturedAt, capturedAt) : null,
    intentEventId: pending ? pending.ulid : null,
    intentEventIdSource: pending ? 'recorded' : 'none',
    inputHash,
    files: mergeFileStates(pending, post),
    source: 'claude-posttooluse',
    captureSchemaVersion: 3,
    capturedAt: capturedAt.toISOString(),
    capturedAtSource: 'recorded',
    monoNs: io.monoNs().toString(),
    sessionId: input.session_id || null,
  };

  phase.current = 'write-record';
  return { capturePath: io.writeEffectRecord(ulid, payload), ulid };
}

/**
 * Pair the intent's pre-state hashes with the post-state ones and classify
 * what happened to each path.
 *
 * @param pending - The intent marker, or null when it was lost.
 * @param post - Hashes taken after the tool returned.
 * @returns One entry per path either half named, in path order.
 */
export function mergeFileStates(pending: PendingIntent | null, post: FileArg[]): FileEffect[] {
  const pre = new Map((pending?.files ?? []).map((f) => [f.path, f]));
  const after = new Map(post.map((f) => [f.path, f]));
  const paths = Array.from(new Set([...pre.keys(), ...after.keys()])).sort();

  return paths.map((path) => {
    const before = pre.get(path);
    const now = after.get(path);
    const preSha256 = before ? before.preSha256 : null;
    const postSha256 = now ? now.preSha256 : null;
    return {
      path,
      preSha256,
      postSha256,
      sizeBytes: now ? now.sizeBytes : null,
      change: classifyChange(preSha256, postSha256, before !== undefined),
    };
  });
}

/**
 * A path with no pre-state recorded is reported as `modified` rather than
 * `created`: without the intent's hash there is no evidence the file was
 * absent, and claiming creation would be a guess presented as a finding.
 */
function classifyChange(
  preSha256: string | null,
  postSha256: string | null,
  hadPreState: boolean
): FileEffect['change'] {
  if (preSha256 === null && postSha256 !== null) return hadPreState ? 'created' : 'modified';
  if (preSha256 !== null && postSha256 === null) return 'deleted';
  if (preSha256 === postSha256) return 'unchanged';
  return 'modified';
}

function durationMs(startIso: string, end: Date): number | null {
  const start = Date.parse(startIso);
  if (Number.isNaN(start)) return null;
  return Math.max(0, end.getTime() - start);
}
