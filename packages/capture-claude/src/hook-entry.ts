// packages/capture-claude/src/hook-entry.ts
//
// Claude Code hook handlers, both halves of a tool call.
// Invoked by Claude Code via settings.json:
//   PreToolUse:  { "type": "command", "command": "depose-hook pretooluse" }
//   PostToolUse: { "type": "command", "command": "depose-hook posttooluse" }
//
// The pre half:
//   1. Reads the hook's JSON payload from stdin (tool name, tool input, cwd, session_id)
//   2. Resolves env subset against the allowlist
//   3. Walks the parent process tree (best-effort, cached per session)
//   4. SHA-256s any file paths referenced in tool input
//   5. Writes a ShellCommandPrePayload to $DEPOSE_CAPTURE_DIR/<ulid>.json
//      and leaves a pending marker carrying that ULID
//   6. Exits 0 (never blocks the tool call)
//
// The post half (hook-effect.ts) takes the marker, re-hashes the same
// paths, and writes the effect record that closes the intent.
//
// The hook is observation-only, never deny or modify.
// Denial is governance; DEPOSE is forensics.
//
// A failure in any phase writes a capture_failed record (capture-failed.ts)
// before the hook exits 0, so a lost capture shows up as a gap in the
// bundle instead of a clean timeline.

import { hostname } from 'node:os';
import { generateUlid } from '@depose/core';
import type { ShellCommandPrePayload, ProcessNode } from '@depose/core';
import { filterEnv, parseExtraAllowlist, type FilterEnvOptions } from './env-allowlist.js';
import { hashFileArgs, type FileArg } from './file-hash.js';
import { writeCaptureRecord } from './capture-record.js';
import { writePendingIntent } from './pending.js';
import { handlePostToolUse, type EffectDeps } from './hook-effect.js';
import {
  canonicalInputHash,
  parseHookInput,
  buildArgv,
  reduceEnv,
  type HookInput,
} from './hook-input.js';
import {
  getCachedProcessTree,
  getCachedTty,
  walkProcessTree,
  resolveTty,
} from './hook-process-tree.js';
import {
  writeCaptureFailedRecord,
  type HookPhase,
  type CaptureFailedOutcome,
} from './capture-failed.js';

export { clearProcessTreeCache } from './hook-process-tree.js';
export type { HookInput } from './hook-input.js';

/**
 * The I/O the hook performs, injectable so a test can force a failure in
 * any one phase and prove the capture_failed path through the real code.
 */
export interface HookDeps {
  readStdin: () => Promise<string>;
  env: () => NodeJS.ProcessEnv;
  hashFileArgs: (toolName: string, toolInput: Record<string, unknown>) => FileArg[];
  walkProcessTree: () => ProcessNode[];
  resolveTty: () => string | null;
  writeCaptureRecord: (ulid: string, payload: ShellCommandPrePayload) => string;
  writePendingIntent: (sessionId: string, inputHash: string, intent: {
    ulid: string;
    capturedAt: string;
    files: Array<{ path: string; preSha256: string | null; sizeBytes: number | null }>;
  }) => void;
  /** Capture clock. Injectable so a fixture reproduces byte for byte. */
  now: () => Date;
}

/** Which half of the tool call this invocation is capturing. */
export type HookHalf = 'pre' | 'post';

/** Outcome of one hook run. */
export type HookOutcome =
  | { ok: true; capturePath: string; ulid: string }
  | { ok: false; phase: HookPhase; failure: CaptureFailedOutcome };

const DEFAULT_DEPS: HookDeps = {
  readStdin: async () => {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString('utf-8');
  },
  env: () => process.env,
  hashFileArgs,
  walkProcessTree,
  resolveTty,
  writeCaptureRecord,
  writePendingIntent,
  now: () => new Date(),
};

// ── Pre-execution half ───────────────────────────────────────────────

/**
 * Process a PreToolUse hook invocation from an already-parsed input.
 *
 * Builds a ShellCommandPrePayload, writes it to the capture directory, and
 * leaves the pending marker the post half needs. Throws on failure; runHook
 * is the layer that turns a throw into a capture_failed record.
 *
 * @param input - The parsed hook payload.
 * @param deps - I/O overrides; defaults to the real host.
 * @returns The record path and its ULID.
 */
export async function handlePreToolUse(
  input: HookInput,
  deps: Partial<HookDeps> = {}
): Promise<{ capturePath: string; ulid: string }> {
  const io = { ...DEFAULT_DEPS, ...deps };
  const phase = { current: 'env' as HookPhase };
  return capture(input, io, phase);
}

async function capture(
  input: HookInput,
  io: HookDeps,
  phase: { current: HookPhase }
): Promise<{ capturePath: string; ulid: string }> {
  const ulid = generateUlid();
  const extraPrefixes = parseExtraAllowlist();

  phase.current = 'env';
  const env = reduceEnv(io.env());
  const filterEnvOptions: FilterEnvOptions = { extraPrefixes };
  const { envSubset, envHash } = filterEnv(env, filterEnvOptions);

  phase.current = 'file-hash';
  const fileArgs: FileArg[] = io.hashFileArgs(input.tool_name, input.tool_input);

  const argv = buildArgv(input);

  phase.current = 'process-tree';
  const parentProcessTree = getCachedProcessTree(input.session_id, io.walkProcessTree);

  phase.current = 'tty';
  const ttyId = getCachedTty(input.session_id, io.resolveTty);

  const files = fileArgs.map((fa) => ({
    path: fa.path,
    preSha256: fa.preSha256,
    sizeBytes: fa.sizeBytes,
  }));
  const capturedAt = io.now().toISOString();
  const inputHash = canonicalInputHash(input.tool_name, input.tool_input);

  const payload: ShellCommandPrePayload = {
    argv,
    cwd: input.cwd,
    envHash,
    envSubset,
    ttyId,
    user: env.USER || env.LOGNAME || '',
    hostname: env.HOSTNAME || hostname(),
    parentProcessTree,
    fileArgs: files,
    // Every Claude tool capture is labelled 'claude-pretooluse': the hook
    // fires for Bash, Edit, and Write but they all originate from the same
    // pre-tool-use point.
    source: 'claude-pretooluse',
    captureSchemaVersion: 3,
    inputHash,
    // Recorded here, at capture time, so the normalizer never has to stamp
    // events with the bundle production time.
    capturedAt,
    capturedAtSource: 'recorded',
    // Claude Code's session_id is the value the session JSONL carries as
    // `sessionId`, which is what the capture scope matches against.
    sessionId: input.session_id || null,
  };

  phase.current = 'write-record';
  const capturePath = io.writeCaptureRecord(ulid, payload);

  phase.current = 'pending';
  io.writePendingIntent(input.session_id, inputHash, { ulid, capturedAt, files });
  return { capturePath, ulid };
}

// ── Runner ───────────────────────────────────────────────────────────

/**
 * Run one half of the hook: read stdin, parse, capture. Never throws. On
 * any failure a capture_failed record is written and the outcome says so.
 *
 * @param deps - I/O overrides; defaults to the real host.
 * @param half - Which half of the tool call to capture. Default 'pre'.
 * @param effectDeps - I/O overrides for the post half.
 * @returns What happened, for the CLI wrapper to report on stderr.
 */
export async function runHook(
  deps: Partial<HookDeps> = {},
  half: HookHalf = 'pre',
  effectDeps: Partial<EffectDeps> = {}
): Promise<HookOutcome> {
  const io = { ...DEFAULT_DEPS, ...deps };
  const phase = { current: 'read-input' as HookPhase };
  let sessionId: string | null = null;
  let toolName: string | null = null;
  try {
    const inputJson = await io.readStdin();
    phase.current = 'parse-input';
    const input = parseHookInput(inputJson);
    sessionId = input.session_id || null;
    toolName = input.tool_name;
    const result =
      half === 'post'
        ? handlePostToolUse(input, effectDeps, phase)
        : await capture(input, io, phase);
    return { ok: true, ...result };
  } catch (err) {
    const failure = writeCaptureFailedRecord({
      phase: phase.current,
      error: err,
      sessionId,
      toolName,
      source: half === 'post' ? 'claude-posttooluse' : 'claude-pretooluse',
    });
    return { ok: false, phase: phase.current, failure };
  }
}

// ── CLI entrypoint ───────────────────────────────────────────────────

/**
 * Run the hook as a CLI command and exit 0 whatever happens.
 *
 * @param half - Which half of the tool call this invocation captures.
 */
export async function runHookCli(half: HookHalf = 'pre'): Promise<void> {
  const outcome = await runHook({}, half);
  if (outcome.ok) {
    process.stderr.write(`depose: capture ${outcome.ulid}\n`);
  } else {
    const where = outcome.failure.written === 'none' ? 'unrecorded' : `recorded as ${outcome.failure.ulid}`;
    process.stderr.write(`depose: capture failed in ${outcome.phase} (${where})\n`);
  }
  process.exit(0);
}
