// packages/capture-claude/src/hook-entry.ts
//
// Claude Code PreToolUse hook handler.
// Invoked by Claude Code via settings.json:
//   { "hooks": { "PreToolUse": [{ "matcher": "Bash|Edit|Write", "hooks": [{ "type": "command", "command": "depose-hook pretooluse" }] }] } }
//
// Behavior:
//   1. Reads the hook's JSON payload from stdin (tool name, tool input, cwd, session_id)
//   2. Resolves env subset against the allowlist
//   3. Walks the parent process tree (best-effort, cached per session)
//   4. SHA-256s any file paths referenced in tool input
//   5. Writes a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json
//   6. Exits 0 (never blocks the tool call)
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

// ── Hook input schema ────────────────────────────────────────────────

/**
 * JSON payload received from Claude Code on stdin.
 * Matches Claude Code's PreToolUse hook contract.
 */
export interface HookInput {
  /** Tool name (e.g., "Bash", "Edit", "Write") */
  tool_name: string;
  /** Tool input (arguments object) */
  tool_input: Record<string, unknown>;
  /** Current working directory */
  cwd: string;
  /** Session ID */
  session_id: string;
}

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
}

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
};

// ── Main hook handler ────────────────────────────────────────────────

/**
 * Process a PreToolUse hook invocation from an already-parsed input.
 *
 * Builds a ShellCommandPrePayload and writes it to the capture directory.
 * Throws on failure; runHook is the layer that turns a throw into a
 * capture_failed record.
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

  const payload: ShellCommandPrePayload = {
    argv,
    cwd: input.cwd,
    envHash,
    envSubset,
    ttyId,
    user: env.USER || env.LOGNAME || '',
    hostname: env.HOSTNAME || hostname(),
    parentProcessTree,
    fileArgs: fileArgs.map((fa) => ({
      path: fa.path,
      preSha256: fa.preSha256,
      sizeBytes: fa.sizeBytes,
    })),
    // Every Claude tool capture is labelled 'claude-pretooluse': the hook
    // fires for Bash, Edit, and Write but they all originate from the same
    // pre-tool-use point.
    source: 'claude-pretooluse',
    captureSchemaVersion: 2,
    // Recorded here, at capture time, so the normalizer never has to stamp
    // events with the bundle production time.
    capturedAt: new Date().toISOString(),
    capturedAtSource: 'recorded',
    // Claude Code's session_id is the value the session JSONL carries as
    // `sessionId`, which is what the capture scope matches against.
    sessionId: input.session_id || null,
  };

  phase.current = 'write-record';
  const capturePath = io.writeCaptureRecord(ulid, payload);
  return { capturePath, ulid };
}

/**
 * Run the whole hook: read stdin, parse, capture. Never throws. On any
 * failure a capture_failed record is written and the outcome says so.
 *
 * @param deps - I/O overrides; defaults to the real host.
 * @returns What happened, for the CLI wrapper to report on stderr.
 */
export async function runHook(deps: Partial<HookDeps> = {}): Promise<HookOutcome> {
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
    const result = await capture(input, io, phase);
    return { ok: true, ...result };
  } catch (err) {
    const failure = writeCaptureFailedRecord({ phase: phase.current, error: err, sessionId, toolName });
    return { ok: false, phase: phase.current, failure };
  }
}

function parseHookInput(json: string): HookInput {
  const parsed = JSON.parse(json) as Partial<HookInput> | null;
  if (!parsed || typeof parsed !== 'object' || typeof parsed.tool_name !== 'string') {
    throw new TypeError('hook input is missing tool_name; Claude Code sends {tool_name, tool_input, cwd, session_id}');
  }
  return {
    tool_name: parsed.tool_name,
    tool_input: parsed.tool_input && typeof parsed.tool_input === 'object' ? parsed.tool_input : {},
    cwd: typeof parsed.cwd === 'string' ? parsed.cwd : '',
    session_id: typeof parsed.session_id === 'string' ? parsed.session_id : '',
  };
}

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Build argv array from tool input.
 * For Bash: ['bash', '-c', <command>], which destructive-rule matching
 * expands back into simple commands.
 * For Edit/Write: ["<tool>", "<file_path>"].
 */
function buildArgv(input: HookInput): string[] {
  const toolInput = input.tool_input;

  if (input.tool_name === 'Bash') {
    const cmd = toolInput['command'];
    if (typeof cmd === 'string') {
      return ['bash', '-c', cmd];
    }
    return ['bash'];
  }

  if (input.tool_name === 'Edit' || input.tool_name === 'Write') {
    const fp = toolInput['file_path'];
    return [input.tool_name.toLowerCase(), typeof fp === 'string' ? fp : ''];
  }

  if (input.tool_name === 'MultiEdit') {
    return ['multiedit'];
  }

  return [input.tool_name.toLowerCase()];
}

/**
 * Reduce process.env to Record<string, string> for filterEnv.
 */
function reduceEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const reduced: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      reduced[key] = value;
    }
  }
  return reduced;
}

// ── CLI entrypoint ───────────────────────────────────────────────────

/**
 * Run the hook as a CLI command and exit 0 whatever happens.
 */
export async function runHookCli(): Promise<void> {
  const outcome = await runHook();
  if (outcome.ok) {
    process.stderr.write(`depose: capture ${outcome.ulid}\n`);
  } else {
    const where = outcome.failure.written === 'none' ? 'unrecorded' : `recorded as ${outcome.failure.ulid}`;
    process.stderr.write(`depose: capture failed in ${outcome.phase} (${where})\n`);
  }
  process.exit(0);
}
