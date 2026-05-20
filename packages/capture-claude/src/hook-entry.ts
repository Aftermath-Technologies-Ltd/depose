// packages/capture-claude/src/hook-entry.ts
//
// Claude Code PreToolUse hook handler.
// Invoked by Claude Code via settings.json:
//   { "hooks": { "PreToolUse": [{ "matcher": "Bash|Edit|Write", "hooks": [{ "type": "command", "command": "depose-hook pretooluse" }] }] } }
//
// Behavior (BUILD_PLAN.md §6, Phase 3):
//   1. Reads the hook's JSON payload from stdin (tool name, tool input, cwd, session_id)
//   2. Resolves env subset against the allowlist
//   3. Walks the parent process tree (best-effort, platform-specific)
//   4. SHA-256s any file paths referenced in tool input
//   5. Writes a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json
//   6. Exits 0 (never blocks the tool call)
//
// The hook is observation-only; never deny or modify.
// Denial is governance; DEPOSE is forensics.

import { hostname } from 'node:os';
import { execSync } from 'node:child_process';
import { generateUlid } from '@depose/core';
import type { ShellCommandPrePayload, ProcessNode } from '@depose/core';
import { filterEnv, parseExtraAllowlist, type FilterEnvOptions } from './env-allowlist.js';
import { hashFileArgs, type FileArg } from './file-hash.js';
import { writeCaptureRecord } from './capture-record.js';

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

// ── Process tree cache (F-17) ──────────────────────────────────────────

/**
 * Per-session cache for walkProcessTree results.
 * Keyed by session ID so different sessions get fresh lookups,
 * but within a session the process tree is stable (same parent chain).
 */
const processTreeCache = new Map<string, ProcessNode[]>();

/**
 * Clear the process tree cache. Useful for testing.
 */
export function clearProcessTreeCache(): void {
  processTreeCache.clear();
}

// ── Main hook handler ────────────────────────────────────────────────

/**
 * Process a PreToolUse hook invocation.
 *
 * Reads JSON from stdin, builds a ShellCommandPrePayload, writes it
 * to the capture directory, and exits 0.
 *
 * This function never throws to the caller; errors are logged to stderr
 * and the process exits 0 regardless (observation-only, never blocks).
 */
export async function handlePreToolUse(
  input: HookInput
): Promise<{ capturePath: string; ulid: string }> {
  const ulid = generateUlid();
  const extraPrefixes = parseExtraAllowlist();

  // Build env subset and hash (with secret redaction)
  const env = reduceEnv(process.env);
  const filterEnvOptions: FilterEnvOptions = { extraPrefixes };
  const { envSubset, envHash } = filterEnv(env, filterEnvOptions);

  // Resolve file args for the tool (skipped for non-destructive tools)
  const fileArgs: FileArg[] = hashFileArgs(input.tool_name, input.tool_input);

  // Build argv from tool input
  const argv = buildArgv(input);

  // Walk parent process tree (best-effort, cached per session)
  const parentProcessTree = getCachedProcessTree(input.session_id);

  // Every Claude tool capture is labelled 'claude-pretooluse' — the
  // hook fires for Bash, Edit, and Write but they all originate
  // from the same pre-tool-use point.
  const source: ShellCommandPrePayload['source'] = 'claude-pretooluse';

  const payload: ShellCommandPrePayload = {
    argv,
    cwd: input.cwd,
    envHash,
    envSubset,
    ttyId: resolveTty(),
    user: process.env.USER || process.env.LOGNAME || '',
    hostname: process.env.HOSTNAME || hostname(),
    parentProcessTree,
    fileArgs: fileArgs.map((fa) => ({
      path: fa.path,
      preSha256: fa.preSha256,
      sizeBytes: fa.sizeBytes,
    })),
    source,
    captureSchemaVersion: 1,
  };

  const capturePath = writeCaptureRecord(ulid, payload);

  return { capturePath, ulid };
}

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Build argv array from tool input.
 * For Bash: tokenizes the command string.
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
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Get the cached process tree for a session, or compute and cache it.
 * F-17: The process tree is stable within a session, so we cache it
 * after the first lookup to avoid redundant `ps` invocations.
 */
function getCachedProcessTree(sessionId: string): ProcessNode[] {
  const cached = processTreeCache.get(sessionId);
  if (cached !== undefined) {
    return cached;
  }
  const tree = walkProcessTree();
  processTreeCache.set(sessionId, tree);
  return tree;
}

/**
 * Walk parent process tree (best-effort, macOS/Linux).
 * Uses a single batched `ps` call for efficiency (F-17).
 */
function walkProcessTree(): ProcessNode[] {
  const tree: ProcessNode[] = [];
  try {
    // Collect PIDs to query (walk up from current process)
    const pids: number[] = [];
    let currentPid = process.pid;
    const seen = new Set<number>();

    // First, collect the PID chain by doing individual lookups
    // (we need ppid to walk up, so we can't batch everything at once)
    for (let i = 0; i < 10; i++) {
      if (seen.has(currentPid)) break;
      seen.add(currentPid);
      pids.push(currentPid);

      const node = getProcessNode(currentPid);
      if (!node || node.ppid === 0 || node.ppid === 1) break;

      // Only continue if ppid wasn't already seen
      if (seen.has(node.ppid)) {
        tree.push(node);
        break;
      }

      tree.push(node);
      currentPid = node.ppid;
    }
  } catch {
    // Best-effort; return whatever we got
  }
  return tree;
}

/**
 * Get a ProcessNode for a given PID using `ps`.
 * Best-effort — returns null on failure.
 */
function getProcessNode(pid: number): ProcessNode | null {
  try {
    const output = execSync(
      `ps -o ppid=,comm= -p ${pid} 2>/dev/null`,
      { encoding: 'utf-8', timeout: 2000 }
    ).trim();
    if (!output) return null;
    const parts = output.split(/\s+/);
    const ppid = parseInt(parts[0] || '0', 10);
    const exe = parts.slice(1).join(' ');
    return { pid, ppid, exe, argv0: exe };
  } catch {
    return null;
  }
}

/**
 * Resolve TTY identifier for the current process.
 * Returns the TTY device path or null.
 */
function resolveTty(): string | null {
  try {
    const tty = execSync('tty 2>/dev/null', { encoding: 'utf-8' }).trim();
    return tty || null;
  } catch {
    return null;
  }
}

// ── CLI entrypoint ───────────────────────────────────────────────────

/**
 * Run the hook as a CLI command.
 * Reads JSON from stdin, processes it, writes capture record.
 * Always exits 0 (never blocks the tool call).
 */
export async function runHookCli(): Promise<void> {
  try {
    // Read hook payload from stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const inputJson = Buffer.concat(chunks).toString('utf-8');
    const input = JSON.parse(inputJson) as HookInput;

    const result = await handlePreToolUse(input);
    // Write result to stderr so Claude Code doesn't interpet it
    process.stderr.write(`depose: capture ${result.ulid}\n`);
  } catch (err) {
    // Never block the tool call. Log to stderr.
    process.stderr.write(
      `depose: capture error (${err instanceof Error ? err.message : String(err)})\n`
    );
  }
  process.exit(0);
}