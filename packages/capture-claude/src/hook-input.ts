// packages/capture-claude/src/hook-input.ts
//
// The Claude Code hook contract, narrowed at the boundary. Both halves of
// a tool call arrive on stdin as JSON from a process we do not control, so
// nothing here trusts a field's presence or its type.

import { canonicalJson, sha256String } from '@depose/core';

/**
 * JSON payload received from Claude Code on stdin.
 * PreToolUse sends everything but `tool_response`; PostToolUse adds it.
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
  /** What the tool returned. PostToolUse only. */
  tool_response?: Record<string, unknown>;
}

/**
 * Parse and narrow one hook invocation's stdin.
 *
 * @param json - The raw stdin text.
 * @returns The narrowed input.
 * @throws TypeError when the payload is not a Claude Code hook envelope.
 */
export function parseHookInput(json: string): HookInput {
  const parsed = JSON.parse(json) as Partial<HookInput> | null;
  if (!parsed || typeof parsed !== 'object' || typeof parsed.tool_name !== 'string') {
    throw new TypeError(
      'hook input is missing tool_name; Claude Code sends {tool_name, tool_input, cwd, session_id}'
    );
  }
  const input: HookInput = {
    tool_name: parsed.tool_name,
    tool_input: parsed.tool_input && typeof parsed.tool_input === 'object' ? parsed.tool_input : {},
    cwd: typeof parsed.cwd === 'string' ? parsed.cwd : '',
    session_id: typeof parsed.session_id === 'string' ? parsed.session_id : '',
  };
  if (parsed.tool_response && typeof parsed.tool_response === 'object') {
    input.tool_response = parsed.tool_response;
  }
  return input;
}

/**
 * Correlation key for the two halves of one tool call.
 *
 * Both hooks see the same tool_name and tool_input, so hashing their
 * canonical form gives the effect a way back to its intent when the
 * pending marker is missing.
 *
 * @param toolName - The tool being called.
 * @param toolInput - The tool's arguments.
 * @returns Hex SHA-256 of the canonical JSON of the pair.
 */
export function canonicalInputHash(toolName: string, toolInput: Record<string, unknown>): string {
  return sha256String(canonicalJson({ toolName, toolInput }));
}

/**
 * Build argv from tool input.
 *
 * For Bash: ['bash', '-c', <command>], which destructive-rule matching
 * expands back into simple commands. For Edit/Write: ['<tool>', '<path>'].
 *
 * @param input - The parsed hook payload.
 * @returns The argv the capture record carries.
 */
export function buildArgv(input: HookInput): string[] {
  const toolInput = input.tool_input;

  if (input.tool_name === 'Bash') {
    const cmd = toolInput['command'];
    return typeof cmd === 'string' ? ['bash', '-c', cmd] : ['bash'];
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
 *
 * @param env - The process environment.
 * @returns The same map with undefined values dropped.
 */
export function reduceEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const reduced: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      reduced[key] = value;
    }
  }
  return reduced;
}

/**
 * Pull an exit status out of whatever Claude Code put in tool_response.
 *
 * Bash results carry it under a few spellings depending on version; a tool
 * that does not report one gets null rather than a fabricated zero.
 *
 * @param response - The tool_response object, when present.
 * @returns The exit code, or null.
 */
export function readExitCode(response: Record<string, unknown> | undefined): number | null {
  if (!response) return null;
  for (const key of ['exit_code', 'exitCode', 'returncode', 'status']) {
    const value = response[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return null;
}
