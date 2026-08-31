// packages/core/src/normalize/merge-correlate.ts
//
// Correlating a tool_result or tool_call_intent to the shell_command_pre
// capture that preceded it, on (cwd, argv, wallTs ± matchWindowSeconds).
//
// Candidates arrive time-sorted so a lookup binary-searches into the window
// band. The previous version rescanned every capture per call and rebuilt
// the candidate array each time, which made merging quadratic in
// (events x captures): 1,246ms for 800 events against a 9,391-record store,
// versus 28ms now.

import type {
  Event,
  ToolResultPayload,
  ToolCallIntentPayload,
  ShellCommandPrePayload,
} from '../events/schema.js';
import { lowerBound } from './merge-support.js';

// ── Correlation helper ───────────────────────────────────────────────

/**
 * Find a shell_command_pre event that matches a given event
 * based on (cwd, argv overlap, wallTs proximity).
 *
 * F-06: When correlating a tool_result, first find the parent
 * tool_call_intent by matching tool_use_id, then use the
 * tool_call_intent's payload data for scoring. Drop the
 * cwd/argv scoring on tool_result itself.
 * Score is: (argv-overlap-from-tool-call-intent × 5) + time-proximity.
 *
 * Returns the best match or null.
 */
export function findMatchingShellPre(
  target: Event,
  shellPreByTime: Event[],
  toolUseIdToIntentMap: Map<string, Event>,
  matchWindowSeconds: number
): Event | null {
  let targetCwd = '';
  let targetArgv: string[] = [];

  if (target.type === 'tool_result') {
    // F-06: For tool_result, find the parent tool_call_intent
    // to get cwd/argv scoring data. tool_result payloads don't
    // have cwd/argv, so we look up the intent by tool_use_id.
    const resultPayload = target.payload as ToolResultPayload;
    const toolUseId = resultPayload.toolUseId;
    if (toolUseId) {
      const parentIntent = toolUseIdToIntentMap.get(toolUseId);
      if (parentIntent) {
        // Use the tool_call_intent's data for scoring
        const intentPayload = parentIntent.payload as ToolCallIntentPayload;
        targetArgv = extractArgvFromToolInput(intentPayload.toolInput);
        targetCwd = extractCwdFromToolInput(intentPayload.toolInput);
      }
    }
    // If no parent intent found, fall through with empty scoring data.
    // Time-proximity will still contribute.
  } else if (target.type === 'tool_call_intent') {
    // tool_call_intent has toolInput with command/argv
    const intentPayload = target.payload as ToolCallIntentPayload;
    targetArgv = extractArgvFromToolInput(intentPayload.toolInput);
    targetCwd = extractCwdFromToolInput(intentPayload.toolInput);
  } else {
    // Other event types: try to read cwd/argv from payload
    const targetPayload = target.payload as unknown as Record<string, unknown>;
    targetCwd = (targetPayload.cwd as string) || '';
    targetArgv = (targetPayload.argv as string[]) || [];
  }

  const targetTs = new Date(target.wallTs).getTime();

  let bestMatch: Event | null = null;
  let bestScore = -1;

  // Only candidates inside the window can match, and the window is a hard
  // reject below, so walk the sorted band rather than the whole store.
  const windowMs = matchWindowSeconds * 1000;
  const from = lowerBound(shellPreByTime, targetTs - windowMs);

  for (let i = from; i < shellPreByTime.length; i++) {
    const shellPre = shellPreByTime[i]!;
    const prePayload = shellPre.payload as ShellCommandPrePayload;
    const preCwd = prePayload.cwd;
    const preArgv = prePayload.argv;
    const preTs = Date.parse(shellPre.wallTs);

    // Sorted ascending, so the first candidate past the window ends the scan.
    if (preTs > targetTs + windowMs) break;

    const timeDiff = Math.abs(targetTs - preTs);

    // Calculate match score
    let score = 0;

    // CWD match (strong signal), only when we have targetCwd
    if (targetCwd && (preCwd === targetCwd || isPathRelated(preCwd, targetCwd))) {
      score += 10;
    }

    // Argv overlap (at least the first N tokens should match)
    const overlap = countArgvOverlap(preArgv, targetArgv);
    score += overlap * 5;

    // Prefer closer timestamps
    score += Math.max(0, 10 - Math.floor(timeDiff / 1000));

    if (score > bestScore) {
      bestScore = score;
      bestMatch = shellPre;
    }
  }

  // Only return a match if we have a reasonable score
  return bestScore >= 5 ? bestMatch : null;
}

// ── Argv extraction helpers ──────────────────────────────────────────

/**
 * Extract an argv-like array from a toolInput object.
 * For Bash-like tools, toolInput.command is a string that we tokenize.
 * Other tools may have different shapes; we do our best.
 */
function extractArgvFromToolInput(toolInput: unknown): string[] {
  if (!toolInput || typeof toolInput !== 'object') return [];
  const input = toolInput as Record<string, unknown>;

  // If it has a command field (Bash tool), tokenize it
  if (typeof input.command === 'string' && input.command.trim()) {
    return tokenize(input.command);
  }

  // If it has an argv field array
  if (Array.isArray(input.argv)) {
    return input.argv as string[];
  }

  return [];
}

/**
 * Extract cwd from a toolInput object.
 */
function extractCwdFromToolInput(toolInput: unknown): string {
  if (!toolInput || typeof toolInput !== 'object') return '';
  const input = toolInput as Record<string, unknown>;

  if (typeof input.cwd === 'string') return input.cwd;
  return '';
}

/**
 * Simple tokenization of a shell command string into argv-like tokens.
 * Splits on whitespace, respecting basic quoting.
 */
function tokenize(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;

  for (const ch of command) {
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === ' ' && !inSingle && !inDouble) {
      if (current) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }
  if (current) {
    tokens.push(current);
  }
  return tokens;
}

/**
 * Check if two paths are related (one is a parent/child of the other,
 * or they share a common prefix).
 */
function isPathRelated(a: string, b: string): boolean {
  const aNorm = a.replace(/\/+$/, '').toLowerCase();
  const bNorm = b.replace(/\/+$/, '').toLowerCase();
  return (
    aNorm.startsWith(bNorm) ||
    bNorm.startsWith(aNorm) ||
    aNorm === bNorm
  );
}

/**
 * Count overlapping tokens between two argv arrays.
 * Checks the first N tokens (up to 5) for equality.
 */
function countArgvOverlap(a: string[], b: string[]): number {
  const max = Math.min(a.length, b.length, 5);
  let count = 0;
  for (let i = 0; i < max; i++) {
    if (a[i]?.toLowerCase() === b[i]?.toLowerCase()) {
      count++;
    }
  }
  return count;
}

