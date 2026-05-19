// packages/core/src/normalize/merge.ts
//
// Merge events from multiple sources (Claude Code JSONL, shell history,
// git reflog) into a single ordered Event[] with gap detection.
//
// This is the core of the normalization layer. It:
//   1. Takes events from multiple sources
//   2. Sorts them by (wallTs, monoNs)
//   3. Detects gaps (unmatched events)
//   4. Links related events (tool_call_intent → shell_command_pre → tool_result)
//   5. Emits gap events for unmatched events
//
// See BUILD_PLAN.md §4.1 for the Event schema.
// See BUILD_PLAN.md §5 (Phase 1) for scope.

import type {
  AgentId,
  Event,
  ToolResultPayload,
  ToolCallIntentPayload,
  ShellCommandPrePayload,
  GapPayload,
} from '../events/schema.js';
import { ulidFromTime } from '../events/ids.js';
import { sha256 } from '../events/canonical-json.js';

// ── Merge options ────────────────────────────────────────────────────

/**
 * Options for the merge operation.
 */
export interface MergeOptions {
  /** Session ID (ULID) — all events must belong to the same session */
  sessionId: string;
  /** Agent ID (default: 'claude-code') */
  agentId?: AgentId;
  /**
   * Time window (in seconds) for matching tool results to shell command
   * pre-captures. Default: 5 seconds (BUILD_PLAN.md §6, Phase 3).
   */
  matchWindowSeconds?: number;
}

/**
 * Result of a merge operation.
 */
export interface MergeResult {
  /** Merged and sorted events (ordered by wallTs, monoNs) */
  events: Event[];
  /** Warnings about merge issues (gaps, conflicts, etc.) */
  warnings: string[];
  /** Count of gap events emitted */
  gapCount: number;
  /** Count of events that were linked (tool_call_intent → shell_command_pre) */
  linkedCount: number;
}

// ── Main merge function ──────────────────────────────────────────────

/**
 * Merge events from multiple sources into a single ordered timeline.
 *
 * Sources:
 *   - claudeCodeEvents: Events from normalizeClaudeCodeJsonl()
 *   - shellHistoryEvents: Events from shell history (shell_command_pre/post)
 *   - reflogEvents: Events from git reflog (process_spawn + gap)
 *
 * The merge:
 *   1. Concatenates all events
 *   2. Sorts by (wallTs, monoNs)
 *   3. Links tool_call_intent events to shell_command_pre events
 *      based on (cwd, argv, wallTs ± matchWindowSeconds)
 *   4. Emits gap events for unmatched tool results
 *   5. Removes duplicate events (same id)
 */
export function mergeEvents(
  sources: {
    claudeCodeEvents?: Event[];
    shellHistoryEvents?: Event[];
    reflogEvents?: Event[];
    captureEvents?: Event[];
  },
  options: MergeOptions
): MergeResult {
  const {
    sessionId,
    agentId = 'claude-code',
    matchWindowSeconds = 5,
  } = options;

  const allEvents: Event[] = [];
  const warnings: string[] = [];
  let gapCount = 0;
  let linkedCount = 0;

  // Collect events from all sources
  const claudeEvents = sources.claudeCodeEvents || [];
  const shellEvents = sources.shellHistoryEvents || [];
  const reflogEvents = sources.reflogEvents || [];
  const captureEvents = sources.captureEvents || [];

  // Deduplicate by id
  const seenIds = new Set<string>();
  const deduped: Event[] = [];
  for (const event of [...claudeEvents, ...shellEvents, ...reflogEvents, ...captureEvents]) {
    if (seenIds.has(event.id)) {
      warnings.push(`Duplicate event id ${event.id}, skipping`);
      continue;
    }
    seenIds.add(event.id);
    // Ensure session ID is correct
    const normalized = { ...event, sessionId } as Event;
    deduped.push(normalized);
  }

  // Sort by (wallTs, monoNs)
  deduped.sort((a, b) => {
    const tsCmp = a.wallTs.localeCompare(b.wallTs);
    if (tsCmp !== 0) return tsCmp;
    return a.monoNs - b.monoNs;
  });

  // Build lookup maps for correlation
  const toolCallIntentMap = new Map<string, Event>();
  const shellPreMap = new Map<string, Event>();
  const toolResultMap = new Map<string, Event>();
  const shellPostMap = new Map<string, Event>();
  const unmatchedToolResults: Event[] = [];

  for (const event of deduped) {
    switch (event.type) {
      case 'tool_call_intent':
        toolCallIntentMap.set(event.id, event);
        break;
      case 'shell_command_pre':
        shellPreMap.set(event.id, event);
        break;
      case 'tool_result':
        toolResultMap.set(event.id, event);
        unmatchedToolResults.push(event);
        break;
      case 'shell_command_post':
        shellPostMap.set(event.id, event);
        break;
    }
  }

  // Correlate: link tool_call_intent to shell_command_pre
  // and tool_result to shell_command_pre
  // Based on (cwd, argv, wallTs ± matchWindowSeconds)
  const matchedShellPre = new Set<string>();
  const matchedToolResult = new Set<string>();

  for (const toolResult of unmatchedToolResults) {
    const matched = findMatchingShellPre(toolResult, shellPreMap, matchWindowSeconds);
    if (matched) {
      const payload = toolResult.payload as ToolResultPayload;
      (toolResult as Event & { payload: ToolResultPayload }).payload = {
        ...payload,
        linkedShellCommandPreId: matched.id,
      };
      matchedToolResult.add(toolResult.id);
      matchedShellPre.add(matched.id);
      linkedCount++;
    }
  }

  // Link tool_call_intent to shell_command_pre (if not already matched)
  Array.from(toolCallIntentMap.entries()).forEach(([, intentEvent]) => {
    const matched = findMatchingShellPre(intentEvent, shellPreMap, matchWindowSeconds);
    if (matched && !matchedShellPre.has(matched.id)) {
      const payload = intentEvent.payload as ToolCallIntentPayload;
      (intentEvent as Event & { payload: ToolCallIntentPayload }).payload = {
        ...payload,
        linkedShellCommandPreId: matched.id,
      };
      matchedShellPre.add(matched.id);
      linkedCount++;
    }
  });

  // Emit gap events for unmatched tool results
  for (const toolResult of unmatchedToolResults) {
    if (!matchedToolResult.has(toolResult.id)) {
      const gapPayload: GapPayload = {
        reason: 'tool_result_without_pre_capture' as const,
        affectedEventIds: [toolResult.id],
        detail: `Tool result for "${(toolResult.payload as ToolResultPayload).toolName}" at ${toolResult.wallTs} has no matching shell_command_pre capture. This could be a command run outside the shim/hook, or a tool that doesn't invoke a shell command.`,
      };
      const gap = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: toolResult.id,
        monoNs: toolResult.monoNs + 1,
        wallTs: toolResult.wallTs,
        payload: gapPayload,
      });
      allEvents.push(gap);
      gapCount++;
    }
  }

  // Emit gap events for unmatched shell_command_pre (pre_capture without tool_result)
  Array.from(shellPreMap.entries()).forEach(([, shellPre]) => {
    if (!matchedShellPre.has(shellPre.id)) {
      const gapPayload: GapPayload = {
        reason: 'pre_capture_without_tool_result' as const,
        affectedEventIds: [shellPre.id],
        detail: `Shell command pre-capture at ${shellPre.wallTs} (${(shellPre.payload as ShellCommandPrePayload).argv.join(' ')}) has no matching tool_result. The command may have been run outside the agent session.`,
      };
      const gap = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: shellPre.id,
        monoNs: shellPre.monoNs + 1,
        wallTs: shellPre.wallTs,
        payload: gapPayload,
      });
      allEvents.push(gap);
      gapCount++;
    }
  });

  // Combine: original events + gap events, re-sorted
  allEvents.push(...deduped);
  allEvents.sort((a, b) => {
    const tsCmp = a.wallTs.localeCompare(b.wallTs);
    if (tsCmp !== 0) return tsCmp;
    return a.monoNs - b.monoNs;
  });

  return {
    events: allEvents,
    warnings,
    gapCount,
    linkedCount,
  };
}

// ── Correlation helper ───────────────────────────────────────────────

/**
 * Find a shell_command_pre event that matches a given event
 * based on (cwd, argv overlap, wallTs proximity).
 *
 * Returns the best match or null.
 */
function findMatchingShellPre(
  target: Event,
  shellPreMap: Map<string, Event>,
  matchWindowSeconds: number
): Event | null {
  const targetPayload = target.payload as unknown as Record<string, unknown>;
  const targetCwd = (targetPayload.cwd as string) || '';
  const targetArgv = (targetPayload.argv as string[]) || [];
  const targetTs = new Date(target.wallTs).getTime();

  let bestMatch: Event | null = null;
  let bestScore = -1;

  for (const shellPre of Array.from(shellPreMap.values())) {
    const prePayload = shellPre.payload as ShellCommandPrePayload;
    const preCwd = prePayload.cwd;
    const preArgv = prePayload.argv;
    const preTs = new Date(shellPre.wallTs).getTime();

    // Check time window
    const timeDiff = Math.abs(targetTs - preTs);
    if (timeDiff > matchWindowSeconds * 1000) {
      continue;
    }

    // Calculate match score
    let score = 0;

    // CWD match (strong signal)
    if (preCwd === targetCwd || (preCwd && targetCwd && isPathRelated(preCwd, targetCwd))) {
      score += 10;
    }

    // argv overlap (at least the first 2 tokens should match)
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

// ── Event builder (shared) ───────────────────────────────────────────

interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: string;
  parentEventId: string | null;
  monoNs: number;
  wallTs: string;
  payload: unknown;
}

function buildEvent(params: BuildEventParams): Event {
  const { sessionId, agentId, type, parentEventId, monoNs, wallTs, payload } = params;
  const id = ulidFromTime(Date.now());
  const payloadHash = sha256(payload);
  return {
    id,
    wallTs,
    monoNs,
    sessionId,
    agentId,
    parentEventId,
    type: type as Event['type'],
    payload,
    payloadHash,
  } as Event;
}
