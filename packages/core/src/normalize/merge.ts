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
// A capture_failed event (a collector could not write a record) becomes a
// gap event here, so a lost capture is disclosed in the timeline rather
// than leaving it looking complete.
//
// Two further passes run over the sorted timeline: intent and effect
// binding (merge-intent-effect.ts) and kernel execve correlation
// (merge-kernel.ts). Both emit gaps the verifier then requires to be
// present.

import type {
  AgentId,
  Event,
  ToolResultPayload,
  ToolCallIntentPayload,
  ShellCommandPrePayload,
  GapPayload,
} from '../events/schema.js';
import { findMatchingShellPre } from './merge-correlate.js';
import { buildEvent, truncateArgv, captureFailedToGap } from './merge-support.js';
import { bindIntentAndEffect } from './merge-intent-effect.js';
import { correlateKernelExecves } from './merge-kernel.js';
import { compareByTime } from '../events/event-io.js';

// ── Merge options ────────────────────────────────────────────────────

/**
 * Options for the merge operation.
 */
export interface MergeOptions {
  /** Session ID (ULID), all events must belong to the same session */
  sessionId: string;
  /** Agent ID (default: 'claude-code') */
  agentId?: AgentId;
  /**
   * Time window (in seconds) for matching tool results to shell command
   * pre-captures. Default: 5 seconds.
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
  /** Kernel execves in the agent's process tree that no hook witnessed */
  unwitnessedExecveCount: number;
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
    if (normalized.type === 'capture_failed') {
      deduped.push(captureFailedToGap(normalized));
      gapCount++;
      continue;
    }
    deduped.push(normalized);
  }

  deduped.sort(compareByTime);

  // Build lookup maps for correlation
  const toolCallIntentMap = new Map<string, Event>();
  const shellPreMap = new Map<string, Event>();
  const toolResultMap = new Map<string, Event>();
  const shellPostMap = new Map<string, Event>();
  const unmatchedToolResults: Event[] = [];

  // Also build a tool_use_id → tool_call_intent lookup for correlating
  // tool_result events back to their parent tool_call_intent
  const toolUseIdToIntentMap = new Map<string, Event>();

  for (const event of deduped) {
    switch (event.type) {
      case 'tool_call_intent': {
        toolCallIntentMap.set(event.id, event);
        // Index by tool_use_id if present (real-session format)
        const intentPayload = event.payload as ToolCallIntentPayload;
        if (intentPayload.toolUseId) {
          toolUseIdToIntentMap.set(intentPayload.toolUseId, event);
        }
        break;
      }
      case 'shell_command_pre':
        shellPreMap.set(event.id, event);
        break;
      case 'tool_result': {
        toolResultMap.set(event.id, event);
        unmatchedToolResults.push(event);
        break;
      }
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

  // Materialize and sort the candidates once. findMatchingShellPre used to
  // call Array.from(shellPreMap.values()) on every invocation, allocating a
  // fresh array of every capture per tool_result and again per intent. With
  // the time-sorted list, each lookup binary-searches into the
  // ± matchWindowSeconds band instead of scanning the whole store.
  const shellPreByTime = Array.from(shellPreMap.values()).sort(
    (a, b) => Date.parse(a.wallTs) - Date.parse(b.wallTs)
  );

  for (const toolResult of unmatchedToolResults) {
    const matched = findMatchingShellPre(
      toolResult,
      shellPreByTime,
      toolUseIdToIntentMap,
      matchWindowSeconds
    );
    if (matched) {
      // F-32: set correlation on the event itself, not inside payload
      toolResult.correlation = {
        linkedShellCommandPreId: matched.id,
      };
      matchedToolResult.add(toolResult.id);
      matchedShellPre.add(matched.id);
      linkedCount++;
    }
  }

  // Link tool_call_intent to shell_command_pre (if not already matched)
  Array.from(toolCallIntentMap.entries()).forEach(([, intentEvent]) => {
    const matched = findMatchingShellPre(
      intentEvent,
      shellPreByTime,
      toolUseIdToIntentMap,
      matchWindowSeconds
    );
    if (matched && !matchedShellPre.has(matched.id)) {
      // F-32: set correlation on the event itself, not inside payload
      intentEvent.correlation = {
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
        monoNs: toolResult.monoNs + 1n,
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
        detail: `Shell command pre-capture at ${shellPre.wallTs} (${truncateArgv(
          (shellPre.payload as ShellCommandPrePayload).argv
        )}) has no matching tool_result. The command may have been run outside the agent session.`,
      };
      const gap = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: shellPre.id,
        monoNs: shellPre.monoNs + 1n,
        wallTs: shellPre.wallTs,
        payload: gapPayload,
      });
      allEvents.push(gap);
      gapCount++;
    }
  });

  // Bind the two halves of each tool call and attribute kernel execves,
  // both over the sorted timeline rather than the gap list built above.
  const pairing = bindIntentAndEffect(deduped, { sessionId, agentId, matchWindowSeconds });
  const kernel = correlateKernelExecves(deduped, { sessionId, agentId, matchWindowSeconds });
  allEvents.push(...pairing.gaps, ...kernel.gaps);
  gapCount += pairing.gaps.length + kernel.gaps.length;
  linkedCount += pairing.linkedCount + kernel.matchedCount;

  // Combine: original events + gap events, re-sorted
  allEvents.push(...deduped);
  allEvents.sort(compareByTime);

  return {
    events: allEvents,
    warnings,
    gapCount,
    linkedCount,
    unwitnessedExecveCount: kernel.unwitnessedCount,
  };
}

