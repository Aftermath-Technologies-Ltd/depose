// packages/core/src/reconstruct/timeline.ts
//
// Build a deterministic reconstruction timeline from a list of Events.
//
// The timeline:
//   1. Sorts events by (wallTs, monoNs)
//   2. Builds a parent-child causal graph (via parentEventId)
//   3. Identifies destructive operations (via ruleset matching)
//   4. Cross-correlates captures vs. aftermath (git reflog, fs state)
//
// See BUILD_PLAN.md §4.1 for the Event schema.
// See BUILD_PLAN.md §5 (Phase 1) for scope.

import type {
  Event,
  ShellCommandPrePayload,
  ToolCallIntentPayload,
  ToolResultPayload,
  GapPayload,
} from '../events/schema.js';
import { buildDestructiveOpsIndex, type DestructiveRule } from './destructive-rules.js';

// ── Timeline types ───────────────────────────────────────────────────

/**
 * A node in the reconstruction timeline.
 * Represents a single event with its children (causal descendants).
 */
export interface TimelineNode {
  /** The event this node represents */
  event: Event;
  /** Child nodes (events whose parentEventId = this event's id) */
  children: TimelineNode[];
  /** Destructive operation matches (if any) */
  destructiveMatches: Array<{
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
}

/**
 * The complete reconstruction timeline.
 */
export interface ReconstructionTimeline {
  /** Root nodes (events with no parent or parent not in the event list) */
  roots: TimelineNode[];
  /** All events in order (sorted by wallTs, monoNs) */
  events: Event[];
  /** Destructive operations index */
  destructiveOps: Array<{
    event: Event;
    matches: Array<{
      ruleId: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      matchedArgv: string[];
      matchedField: string;
    }>;
  }>;
  /** Gap events (coverage holes) */
  gaps: Event[];
  /** File changes (file_diff events) */
  fileChanges: Event[];
  /** Error events */
  errors: Event[];
  /** Process spawns (from shell history or reflog) */
  processSpawns: Event[];
  /** Tool call summary (count by tool name) */
  toolCallSummary: Record<string, { intent: number; result: number }>;
}

// ── Main timeline builder ────────────────────────────────────────────

/**
 * Build a reconstruction timeline from a list of events.
 *
 * The timeline is deterministic: same events always produce the same
 * timeline (sorted order, deterministic tree structure).
 *
 * @param events - Sorted list of events (should be sorted by wallTs, monoNs)
 * @param rules - Destructive ruleset (for destructive ops index)
 */
export function buildTimeline(
  events: Event[],
  rules: DestructiveRule[]
): ReconstructionTimeline {
  // Sort events (should already be sorted, but ensure it)
  const sorted = [...events].sort((a, b) => {
    const tsCmp = a.wallTs.localeCompare(b.wallTs);
    if (tsCmp !== 0) return tsCmp;
    return a.monoNs - b.monoNs;
  });

  // Build parent-child graph
  const eventMap = new Map<string, Event>();
  const childrenMap = new Map<string, string[]>(); // parentId -> [childId, ...]
  const roots: string[] = [];

  for (const event of sorted) {
    eventMap.set(event.id, event);
    if (event.parentEventId && eventMap.has(event.parentEventId)) {
      const children = childrenMap.get(event.parentEventId) || [];
      children.push(event.id);
      childrenMap.set(event.parentEventId, children);
    } else {
      roots.push(event.id);
    }
  }

  // Build tree
  const rootNodes: TimelineNode[] = [];
  for (const rootId of roots) {
    const node = buildTree(rootId, eventMap, childrenMap, rules);
    rootNodes.push(node);
  }

  // Destructive operations index
  const destructiveOps = buildDestructiveOpsIndex(sorted, rules);

  // Categorize events
  const gaps = sorted.filter((e) => e.type === 'gap');
  const fileChanges = sorted.filter((e) => e.type === 'file_diff');
  const errors = sorted.filter((e) => e.type === 'error');
  const processSpawns = sorted.filter((e) => e.type === 'process_spawn');

  // Tool call summary
  const toolCallSummary: Record<string, { intent: number; result: number }> = {};
  for (const event of sorted) {
    if (event.type === 'tool_call_intent') {
      const payload = event.payload as ToolCallIntentPayload;
      const name = payload.toolName;
      if (!toolCallSummary[name]) {
        toolCallSummary[name] = { intent: 0, result: 0 };
      }
      toolCallSummary[name].intent++;
    }
    if (event.type === 'tool_result') {
      const payload = event.payload as ToolResultPayload;
      const name = payload.toolName;
      if (!toolCallSummary[name]) {
        toolCallSummary[name] = { intent: 0, result: 0 };
      }
      toolCallSummary[name].result++;
    }
  }

  return {
    roots: rootNodes,
    events: sorted,
    destructiveOps,
    gaps,
    fileChanges,
    errors,
    processSpawns,
    toolCallSummary,
  };
}

// ── Tree building ────────────────────────────────────────────────────

/**
 * Build a timeline tree rooted at a given event ID.
 */
function buildTree(
  eventId: string,
  eventMap: Map<string, Event>,
  childrenMap: Map<string, string[]>,
  rules: DestructiveRule[]
): TimelineNode {
  const event = eventMap.get(eventId);
  if (!event) {
    throw new Error(`Event not found: ${eventId}`);
  }

  // Destructive matches
  const destructiveMatches: Array<{
    ruleId: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }> = [];
  if (event.type === 'shell_command_pre') {
    const matches = rules
      .filter((r) => {
        const payload = event.payload as ShellCommandPrePayload;
        return matchesRule(r, payload);
      })
      .map((r) => ({
        ruleId: r.id,
        severity: r.severity,
      }));
    destructiveMatches.push(...matches);
  }

  // Children
  const childIds = childrenMap.get(eventId) || [];
  const children = childIds
    .map((childId) => buildTree(childId, eventMap, childrenMap, rules))
    .sort((a, b) => a.event.wallTs.localeCompare(b.event.wallTs));

  return {
    event,
    children,
    destructiveMatches,
  };
}

// ── Inline rule matching (avoid circular dependency) ─────────────────

function matchesRule(rule: DestructiveRule, payload: ShellCommandPrePayload): boolean {
  const { argv } = payload;
  const { argvHead, argvContainsAny, anyArgvRegex } = rule.matcher;

  // argvHead (prefix match)
  if (argvHead && argvHead.length > 0) {
    const head = argv.slice(0, argvHead.length);
    if (argvHead.every((term, i) => head[i]?.toLowerCase() === term.toLowerCase())) {
      return true;
    }
  }

  // argvContainsAny
  if (argvContainsAny && argvContainsAny.length > 0) {
    if (argv.some((arg) => argvContainsAny.some((term) => arg.includes(term)))) {
      return true;
    }
  }

  // anyArgvRegex
  if (anyArgvRegex) {
    try {
      const regex = new RegExp(anyArgvRegex);
      if (argv.some((arg) => regex.test(arg))) {
        return true;
      }
    } catch {
      // Invalid regex
    }
  }

  return false;
}

// ── Timeline formatting (for narrative output) ───────────────────────

/**
 * Format a timeline as a plain-text summary (for debugging and narrative).
 */
export function formatTimelineSummary(timeline: ReconstructionTimeline): string {
  const lines: string[] = [];
  lines.push(`DEPOSE Reconstruction Timeline`);
  lines.push(`═══════════════════════════════`);
  lines.push(`Total events: ${timeline.events.length}`);
  lines.push(`Root nodes: ${timeline.roots.length}`);
  lines.push(`Destructive operations: ${timeline.destructiveOps.length}`);
  lines.push(`Gaps (coverage holes): ${timeline.gaps.length}`);
  lines.push(`File changes: ${timeline.fileChanges.length}`);
  lines.push(`Errors: ${timeline.errors.length}`);
  lines.push(`Process spawns: ${timeline.processSpawns.length}`);
  lines.push('');

  // Tool call summary
  const toolNames = Object.keys(timeline.toolCallSummary).sort();
  if (toolNames.length > 0) {
    lines.push('Tool calls:');
    for (const name of toolNames) {
      const summary = timeline.toolCallSummary[name] || { intent: 0, result: 0 };
      lines.push(`  ${name}: ${summary.intent} intent, ${summary.result} result`);
    }
    lines.push('');
  }

  // Destructive operations
  if (timeline.destructiveOps.length > 0) {
    lines.push('Destructive operations:');
    for (const { event, matches } of timeline.destructiveOps) {
      const payload = event.payload as ShellCommandPrePayload;
      const severity = matches.map((m) => m.severity).join(', ');
      const cmd = payload.argv.join(' ');
      lines.push(`  [${severity}] ${event.wallTs}: ${cmd}`);
      for (const match of matches) {
        lines.push(`    → Rule: ${match.ruleId}`);
      }
    }
    lines.push('');
  }

  // Gaps
  if (timeline.gaps.length > 0) {
    lines.push('Coverage gaps:');
    for (const gap of timeline.gaps) {
      const payload = gap.payload as GapPayload;
      lines.push(`  [${payload.reason}] ${gap.wallTs}: ${payload.detail.slice(0, 120)}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
