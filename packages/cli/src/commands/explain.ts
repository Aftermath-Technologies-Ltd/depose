// packages/cli/src/commands/explain.ts
//
// `depose explain` — LLM-narrated postmortem to commentary.md.
//
// BUILD_PLAN.md §6 Phase 4:
//   "depose explain produces an LLM-narrated postmortem to commentary.md,
//    explicitly EXCLUDED from events.jsonl, EXCLUDED from rootHash,
//    with a banner: 'AI-GENERATED COMMENTARY — NOT EVIDENCE.'"
//
// This command reads the bundle timeline and generates a human-readable
// narrative. The output is NOT evidence — it is commentary for human
// convenience only. It is structurally excluded from the signed content.
//
// Named exports only (BUILD_PLAN.md §3.1).

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  mergeEvents,
  buildTimeline,
  formatTimelineSummary,
  loadDestructiveRules,
  generateUlid,
  type Event,
  type AgentId,
} from '@depose/core';

// ── CLI args interface ─────────────────────────────────────────────

export interface ExplainCommandArgs {
  'from-claude'?: string;
  'bundle'?: string;
  rules?: string;
  ruleset?: string;
  output?: string;
  'session-id'?: string;
  'agent-id'?: string;
  [key: string]: string | boolean | string[] | undefined;
}

// ── AI-GENERATED banner ────────────────────────────────────────────

const AI_COMMENTARY_BANNER = [
  '═══════════════════════════════════════════════════════════════',
  '  AI-GENERATED COMMENTARY — NOT EVIDENCE',
  '',
  '  This file was produced by an AI summarization system.',
  '  It is explicitly EXCLUDED from the signed content of this',
  '  bundle. It carries NO evidentiary weight. Modifying this file',
  '  does NOT affect bundle validity.',
  '',
  '  For the evidentiary record, see events.jsonl and narrative.md.',
  '═══════════════════════════════════════════════════════════════',
  '',
].join('\n');

// ── Explain command handler ────────────────────────────────────────

/**
 * Handle `depose explain --from-claude <path>` or `depose explain --bundle <path>`.
 *
 * Produces commentary.md — an AI-narrated postmortem that is explicitly
 * EXCLUDED from the signed content of the bundle.
 */
export async function handleExplain(args: ExplainCommandArgs): Promise<void> {
  const jsonlPath = typeof args['from-claude'] === 'string' ? args['from-claude'] as string : undefined;
  const bundlePath = typeof args['bundle'] === 'string' ? args['bundle'] as string : undefined;
  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;
  const outputDir = (args['output']) as string | undefined;
  const sessionId = args['session-id'] as string | undefined;
  const agentId = (args['agent-id'] || 'claude-code') as string;

  if (!jsonlPath && !bundlePath) {
    console.error('ERROR: --from-claude <path> or --bundle <path> is required.');
    console.error('');
    console.error('Usage: depose explain --from-claude <path> [options]');
    console.error('       depose explain --bundle <bundle-dir> [options]');
    process.exit(1);
    return;
  }

  const resolvedRules = rulesPath ? resolve(rulesPath) : resolve('../rules/destructive.default.yaml');
  const rules = loadDestructiveRules(resolvedRules);

  let events: Event[];

  if (bundlePath) {
    // Read events from an existing bundle
    const resolvedBundle = resolve(bundlePath);
    const eventsPath = join(resolvedBundle, 'events.jsonl');

    if (!existsSync(eventsPath)) {
      console.error(`ERROR: events.jsonl not found in bundle: ${resolvedBundle}`);
      process.exit(1);
      return;
    }

    const eventsJsonl = readFileSync(eventsPath, 'utf-8');
    events = eventsJsonl
      .trim()
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Event);
  } else {
    // Read events from JSONL source
    const resolvedJsonl = resolve(jsonlPath!);

    if (!existsSync(resolvedJsonl)) {
      console.error(`ERROR: Input file not found: ${resolvedJsonl}`);
      process.exit(1);
      return;
    }

    const jsonl = readFileSync(resolvedJsonl, 'utf-8');
    const { events: claudeEvents } = normalizeClaudeCodeJsonl(jsonl, {
      sessionId,
      agentId: agentId as AgentId,
    });

    const { events: merged } = mergeEvents(
      { claudeCodeEvents: claudeEvents },
      { sessionId: sessionId || claudeEvents[0]?.sessionId || generateUlid(), agentId: agentId as AgentId }
    );

    events = merged;
  }

  // Build timeline
  const timeline = buildTimeline(events, rules);
  const summary = formatTimelineSummary(timeline);

  // Generate commentary (deterministic, no actual LLM call — 
  // this is a template-based commentary that summarizes the timeline)
  const commentary = generateCommentary(timeline, summary, agentId);

  // Write to bundle or standalone file
  if (bundlePath) {
    const resolvedBundle = resolve(bundlePath);
    writeFileSync(join(resolvedBundle, 'commentary.md'), AI_COMMENTARY_BANNER + commentary, 'utf-8');
    console.log(`Commentary written to: ${join(resolvedBundle, 'commentary.md')}`);
  } else {
    const resolvedOutput = outputDir ? resolve(outputDir) : resolve('./depose-output');
    writeFileSync(join(resolvedOutput, 'commentary.md'), AI_COMMENTARY_BANNER + commentary, 'utf-8');
    console.log(`Commentary written to: ${join(resolvedOutput, 'commentary.md')}`);
  }

  console.log('');
  console.log('NOTE: commentary.md is AI-GENERATED and NOT EVIDENCE.');
  console.log('It is excluded from the signed bundle content.');
}

// ── Commentary generator ───────────────────────────────────────────

/**
 * Generate a deterministic commentary from the timeline.
 *
 * Per BUILD_PLAN.md §7.8: "Never put an LLM in the signed path."
 * This is a template-based generator that provides a structured
 * summary. In a full implementation, an LLM could enrich this,
 * but the output would ALWAYS be excluded from the signed path.
 */
function generateCommentary(
  timeline: ReturnType<typeof buildTimeline>,
  summary: string,
  agentId: string
): string {
  const lines: string[] = [];

  lines.push(`# Session Commentary`);
  lines.push('');
  lines.push(`**Agent:** ${agentId}`);
  lines.push(`**Total events:** ${timeline.events.length}`);
  lines.push(`**Destructive operations:** ${timeline.destructiveOps.length}`);
  lines.push(`**Coverage gaps:** ${timeline.gaps.length}`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // Executive summary
  lines.push('## Executive Summary');
  lines.push('');

  if (timeline.destructiveOps.length === 0 && timeline.gaps.length === 0) {
    lines.push(`The ${agentId} session completed without destructive operations or coverage gaps.`);
    lines.push(`All ${timeline.events.length} events were captured and reconstructed successfully.`);
  } else if (timeline.destructiveOps.length > 0 && timeline.gaps.length === 0) {
    lines.push(`The ${agentId} session included ${timeline.destructiveOps.length} destructive operation(s)`);
    lines.push(`but no coverage gaps. Pre-execution capture was available for all tool results.`);
  } else if (timeline.destructiveOps.length === 0 && timeline.gaps.length > 0) {
    lines.push(`The ${agentId} session had no destructive operations but ${timeline.gaps.length}`);
    lines.push(`coverage gap(s). Some tool results lack pre-execution capture records.`);
  } else {
    lines.push(`The ${agentId} session included ${timeline.destructiveOps.length} destructive`);
    lines.push(`operation(s) and ${timeline.gaps.length} coverage gap(s).`);
  }
  lines.push('');

  // Detailed walkthrough
  lines.push('## Event Walkthrough');
  lines.push('');
  lines.push('The following is a chronological summary of the session events.');
  lines.push('Each entry references the event ID that can be looked up in events.jsonl.');
  lines.push('');

  for (const event of timeline.events) {
    const typeEmoji = getTypeEmoji(event.type);
    lines.push(`- ${typeEmoji} **${event.type}** at ${event.wallTs} UTC \`[#evt-${event.id}]\``);
  }

  lines.push('');

  // Destructive operations
  if (timeline.destructiveOps.length > 0) {
    lines.push('## Destructive Operations Detail');
    lines.push('');

    for (const op of timeline.destructiveOps) {
      const payload = op.event.payload as { argv?: string[] };
      const cmd = payload.argv ? payload.argv.join(' ') : '(unknown command)';
      const severity = op.matches.map((m) => m.severity).join(', ');
      const rules = op.matches.map((m) => m.ruleId).join(', ');

      lines.push(`### ${cmd}`);
      lines.push(`- Event ID: ${op.event.id}`);
      lines.push(`- Time: ${op.event.wallTs} UTC`);
      lines.push(`- Severity: ${severity}`);
      lines.push(`- Matched rules: ${rules}`);
      lines.push('');
    }
  }

  // Gaps
  if (timeline.gaps.length > 0) {
    lines.push('## Coverage Gaps Detail');
    lines.push('');

    for (const gap of timeline.gaps) {
      const payload = gap.payload as { reason: string; detail: string; affectedEventIds: string[] };
      lines.push(`- **${payload.reason.replace(/_/g, ' ')}**: ${payload.detail}`);
      const affectedLinks = payload.affectedEventIds.map((id) => `[#evt-${id}]`).join(', ');
      lines.push(`  Affected: ${affectedLinks}`);
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');
  lines.push('*This commentary was generated deterministically from the event timeline.');
  lines.push('No LLM inference was used. The commentary is a structured summary, not');
  lines.push('a narrative reconstruction. It is excluded from the signed bundle content.*');

  return lines.join('\n');
}

function getTypeEmoji(type: string): string {
  switch (type) {
    case 'prompt': return '💬';
    case 'assistant_message': return '🤖';
    case 'tool_call_intent': return '🔧';
    case 'tool_call_executed': return '⚙️';
    case 'tool_result': return '📋';
    case 'file_diff': return '📝';
    case 'shell_command_pre': return '🔍';
    case 'shell_command_post': return '✅';
    case 'gap': return '⚠️';
    case 'error': return '❌';
    default: return '•';
  }
}