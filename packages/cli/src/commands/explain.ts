// packages/cli/src/commands/explain.ts
//
// `depose explain`: templated postmortem summary to commentary.md.
//
// The original plan called for an LLM-narrated postmortem. No model
// was ever wired up; generateCommentary below is deterministic templating
// over the timeline. The banner and the CLI help said
// "AI-GENERATED" anyway, which claimed a provenance the output does not
// have. For a tool whose product is credibility, a command that misstates
// how its own output was produced is a defect, so the labelling now
// matches the implementation.
//
// The output is still NOT evidence: it is a convenience summary,
// structurally excluded from the signed content.
//
// Named exports only.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import {
  normalizeClaudeCodeJsonl,
  mergeEvents,
  buildTimeline,
  formatTimelineSummary,
  loadDestructiveRules,
  generateUlid,
  parseEventLine,
  type Event,
  type AgentId,
} from '@depose/core';
import { DEFAULT_RULES_PATH } from '../rules-default.js';

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

// ── Not-evidence banner ────────────────────────────────────────────

const COMMENTARY_BANNER = [
  '═══════════════════════════════════════════════════════════════',
  '  TEMPLATED COMMENTARY, NOT EVIDENCE',
  '',
  '  This file is a deterministic template summary of the event',
  '  timeline. No language model produced it and none is involved.',
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
 * Produces commentary.md, a deterministic template summary of the
 * timeline that is explicitly EXCLUDED from the signed bundle content.
 * No language model is involved.
 */
export async function handleExplain(args: ExplainCommandArgs): Promise<void> {
  console.error('WARNING: depose explain is deprecated. Use narrative.md in the bundle instead.');
  console.error('The explain command produces deterministic template output, not AI-generated commentary.');
  console.error('It will be removed in a future release.');
  console.error('');

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

  const resolvedRules = rulesPath ? resolve(rulesPath) : DEFAULT_RULES_PATH;
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
      .map((line) => parseEventLine(line));
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

  // Deterministic template over the timeline. No model call.
  const commentary = generateCommentary(timeline, summary, agentId);

  // Never write into a sealed bundle: every file in the tree is pinned by
  // the signed files map, so an added commentary.md would fail
  // verification. The commentary lands next to the bundle instead.
  if (bundlePath) {
    const resolvedBundle = resolve(bundlePath);
    const sidecar = `${resolvedBundle}-commentary.md`;
    writeFileSync(sidecar, COMMENTARY_BANNER + commentary, 'utf-8');
    console.log(`Commentary written to: ${sidecar}`);
  } else {
    const resolvedOutput = outputDir ? resolve(outputDir) : resolve('./depose-output');
    writeFileSync(join(resolvedOutput, 'commentary.md'), COMMENTARY_BANNER + commentary, 'utf-8');
    console.log(`Commentary written to: ${join(resolvedOutput, 'commentary.md')}`);
  }

  console.log('');
  console.log('NOTE: commentary.md is a templated summary, NOT EVIDENCE.');
  console.log('It is excluded from the signed bundle content.');
}

// ── Commentary generator ───────────────────────────────────────────

/**
 * Generate a deterministic commentary from the timeline.
 *
 * Never put an LLM in the signed path (docs/architecture.md §4.1).
 * This is a template-based generator that provides a structured
 * summary. If a model-backed variant is ever added it must be opt-in
 * and labelled as such, and its output would still be excluded from
 * the signed path.
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