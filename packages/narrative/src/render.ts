// packages/narrative/src/render.ts
//
// Deterministic narrative renderer for DEPOSE evidence bundles.
// Walks the timeline and emits prose with [#evt-<ulid>] anchors
// that link to events.jsonl rows.
//
// BUILD_PLAN.md §6 Phase 4:
//   "Template-driven, deterministic, every claim cites event ID.
//    No LLM in signed path."
//
// The narrative is EXCLUDED from rootHash. It is derived from
// signed events. Modifying it does not affect bundle validity.

import Handlebars from 'handlebars';
import type {
  Event,
  ShellCommandPrePayload,
  ToolCallIntentPayload,
  ToolCallExecutedPayload,
  ToolResultPayload,
  FileDiffPayload,
  GapPayload,
  PromptPayload,
  AssistantMessagePayload,
  ErrorPayload,
} from '@depose/core';
import type { ReconstructionTimeline } from '@depose/core';

// ── Template loading ────────────────────────────────────────────────

const MD_TEMPLATE = `# DEPOSE Reconstruction Narrative

**Bundle ID:** {{bundleId}}
**Produced:** {{producedAt}}
**Agent:** {{agentId}}
**Session:** {{sessionId}}

---

## Summary

This bundle reconstructs {{totalCount}} events from an AI coding agent session
({{agentId}}). The session ran from {{sessionStartedAt}} to {{sessionEndedAt}} UTC.

{{#if destructiveCount}}
**⚠ {{destructiveCount}} destructive operation(s) detected.** See Destructive Operations below.
{{/if}}

{{#if gapCount}}
**◉ {{gapCount}} coverage gap(s) identified.** Gaps indicate events where pre-execution
capture was not available. These are disclosed, not hidden. See Coverage Gaps below.
{{/if}}

---

## Timeline

{{#each sections}}
### {{header}}

{{#each events}}
- **[{{type}}]** {{wallTs}} UTC — {{summary}} \`[#evt-{{id}}]\`
{{#if detail}}
  - {{detail}}
{{/if}}
{{/each}}

{{/each}}

---

## Destructive Operations

{{#if destructiveOps}}
{{#each destructiveOps}}
- **[{{severity}}]** {{wallTs}}: \`{{command}}\` — Rule: {{ruleId}} \`[#evt-{{eventId}}]\`
{{/each}}
{{else}}
No destructive operations detected.
{{/if}}

---

## Coverage Gaps

{{#if gaps}}
{{#each gaps}}
- **[{{reason}}]** {{wallTs}}: {{detail}} \`[#evt-{{id}}]\`
{{/each}}
{{else}}
No coverage gaps — all tool results have matching pre-execution captures.
{{/if}}

---

## Verification

This narrative is **deterministically generated** from the event timeline.
Every claim above cites a specific event ID (\`#evt-<ulid>\`) that maps to a
row in \`events.jsonl\`. The events are hash-chained and signed; altering any
event invalidates the bundle.

To verify: \`depose-verify <bundle-path>\`

**Note:** This narrative is excluded from the signed content. It is derived
from signed events. Modifying this file does not affect bundle validity.`;

// ── Event summarization (deterministic, no inference) ──────────────

/**
 * Summarize an event for narrative display.
 * Deterministic: same event always produces the same summary.
 * Conservative: only states what the event directly records, no inference.
 */
export function summarizeEvent(event: Event): { summary: string; detail: string } {
  switch (event.type) {
    case 'prompt': {
      const p = event.payload as PromptPayload;
      const text = p.text.length > 120 ? p.text.slice(0, 117) + '...' : p.text;
      return { summary: `User prompt: "${text}"`, detail: '' };
    }
    case 'assistant_message': {
      const p = event.payload as AssistantMessagePayload;
      const content = p.content.length > 120 ? p.content.slice(0, 117) + '...' : p.content;
      const toolCount = p.toolCalls?.length ?? 0;
      const toolNote = toolCount > 0 ? ` (${toolCount} tool call(s) attached)` : '';
      return { summary: `Assistant response: "${content}"${toolNote}`, detail: '' };
    }
    case 'tool_call_intent': {
      const p = event.payload as ToolCallIntentPayload;
      const linked = event.correlation?.linkedShellCommandPreId
        ? ` → linked to shell_command_pre [#evt-${event.correlation.linkedShellCommandPreId}]`
        : '';
      return {
        summary: `Tool call intent: ${p.toolName}`,
        detail: `Input: ${JSON.stringify(p.toolInput).slice(0, 200)}${linked}`,
      };
    }
    case 'tool_call_executed': {
      const p = event.payload as ToolCallExecutedPayload;
      const exitInfo = p.exitCode !== null ? ` (exit ${p.exitCode})` : '';
      const durationInfo = p.durationMs !== null ? ` in ${p.durationMs}ms` : '';
      return {
        summary: `Tool executed: ${p.toolName}${exitInfo}${durationInfo}`,
        detail: event.correlation?.linkedShellCommandPreId
          ? `Pre-capture linked: [#evt-${event.correlation.linkedShellCommandPreId}]`
          : '',
      };
    }
    case 'tool_result': {
      const p = event.payload as ToolResultPayload;
      const output = p.output.length > 100 ? p.output.slice(0, 97) + '...' : p.output;
      const exitInfo = p.exitCode !== null ? ` (exit ${p.exitCode})` : '';
      const linked = event.correlation?.linkedShellCommandPreId
        ? ` | Pre-capture: [#evt-${event.correlation.linkedShellCommandPreId}]`
        : '';
      return {
        summary: `Tool result${exitInfo}: ${p.toolName}`,
        detail: `Output: "${output}"${linked}`,
      };
    }
    case 'file_diff': {
      const p = event.payload as FileDiffPayload;
      const pre = p.preHash ? `exists (sha256:${p.preHash.slice(0, 12)}...)` : 'did not exist';
      const post = p.postHash ? `sha256:${p.postHash.slice(0, 12)}...` : 'deleted';
      return {
        summary: `File modified: ${p.path}`,
        detail: `Before: ${pre}; After: ${post}`,
      };
    }
    case 'shell_command_pre': {
      const p = event.payload as ShellCommandPrePayload;
      const cmd = p.argv.join(' ');
      const fileCount = p.fileArgs.length;
      const files = fileCount > 0 ? `; ${fileCount} file arg(s) hashed` : '';
      return {
        summary: `Pre-capture (${p.source}): ${cmd.length > 80 ? cmd.slice(0, 77) + '...' : cmd}`,
        detail: `cwd=${p.cwd} user=${p.user}${files}`,
      };
    }
    case 'shell_command_post': {
      return { summary: 'Post-capture: command completed', detail: '' };
    }
    case 'env_change': {
      return { summary: 'Environment change detected', detail: '' };
    }
    case 'process_spawn': {
      return { summary: 'Process spawned', detail: '' };
    }
    case 'error': {
      const p = event.payload as ErrorPayload;
      return { summary: `Error: ${p.message}`, detail: p.code ? `Code: ${p.code}` : '' };
    }
    case 'gap': {
      const p = event.payload as GapPayload;
      return {
        summary: `Gap: ${p.reason.replace(/_/g, ' ')}`,
        detail: p.detail.length > 200 ? p.detail.slice(0, 197) + '...' : p.detail,
      };
    }
    default: {
      return { summary: `Unknown event type: ${(event as Event).type}`, detail: '' };
    }
  }
}

// ── Section grouping ───────────────────────────────────────────────

/**
 * Group events into time-based sections for narrative organization.
 * Deterministic: same events always produce the same sections.
 */
export function groupEventsIntoSections(
  events: Event[]
): Array<{ header: string; events: Array<Event & { summary: string; detail: string }> }> {
  if (events.length === 0) {
    return [];
  }

  const sections: Array<{
    header: string;
    events: Array<Event & { summary: string; detail: string }>;
  }> = [];

  // Group by hour
  let currentHour = '';
  let currentSection: Array<Event & { summary: string; detail: string }> = [];

  for (const event of events) {
    // Extract hour from wallTs (e.g., "2025-05-18T15:30:00.000Z" -> "15:00 UTC")
    const hourMatch = event.wallTs.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}):/);
    const hour = hourMatch ? `${hourMatch[1]} ${hourMatch[2]}:00 UTC` : event.wallTs;

    if (hour !== currentHour) {
      if (currentSection.length > 0) {
        sections.push({ header: currentHour, events: currentSection });
      }
      currentHour = hour;
      currentSection = [];
    }

    const { summary, detail } = summarizeEvent(event);
    currentSection.push({ ...event, summary, detail });
  }

  if (currentSection.length > 0) {
    sections.push({ header: currentHour, events: currentSection });
  }

  return sections;
}

// ── Render options ─────────────────────────────────────────────────

export interface RenderOptions {
  /** Bundle ID (ULID) */
  bundleId: string;
  /** Production timestamp (ISO 8601 UTC) */
  producedAt: string;
  /** Agent ID (e.g., "claude-code") */
  agentId: string;
  /** Session ID */
  sessionId: string;
  /** Session start timestamp */
  sessionStartedAt: string;
  /** Session end timestamp */
  sessionEndedAt: string;
}

// ── Template data shape ────────────────────────────────────────────

interface NarrativeData {
  bundleId: string;
  producedAt: string;
  agentId: string;
  sessionId: string;
  sessionStartedAt: string;
  sessionEndedAt: string;
  totalCount: number;
  destructiveCount: number;
  gapCount: number;
  sections: Array<{ header: string; events: Array<{ type: string; wallTs: string; id: string; summary: string; detail: string }> }>;
  destructiveOps: Array<{ severity: string; wallTs: string; command: string; ruleId: string; eventId: string }>;
  gaps: Array<{ reason: string; wallTs: string; detail: string; id: string }>;
}

// ── Build template data from timeline ──────────────────────────────

/**
 * Build the template data object from a reconstruction timeline.
 * Deterministic: same timeline always produces the same data.
 */
export function buildNarrativeData(
  timeline: ReconstructionTimeline,
  options: RenderOptions
): NarrativeData {
  const sections = groupEventsIntoSections(timeline.events).map((section) => ({
    header: section.header,
    events: section.events.map((e) => ({
      type: e.type,
      wallTs: e.wallTs,
      id: e.id,
      summary: e.summary,
      detail: e.detail,
    })),
  }));

  const destructiveOps = timeline.destructiveOps.map((op) => {
    // shell_command_pre carries argv already; tool_call_intent (the
    // reconstruct-from-JSONL path) carries a free-form command string
    // under toolInput.command. Render the command verbatim when we
    // can find it; otherwise show the tool + stringified input.
    let command = '(unknown)';
    const payload = op.event.payload as unknown as Record<string, unknown>;
    if (Array.isArray(payload.argv)) {
      command = (payload.argv as string[]).join(' ');
    } else if (typeof payload.toolName === 'string') {
      const input = payload.toolInput as { command?: unknown } | null | undefined;
      if (input && typeof input.command === 'string') {
        command = input.command;
      } else {
        const stringified = payload.toolInput ? JSON.stringify(payload.toolInput) : '';
        command = `${payload.toolName} ${stringified.slice(0, 80)}`;
      }
    }
    return {
      severity: op.matches[0]?.severity ?? 'medium',
      wallTs: op.event.wallTs,
      command,
      ruleId: op.matches.map((m) => m.ruleId).join(', '),
      eventId: op.event.id,
    };
  });

  const gaps = timeline.gaps.map((g) => {
    const payload = g.payload as GapPayload;
    return {
      reason: payload.reason.replace(/_/g, ' '),
      wallTs: g.wallTs,
      detail: payload.detail,
      id: g.id,
    };
  });

  return {
    bundleId: options.bundleId,
    producedAt: options.producedAt,
    agentId: options.agentId,
    sessionId: options.sessionId,
    sessionStartedAt: options.sessionStartedAt,
    sessionEndedAt: options.sessionEndedAt,
    totalCount: timeline.events.length,
    destructiveCount: timeline.destructiveOps.length,
    gapCount: timeline.gaps.length,
    sections,
    destructiveOps,
    gaps,
  };
}

// ── Main renderers ──────────────────────────────────────────────────

// Compile templates once (deterministic: no side-effect helpers)
const mdTemplate = Handlebars.compile(MD_TEMPLATE, { noEscape: true });

/**
 * Render the narrative as Markdown.
 * Deterministic: same timeline + same options → same output.
 */
export function renderMarkdown(
  timeline: ReconstructionTimeline,
  options: RenderOptions
): string {
  const data = buildNarrativeData(timeline, options);
  return mdTemplate(data);
}

/**
 * Render the narrative as HTML.
 * Deterministic: same timeline + same options → same output.
 */
export function renderHtml(
  timeline: ReconstructionTimeline,
  options: RenderOptions
): string {
  // HTML template is inline for deterministic rendering
  const htmlTemplate = Handlebars.compile(HTML_TEMPLATE);
  const data = buildNarrativeData(timeline, options);
  return htmlTemplate(data);
}

// ── HTML template (inline for determinism) ─────────────────────────

const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DEPOSE Reconstruction — {{bundleId}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; line-height: 1.6; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 0.3em; }
  h2 { color: #444; margin-top: 2em; }
  h3 { color: #555; }
  .meta { background: #f5f5f5; padding: 1em; border-radius: 4px; margin-bottom: 1.5em; font-size: 0.9em; }
  .destructive { background: #fff3f3; border-left: 4px solid #c00; padding: 0.5em 1em; margin: 0.5em 0; }
  .gap { background: #fff8e1; border-left: 4px solid #f90; padding: 0.5em 1em; margin: 0.5em 0; }
  .event-ref { font-family: monospace; font-size: 0.85em; color: #666; }
  code { background: #f0f0f0; padding: 0.15em 0.3em; border-radius: 3px; font-size: 0.9em; }
  .warning { color: #c00; font-weight: bold; }
  .note { font-style: italic; color: #666; font-size: 0.9em; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #ddd; padding: 0.5em; text-align: left; }
  th { background: #f5f5f5; }
</style>
</head>
<body>
<h1>DEPOSE Reconstruction Narrative</h1>
<div class="meta">
<p><strong>Bundle ID:</strong> {{bundleId}}<br>
<strong>Produced:</strong> {{producedAt}}<br>
<strong>Agent:</strong> {{agentId}}<br>
<strong>Session:</strong> {{sessionId}}</p>
</div>
<h2>Summary</h2>
<p>This bundle reconstructs {{totalCount}} events from an AI coding agent session
({{agentId}}). The session ran from {{sessionStartedAt}} to {{sessionEndedAt}} UTC.</p>
{{#if destructiveCount}}
<div class="destructive"><strong>WARNING: {{destructiveCount}} destructive operation(s) detected.</strong> See Destructive Operations below.</div>
{{/if}}
{{#if gapCount}}
<div class="gap"><strong>NOTE: {{gapCount}} coverage gap(s) identified.</strong> Gaps indicate events where pre-execution capture was not available. These are disclosed, not hidden.</div>
{{/if}}
<h2>Timeline</h2>
{{#each sections}}
<h3>{{header}}</h3>
<table>
<tr><th>Type</th><th>Time (UTC)</th><th>Summary</th><th>Event ID</th></tr>
{{#each events}}
<tr><td>{{type}}</td><td>{{wallTs}}</td><td>{{summary}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{/each}}
<h2>Destructive Operations</h2>
{{#if destructiveOps}}
<table>
<tr><th>Severity</th><th>Time</th><th>Command</th><th>Rule</th><th>Event ID</th></tr>
{{#each destructiveOps}}
<tr class="destructive"><td>{{severity}}</td><td>{{wallTs}}</td><td><code>{{command}}</code></td><td>{{ruleId}}</td><td class="event-ref"><code>#evt-{{eventId}}</code></td></tr>
{{/each}}
</table>
{{else}}
<p>No destructive operations detected.</p>
{{/if}}
<h2>Coverage Gaps</h2>
{{#if gaps}}
<table>
<tr><th>Reason</th><th>Time</th><th>Detail</th><th>Event ID</th></tr>
{{#each gaps}}
<tr class="gap"><td>{{reason}}</td><td>{{wallTs}}</td><td>{{detail}}</td><td class="event-ref"><code>#evt-{{id}}</code></td></tr>
{{/each}}
</table>
{{else}}
<p>No coverage gaps — all tool results have matching pre-execution captures.</p>
{{/if}}
<h2>Verification</h2>
<p>This narrative is <strong>deterministically generated</strong> from the event timeline.
Every claim above cites a specific event ID that maps to a row in <code>events.jsonl</code>.
The events are hash-chained and signed; altering any event invalidates the bundle.</p>
<p>To verify: <code>depose-verify &lt;bundle-path&gt;</code></p>
<p class="note">This narrative is excluded from the signed content. It is derived from signed events. Modifying this file does not affect bundle validity.</p>
</body>
</html>`;