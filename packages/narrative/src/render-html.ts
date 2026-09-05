// packages/narrative/src/render-html.ts
//
// The HTML narrative, as a function rather than a template.
//
// Handlebars escaped interpolated values here and did not in the
// Markdown renderer, which meant two different escaping rules for the
// same data. Escaping is explicit now: every value that reaches the
// document goes through `escapeHtml`, and nothing else does.

import type { NarrativeData } from './narrative-data.js';

const STYLE = `  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; line-height: 1.6; }
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
  th { background: #f5f5f5; }`;

/**
 * Escape a value for HTML text or an attribute.
 *
 * The narrative quotes command lines verbatim, so `<`, `&`, and quotes
 * reach this function routinely and every one of them has to come out
 * escaped: a bundle whose narrative renders an attacker's command as
 * markup is a bundle whose narrative can be made to say anything.
 *
 * @param value - The text to escape.
 * @returns The escaped text.
 */
export function escapeHtml(value: string | number): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Render the narrative as HTML.
 *
 * Deterministic: the same data always produces the same bytes.
 *
 * @param data - The view model built from the timeline.
 * @returns The HTML document.
 */
export function renderHtmlDocument(data: NarrativeData): string {
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
    `<title>DEPOSE Reconstruction: ${escapeHtml(data.bundleId)}</title>`,
    '<style>',
    STYLE,
    '</style>',
    '</head>',
    '<body>',
    '<h1>DEPOSE Reconstruction Narrative</h1>',
    '<div class="meta">',
    `<p><strong>Bundle ID:</strong> ${escapeHtml(data.bundleId)}<br>`,
    `<strong>Produced:</strong> ${escapeHtml(data.producedAt)}<br>`,
    `<strong>Agent:</strong> ${escapeHtml(data.agentId)}<br>`,
    `<strong>Session:</strong> ${escapeHtml(data.sessionId)}</p>`,
    '</div>',
    '<h2>Summary</h2>',
    `<p>This bundle reconstructs ${data.totalCount} events from an AI coding agent session`,
    `(${escapeHtml(data.agentId)}). The session ran from ${escapeHtml(data.sessionStartedAt)} to ${escapeHtml(data.sessionEndedAt)} UTC.</p>`,
    ...banners(data),
    '<h2>Lost Outcomes</h2>',
    ...detailTable(data.lostOutcomes, 'destructive', 'Every recorded intent has a recorded outcome.'),
    ...unwitnessedSection(data),
    '<h2>Timeline</h2>',
    ...timeline(data),
    '<h2>Destructive Operations</h2>',
    ...destructiveOps(data),
    '<h2>Coverage Gaps</h2>',
    ...gaps(data),
    '<h2>Verification</h2>',
    '<p>This narrative is <strong>deterministically generated</strong> from the event timeline.',
    'Every claim above cites a specific event ID that maps to a row in <code>events.jsonl</code>.',
    'The events are hash-chained and signed; altering any event invalidates the bundle.</p>',
    '<p>To verify: <code>depose-verify &lt;bundle-path&gt;</code></p>',
    '<p class="note">This narrative is excluded from the signed content. It is derived from signed events. Modifying this file does not affect bundle validity.</p>',
    '</body>',
    '</html>',
  ].join('\n');
}

function banners(data: NarrativeData): string[] {
  const lines: string[] = [];
  if (data.destructiveCount) {
    lines.push(
      `<div class="destructive"><strong>WARNING: ${data.destructiveCount} destructive operation(s) detected.</strong> See Destructive Operations below.</div>`
    );
  }
  if (data.lostOutcomeCount) {
    lines.push(
      `<div class="destructive"><strong>WARNING: ${data.lostOutcomeCount} tool call(s) ran with no recorded outcome.</strong> The agent was about to act and nothing in this bundle records what happened next. See Lost Outcomes below.</div>`
    );
  }
  if (data.unwitnessedExecveCount) {
    lines.push(
      `<div class="destructive"><strong>WARNING: ${data.unwitnessedExecveCount} command(s) ran in the agent's process tree with no hook record.</strong> The kernel witnessed them; the capture surface did not.</div>`
    );
  }
  if (data.gapCount) {
    lines.push(
      `<div class="gap"><strong>NOTE: ${data.gapCount} coverage gap(s) identified.</strong> Gaps indicate events where pre-execution capture was not available. These are disclosed, not hidden.</div>`
    );
  }
  return lines;
}

function detailTable(
  rows: Array<{ wallTs: string; detail: string; id: string }>,
  rowClass: string,
  empty: string
): string[] {
  if (rows.length === 0) return [`<p>${empty}</p>`];
  return [
    '<table>',
    '<tr><th>Time</th><th>Detail</th><th>Event ID</th></tr>',
    ...rows.map(
      (row) =>
        `<tr class="${rowClass}"><td>${escapeHtml(row.wallTs)}</td><td>${escapeHtml(row.detail)}</td><td class="event-ref"><code>#evt-${escapeHtml(row.id)}</code></td></tr>`
    ),
    '</table>',
  ];
}

function unwitnessedSection(data: NarrativeData): string[] {
  if (data.unwitnessedExecves.length === 0) return [];
  return ['<h2>Unwitnessed Commands</h2>', ...detailTable(data.unwitnessedExecves, 'destructive', '')];
}

function timeline(data: NarrativeData): string[] {
  const lines: string[] = [];
  for (const section of data.sections) {
    lines.push(
      `<h3>${escapeHtml(section.header)}</h3>`,
      '<table>',
      '<tr><th>Type</th><th>Time (UTC)</th><th>Summary</th><th>Event ID</th></tr>',
      ...section.events.map(
        (event) =>
          `<tr><td>${escapeHtml(event.type)}</td><td>${escapeHtml(event.wallTs)}</td><td>${escapeHtml(event.summary)}</td><td class="event-ref"><code>#evt-${escapeHtml(event.id)}</code></td></tr>`
      ),
      '</table>'
    );
  }
  return lines;
}

function destructiveOps(data: NarrativeData): string[] {
  if (data.destructiveOps.length === 0) return ['<p>No destructive operations detected.</p>'];
  return [
    '<table>',
    '<tr><th>Severity</th><th>Time</th><th>Command</th><th>Rule</th><th>Event ID</th></tr>',
    ...data.destructiveOps.map(
      (op) =>
        `<tr class="destructive"><td>${escapeHtml(op.severity)}</td><td>${escapeHtml(op.wallTs)}</td><td><code>${escapeHtml(op.command)}</code>${escapeHtml(op.position)}</td><td>${escapeHtml(op.ruleId)}</td><td class="event-ref"><code>#evt-${escapeHtml(op.eventId)}</code></td></tr>`
    ),
    '</table>',
  ];
}

function gaps(data: NarrativeData): string[] {
  if (data.gaps.length === 0) {
    return ['<p>No coverage gaps. All tool results have matching pre-execution captures.</p>'];
  }
  return [
    '<table>',
    '<tr><th>Reason</th><th>Time</th><th>Detail</th><th>Event ID</th></tr>',
    ...data.gaps.map(
      (gap) =>
        `<tr class="gap"><td>${escapeHtml(gap.reason)}</td><td>${escapeHtml(gap.wallTs)}</td><td>${escapeHtml(gap.detail)}</td><td class="event-ref"><code>#evt-${escapeHtml(gap.id)}</code></td></tr>`
    ),
    '</table>',
  ];
}
