// packages/narrative/src/render-markdown.ts
//
// The Markdown narrative, as a function rather than a template.
//
// It was Handlebars, which meant the CLI shipped a template engine to
// interpolate a dozen values and loop over four lists. Template literals
// do the same job with no dependency, and the escaping question goes
// away: Handlebars had to be compiled with `noEscape` here anyway,
// because HTML-escaping Markdown mangles the command lines the narrative
// exists to quote.

import type { NarrativeData } from './narrative-data.js';

/**
 * Render the narrative as Markdown.
 *
 * Deterministic: the same data always produces the same bytes.
 *
 * @param data - The view model built from the timeline.
 * @returns The Markdown document.
 */
export function renderMarkdownDocument(data: NarrativeData): string {
  return [
    '# DEPOSE Reconstruction Narrative',
    '',
    `**Bundle ID:** ${data.bundleId}`,
    `**Produced:** ${data.producedAt}`,
    `**Agent:** ${data.agentId}`,
    `**Session:** ${data.sessionId}`,
    '',
    '---',
    '',
    '## Summary',
    '',
    `This bundle reconstructs ${data.totalCount} events from an AI coding agent session`,
    `(${data.agentId}). The session ran from ${data.sessionStartedAt} to ${data.sessionEndedAt} UTC.`,
    '',
    ...summaryBanners(data),
    '---',
    '',
    ...lostOutcomes(data),
    ...unwitnessedCommands(data),
    '---',
    '',
    '## Timeline',
    '',
    ...timeline(data),
    '---',
    '',
    '## Destructive Operations',
    '',
    ...destructiveOps(data),
    '',
    '---',
    '',
    '## Coverage Gaps',
    '',
    ...gaps(data),
    '',
    ...capturesNote(data),
    '---',
    '',
    '## Verification',
    '',
    'This narrative is **deterministically generated** from the event timeline.',
    'Every claim above cites a specific event ID (`#evt-<ulid>`) that maps to a',
    'row in `events.jsonl`. The events are hash-chained and signed; altering any',
    'event invalidates the bundle.',
    '',
    'To verify: `depose-verify <bundle-path>`',
    '',
    '**Note:** This narrative is excluded from the signed content. It is derived',
    'from signed events. Modifying this file does not affect bundle validity.',
  ].join('\n');
}

function summaryBanners(data: NarrativeData): string[] {
  const lines: string[] = [];
  if (data.destructiveCount) {
    lines.push(
      `**⚠ ${data.destructiveCount} destructive operation(s) detected.** See Destructive Operations below.`,
      ''
    );
  }
  if (data.lostOutcomeCount) {
    lines.push(
      `**⚠ ${data.lostOutcomeCount} tool call(s) ran with no recorded outcome.** The agent was`,
      'about to act, and nothing in this bundle records what happened next. See Lost',
      'Outcomes below; this is the most serious kind of coverage hole DEPOSE reports.',
      ''
    );
  }
  if (data.unwitnessedExecveCount) {
    lines.push(
      `**⚠ ${data.unwitnessedExecveCount} command(s) ran in the agent's process tree with no hook record.**`,
      'The kernel witnessed them; the capture surface did not. See Unwitnessed Commands below.',
      ''
    );
  }
  if (data.gapCount) {
    lines.push(
      `**◉ ${data.gapCount} coverage gap(s) identified.** Gaps indicate events where pre-execution`,
      'capture was not available. These are disclosed, not hidden. See Coverage Gaps below.',
      ''
    );
  }
  return lines;
}

function lostOutcomes(data: NarrativeData): string[] {
  const lines = ['## Lost Outcomes', ''];
  if (data.lostOutcomes.length === 0) {
    lines.push('Every recorded intent has a recorded outcome.', '');
    return lines;
  }
  lines.push('Each entry is a tool call whose pre-execution record exists and whose outcome does not.');
  for (const entry of data.lostOutcomes) {
    lines.push(`- ${entry.wallTs}: ${entry.detail} \`[#evt-${entry.id}]\``);
  }
  lines.push('');
  return lines;
}

function unwitnessedCommands(data: NarrativeData): string[] {
  if (data.unwitnessedExecves.length === 0) return [];
  const lines = [
    '---',
    '',
    '## Unwitnessed Commands',
    '',
    'The kernel execve collector saw these in the agent\'s process tree and no hook or shim recorded them.',
  ];
  for (const entry of data.unwitnessedExecves) {
    lines.push(`- ${entry.wallTs}: ${entry.detail} \`[#evt-${entry.id}]\``);
  }
  lines.push('');
  return lines;
}

function timeline(data: NarrativeData): string[] {
  const lines: string[] = [];
  for (const section of data.sections) {
    lines.push(`### ${section.header}`, '');
    for (const event of section.events) {
      lines.push(`- **[${event.type}]** ${event.wallTs} UTC, ${event.summary} \`[#evt-${event.id}]\``);
      if (event.detail) {
        lines.push(`  - ${event.detail}`);
      }
    }
    lines.push('');
  }
  return lines;
}

function destructiveOps(data: NarrativeData): string[] {
  if (data.destructiveOps.length === 0) {
    return ['No destructive operations detected.'];
  }
  return data.destructiveOps.map(
    (op) =>
      `- **[${op.severity}]** ${op.wallTs}: \`${op.command}\`${op.position}, Rule: ${op.ruleId} \`[#evt-${op.eventId}]\``
  );
}

function gaps(data: NarrativeData): string[] {
  if (data.gaps.length === 0) {
    return ['No coverage gaps. All tool results have matching pre-execution captures.'];
  }
  return data.gaps.map((gap) => `- **[${gap.reason}]** ${gap.wallTs}: ${gap.detail} \`[#evt-${gap.id}]\``);
}

function capturesNote(data: NarrativeData): string[] {
  if (!data.capturesExcluded) return [];
  return [
    `**Capture records excluded:** ${data.capturesExcluded} record(s) in the producer's`,
    'capture store could not be attributed to this session and were left out of this',
    `bundle; ${data.capturesAttributed} were included. The store is machine-wide, so it`,
    'holds activity from unrelated work. Excluded records are counted in the signed',
    'manifest (`counts.capturesExcluded`) so this disclosure is covered by the',
    'signature rather than asserted only here.',
    '',
  ];
}
