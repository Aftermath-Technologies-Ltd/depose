// packages/narrative/src/render.ts
//
// Deterministic narrative renderer for DEPOSE evidence bundles.
// Walks the timeline and emits prose with [#evt-<ulid>] anchors
// that link to events.jsonl rows.
//
// Deterministic, every claim cites an event ID. No LLM in the signed
// path, and no template engine: the two renderers are functions over the
// view model this file builds (render-markdown.ts, render-html.ts).
//
// The narrative is EXCLUDED from rootHash. It is derived from
// signed events. Modifying it does not affect bundle validity.

import { renderMarkdownDocument } from './render-markdown.js';
import { renderHtmlDocument } from './render-html.js';
import { summarizeEvent } from './summarize.js';
import type { NarrativeData } from './narrative-data.js';
import type { Event, GapPayload } from '@depose/core';
import type { ReconstructionTimeline } from '@depose/core';

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
  /** Capture records merged into this bundle. */
  capturesAttributed?: number;
  /**
   * Capture records held by the producer that were not attributable to
   * this session. Disclosed rather than silently omitted, matching how
   * coverage gaps are handled.
   */
  capturesExcluded?: number;
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
    // The match names the simple command that fired, after wrapper
    // stripping, so `sudo bash -c "cd /prod && rm -rf ."` reads as
    // `rm -rf .` with its position in the compound command alongside.
    const first = op.matches[0];
    const command = first ? first.simpleCommand.join(' ') : '(unknown)';
    const position = first && first.simpleCommandCount > 1
      ? ` (command ${first.simpleCommandIndex + 1} of ${first.simpleCommandCount})`
      : '';
    const wrappers = first && first.strippedWrappers.length > 0
      ? ` via ${first.strippedWrappers.join(' ')}`
      : '';
    return {
      severity: first?.severity ?? 'medium',
      wallTs: op.event.wallTs,
      command,
      position: position + wrappers,
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

  const byReason = (reason: GapPayload['reason']) =>
    timeline.gaps
      .filter((g) => (g.payload as GapPayload).reason === reason)
      .map((g) => ({ wallTs: g.wallTs, detail: (g.payload as GapPayload).detail, id: g.id }));
  const lostOutcomes = byReason('intent_without_effect');
  const unwitnessedExecves = byReason('kernel_execve_without_hook');

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
    capturesAttributed: options.capturesAttributed ?? 0,
    capturesExcluded: options.capturesExcluded ?? 0,
    sections,
    destructiveOps,
    gaps,
    lostOutcomes,
    lostOutcomeCount: lostOutcomes.length,
    unwitnessedExecves,
    unwitnessedExecveCount: unwitnessedExecves.length,
  };
}

// ── Main renderers ──────────────────────────────────────────────────


/**
 * Render the narrative as Markdown.
 * Deterministic: same timeline + same options → same output.
 */
export function renderMarkdown(
  timeline: ReconstructionTimeline,
  options: RenderOptions
): string {
  return renderMarkdownDocument(buildNarrativeData(timeline, options));
}

/**
 * Render the narrative as HTML.
 * Deterministic: same timeline + same options → same output.
 */
export function renderHtml(
  timeline: ReconstructionTimeline,
  options: RenderOptions
): string {
  return renderHtmlDocument(buildNarrativeData(timeline, options));
}

export type { NarrativeData } from './narrative-data.js';
