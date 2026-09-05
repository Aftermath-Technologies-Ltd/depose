// packages/core/src/normalize/codex.ts
//
// Normalize an OpenAI Codex CLI rollout log into DEPOSE Event[].
//
// Codex writes one JSONL file per session under
// $CODEX_HOME/sessions/YYYY/MM/DD/rollout-<timestamp>-<id>.jsonl. The
// format has changed at least once, so this normalizer detects which one
// it is reading and records the answer rather than guessing:
//
//   codex-rollout-v2  every line is {timestamp, type, payload}; the
//                     conversation is in `response_item` payloads and the
//                     session facts in a `session_meta` payload. This is
//                     what current Codex writes.
//   codex-rollout-v1  the first line is a bare session-meta object and
//                     every later line is a bare response item, with no
//                     envelope and no per-line timestamp.
//
// The detected format travels into the bundle
// (`manifest.session.sourceFormat`), because a reader needs to know which
// grammar produced the timeline before they can argue about what it
// means. Lines that do not parse become warnings and, downstream, gap
// events; nothing is dropped silently
// (docs/bundle-format.md#producer-invariants).

import type { AgentId, Event } from '../events/schema.js';
import { generateUlid } from '../events/ids.js';
import {
  detectCodexFormat,
  readEnvelope,
  readSessionMeta,
  type CodexFormat,
  type CodexResponseItem,
} from './codex-types.js';
import { itemToEvents } from './codex-items.js';

export { CODEX_FORMATS, detectCodexFormat } from './codex-types.js';
export type { CodexFormat } from './codex-types.js';

/** Options for the Codex normalizer. */
export interface CodexNormalizeOptions {
  /** Session ID (ULID). Generated when absent. */
  sessionId?: string;
  /** Agent ID. Defaults to 'codex'. */
  agentId?: AgentId;
  /** Fallback session start when the log carries no usable timestamp. */
  sessionStart?: string;
  /** Monotonic counter for ordering events inside one millisecond. */
  monoOffset?: number;
}

/** What the Codex normalizer produced. */
export interface CodexNormalizationResult {
  events: Event[];
  warnings: string[];
  /** DEPOSE's internal session id. */
  sessionId: string;
  /** Codex's own session id, used to scope capture records. Null when absent. */
  agentSessionId: string | null;
  /** Working directories the session declared, in first-seen order. */
  cwds: string[];
  /** Which rollout grammar this file turned out to be. */
  sourceFormat: CodexFormat;
  /** Codex CLI version from session_meta, when the log records one. */
  cliVersion: string | null;
}

/**
 * Parse a Codex CLI rollout JSONL file into Events.
 *
 * @param jsonl - The rollout file's contents.
 * @param options - Session id, agent id, and ordering.
 * @returns The events, the detected format, and everything needed to
 *   scope capture records to this session.
 */
export function normalizeCodexJsonl(
  jsonl: string,
  options: CodexNormalizeOptions = {}
): CodexNormalizationResult {
  const {
    sessionId = generateUlid(),
    agentId = 'codex',
    sessionStart = new Date().toISOString(),
    monoOffset = 0,
  } = options;

  const lines = jsonl.split('\n').filter((line) => line.trim().length > 0);
  const parsed: unknown[] = [];
  const warnings: string[] = [];
  for (const [index, line] of lines.entries()) {
    try {
      parsed.push(JSON.parse(line));
    } catch (err) {
      warnings.push(
        `Codex rollout line ${index + 1}: unparseable JSON (${err instanceof Error ? err.message : String(err)})`
      );
      parsed.push(null);
    }
  }

  const sourceFormat = detectCodexFormat(parsed);
  const meta = readSessionMeta(parsed, sourceFormat);
  const cwds: string[] = [];
  if (meta.cwd) cwds.push(meta.cwd);

  const events: Event[] = [];
  let mono = monoOffset;
  let lastParentId: string | null = null;
  let wallTs = meta.startedAt ?? sessionStart;

  for (const [index, value] of parsed.entries()) {
    if (value === null) continue;
    const envelope = readEnvelope(value, sourceFormat);
    if (!envelope) {
      warnings.push(`Codex rollout line ${index + 1}: unrecognized shape, no type field`);
      continue;
    }
    if (envelope.timestamp) wallTs = envelope.timestamp;
    if (envelope.cwd && !cwds.includes(envelope.cwd)) cwds.push(envelope.cwd);
    if (!envelope.item) continue;

    const produced = itemToEvents(envelope.item as CodexResponseItem, {
      sessionId,
      agentId,
      wallTs,
      monoNs: mono,
      lastParentId,
      lineNumber: index + 1,
    });
    warnings.push(...produced.warnings);
    for (const event of produced.events) {
      events.push(event);
      mono++;
      if (event.type === 'prompt' || event.type === 'assistant_message') {
        lastParentId = event.id;
      }
    }
  }

  if (events.length === 0 && lines.length > 0 && warnings.length === 0) {
    warnings.push(
      `Codex rollout has ${lines.length} line(s) and none carried a conversation turn; ` +
        `detected format ${sourceFormat}. If this is a newer Codex, the format has drifted again.`
    );
  }

  return {
    events,
    warnings,
    sessionId,
    agentSessionId: meta.agentSessionId,
    cwds,
    sourceFormat,
    cliVersion: meta.cliVersion,
  };
}
