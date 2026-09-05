// packages/core/src/normalize/claude-code.ts
//
// Normalize Claude Code JSONL session transcripts into DEPOSE Event[].
//
// Claude Code (Claude CLI) writes a JSONL file per session (typically
// in ~/.claude/CLAUDE_JSON_LOG or a project-local path). Each line
// is a JSON object representing a conversation turn.
//
// Two formats are supported, each with its own module:
//   1. Flat format (legacy/synthetic), claude-code-flat.ts
//   2. Real session format, claude-code-real.ts
//
// This file is the entry point: it walks the file, collects session-level
// facts (start time, the agent's own session id, working directories), and
// delegates each line to the format-specific normalizer.
//
// See docs/bundle-format.md#event-schema. Scope: passive reconstruction only.

import type { Event } from '../events/schema.js';
import { generateUlid } from '../events/ids.js';
import type {
  ClaudeCodeLine,
  ClaudeCodeNormalizeOptions,
  ClaudeCodeNormalizationResult,
} from './claude-code-types.js';
import { normalizeClaudeCodeLine } from './claude-code-flat.js';
import { buildEvent } from './claude-code-build-event.js';

export type {
  ClaudeCodeLine,
  ContentBlock,
  ClaudeCodeNormalizeOptions,
  ClaudeCodeNormalizationResult,
} from './claude-code-types.js';

// ── Main normalizer ──────────────────────────────────────────────────

/**
 * Parse a Claude Code JSONL session file (as a string) into Events.
 *
 * Each line is parsed as JSON. Lines that fail to parse are skipped
 * and recorded as warnings (not errors; we never silently drop data
 * per docs/bundle-format.md#producer-invariants).
 *
 * Events are emitted in order:
 *   1. prompt (from "user" lines)
 *   2. assistant_message (from "assistant" lines)
 *   3. tool_call_intent (extracted from assistant tool_calls or tool_use blocks)
 *   4. tool_result (from "tool" lines or tool_result content blocks)
 *   5. file_diff (from "file_edit" lines)
 *   6. error (from "error" lines)
 *   7. gap (for unrecognized types or missing correlations)
 */
export function normalizeClaudeCodeJsonl(
  jsonl: string,
  options: ClaudeCodeNormalizeOptions = {}
): ClaudeCodeNormalizationResult {
  const {
    sessionId = generateUlid(),
    agentId = 'claude-code',
    sessionStart = new Date().toISOString(),
    monoOffset = 0,
  } = options;

  const lines = jsonl.split('\n').filter((l) => l.trim().length > 0);
  const events: Event[] = [];
  const warnings: string[] = [];
  let mono = monoOffset;
  let lastParentId: string | null = null;
  let sessionStartTime = sessionStart;
  let agentSessionId: string | null = null;
  const cwdSet = new Set<string>();

  // First pass: establish session start, and collect the agent's own
  // session id and working directories. Both are needed to scope capture
  // records to this session; without them a bundle absorbs every capture
  // on the machine.
  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as ClaudeCodeLine;
      if (parsed.timestamp) {
        const ts = new Date(parsed.timestamp);
        if (!isNaN(ts.getTime()) && ts < new Date(sessionStartTime)) {
          sessionStartTime = parsed.timestamp;
        }
      }
      // Real sessions write `sessionId`; synthetic fixtures write
      // `session_id`. Accept both, first non-empty value wins.
      const lineSessionId = parsed.sessionId || parsed.session_id;
      if (agentSessionId === null && typeof lineSessionId === 'string' && lineSessionId) {
        agentSessionId = lineSessionId;
      }
      if (typeof parsed.cwd === 'string' && parsed.cwd) {
        cwdSet.add(parsed.cwd);
      }
    } catch {
      // Skip unparseable lines (will be caught in second pass too)
    }
  }

  // Second pass: normalize each line
  for (const line of lines) {
    let parsed: ClaudeCodeLine;
    try {
      parsed = JSON.parse(line) as ClaudeCodeLine;
    } catch {
      warnings.push(`Failed to parse JSONL line (not valid JSON): ${line.slice(0, 100)}`);
      // Emit a gap event for unparseable lines
      const gap: Event = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: lastParentId,
        monoNs: mono++,
        wallTs: sessionStartTime,
        payload: {
          reason: 'jsonl_line_unparseable' as const,
          affectedEventIds: [],
          detail: `Unparseable JSONL line: ${line.slice(0, 200)}`,
        },
      });
      events.push(gap);
      continue;
    }

    const lineTs = parsed.timestamp || sessionStartTime;
    const lineMono = mono++;

    try {
      const lineEvents = normalizeClaudeCodeLine(parsed, {
        sessionId,
        agentId,
        wallTs: lineTs,
        monoNs: lineMono,
        lastParentId,
      });
      events.push(...lineEvents);
      // Update parent for next iteration
      if (lineEvents.length > 0) {
        lastParentId = lineEvents[lineEvents.length - 1]?.id ?? lastParentId;
      }
    } catch (err) {
      const errorStr = err instanceof Error ? err.message : String(err);
      warnings.push(`Error normalizing line: ${errorStr}`);
      const gap: Event = buildEvent({
        sessionId,
        agentId,
        type: 'gap',
        parentEventId: lastParentId,
        monoNs: lineMono,
        wallTs: lineTs,
        payload: {
          reason: 'jsonl_line_unparseable' as const,
          affectedEventIds: [],
          detail: `Normalization error: ${errorStr}`,
        },
      });
      events.push(gap);
    }
  }

  return { events, warnings, sessionId, agentSessionId, cwds: Array.from(cwdSet) };
}

