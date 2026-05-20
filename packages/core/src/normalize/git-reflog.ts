// packages/core/src/normalize/git-reflog.ts
//
// Normalize git reflog output into DEPOSE Event[].
//
// Git reflog records every change to branch tips and HEAD.
// Each entry looks like:
//
//   abc1234 (HEAD -> main) commit: Fix typo in README
//   def5678 (HEAD -> main) merge feature-branch: Fast-forward
//   ghi9012 (HEAD@{1}) reset: moving to abc1234
//
// This normalizer emits:
//   - process_spawn events for git operations
//   - gap events for reflog changes without a matching command
//
// See BUILD_PLAN.md §4.1 for the Event schema.

import type {
  AgentId,
  Event,
  ProcessSpawnPayload,
  GapPayload,
} from '../events/schema.js';
import { ulidFromTime } from '../events/ids.js';
import { sha256 } from '../events/canonical-json.js';

// ── Reflog line shape ────────────────────────────────────────────────

/**
 * Represents a single git reflog entry.
 */
export interface GitReflogEntry {
  /** Full commit hash (40-char hex) */
  commitHash: string;
  /** Short commit hash (7-char hex) */
  shortHash: string;
  /** Ref name (e.g., "HEAD -> main", "refs/heads/feature") */
  ref: string;
  /** Action type (commit, merge, reset, rebase, cherry-pick, amend) */
  action: string;
  /** Action description (e.g., "Fix typo in README") */
  description: string;
  /** Full reflog message (before parsing) */
  rawMessage: string;
  /** Timestamp (null if not available — depends on git config) */
  timestamp: string | null;
  /** Author (null if not available) */
  author: string | null;
}

// ── Parser ───────────────────────────────────────────────────────────

/**
 * Parse git reflog output (from `git reflog` or `git reflog show`).
 *
 * Supports standard reflog format:
 *   abc1234 (HEAD -> main) commit: Fix typo
 *   def5678 (HEAD -> main) merge feature: Fast-forward
 *   ghi9012 (HEAD@{1}) reset: moving to abc1234
 *
 * Also supports timestamped reflog (git reflog show --format=...):
 *   abc1234 (HEAD -> main) commit: Fix typo  2025-05-18 15:30:00 +0000
 */
export function parseGitReflog(content: string): GitReflogEntry[] {
  const lines = content.split('\n').filter((l) => l.trim().length > 0);
  const entries: GitReflogEntry[] = [];

  // Pattern: HASH (REF) ACTION: DESCRIPTION [TIMESTAMP]
  // The reflog format is:
  //   <hash> (<ref>) <action>: <description> [<timestamp>]
  const reflogPattern =
    /^([0-9a-f]{7,40})\s+\(([^)]+)\)\s+(\w+):\s+(.+?)(?:\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}))?\s*$/;

  for (const line of lines) {
    const trimmed = line.trim();
    const match = trimmed.match(reflogPattern);

    if (match) {
      const [, commitHash, ref, action, description, timestampStr] = match;
      if (!commitHash) continue;
      const shortHash = commitHash.slice(0, 7);
      const timestamp = timestampStr ? new Date(timestampStr).toISOString() : '';

      entries.push({
        commitHash,
        shortHash,
        ref: ref ?? '',
        action: action ?? '',
        description: description ?? '',
        rawMessage: trimmed,
        timestamp,
        author: '',
      });
    } else {
      // Try a simpler format (no ref, no timestamp)
      //   abc1234 commit: Fix typo
      const simplePattern = /^([0-9a-f]{7,40})\s+(\w+):\s+(.+)$/;
      const simpleMatch = trimmed.match(simplePattern);
      if (simpleMatch) {
        const [, commitHash, action, description] = simpleMatch;
        if (commitHash === undefined) continue;
        const shortHash = commitHash.slice(0, 7);
        entries.push({
          commitHash,
          shortHash,
          ref: '',
          action: action || '',
          description: description || '',
          rawMessage: trimmed,
          timestamp: null,
          author: '',
        });
      }
      // Lines that don't match any pattern are silently skipped
      // (they may be formatting artifacts or empty reflog entries)
    }
  }

  return entries;
}

// ── Event generation ─────────────────────────────────────────────────

/**
 * Convert git reflog entries into DEPOSE Events.
 *
 * Each reflog entry becomes:
 *   1. A process_spawn event (the git command that caused the reflog change)
 *   2. A gap event (because we don't know the exact command —
 *      reflog records the RESULT, not the command)
 *
 * This is intentional: reflog changes without a captured command
 * are gaps per BUILD_PLAN.md §8.8 ("show the gap").
 */
export function reflogToEvents(
  entries: GitReflogEntry[],
  options: {
    sessionId: string;
    agentId: AgentId;
    monoOffset?: number;
  }
): { events: Event[]; warnings: string[] } {
  const { sessionId, agentId, monoOffset = 0 } = options;
  const events: Event[] = [];
  const warnings: string[] = [];
  let mono = monoOffset;

  for (const entry of entries) {
    const wallTs = entry.timestamp || new Date().toISOString();
    const monoNs = mono++;

    // Process spawn event (best-effort reconstruction)
    const spawnPayload: ProcessSpawnPayload = {
      pid: 0,
      ppid: 0,
      exe: 'git',
      argv: ['git', entry.action, ...entry.description.split(' ')],
      cwd: process.cwd(),
    };
    const spawnEvent = buildEvent({
      sessionId,
      agentId,
      type: 'process_spawn',
      parentEventId: null,
      monoNs,
      wallTs,
      payload: spawnPayload,
    });
    events.push(spawnEvent);

    // Gap event: reflog change without a captured command
    const gapPayload: GapPayload = {
      reason: 'reflog_change_without_command' as const,
      affectedEventIds: [spawnEvent.id],
      detail: `Git reflog shows ${entry.action}: ${entry.description} (commit ${entry.shortHash}) but no shell command was captured. This could be a git command run outside the shim/hook, or a git hook that modified the reflog.`,
    };
    const gapEvent = buildEvent({
      sessionId,
      agentId,
      type: 'gap',
      parentEventId: spawnEvent.id,
      monoNs: mono++,
      wallTs,
      payload: gapPayload,
    });
    events.push(gapEvent);
  }

  return { events, warnings };
}

// ── Event builder (shared) ───────────────────────────────────────────

interface BuildEventParams {
  sessionId: string;
  agentId: AgentId;
  type: string;
  parentEventId: string | null;
  monoNs: number;
  wallTs: string;
  payload: unknown;
}

function buildEvent(params: BuildEventParams): Event {
  const { sessionId, agentId, type, parentEventId, monoNs, wallTs, payload } = params;
  const id = ulidFromTime(new Date(wallTs).getTime());
  const payloadHash = sha256(payload);
  return {
    id,
    wallTs,
    monoNs,
    sessionId,
    agentId,
    parentEventId,
    type: type as Event['type'],
    payload,
    payloadHash,
  } as Event;
}
