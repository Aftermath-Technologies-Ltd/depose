// packages/core/src/normalize/codex-types.ts
//
// Reading a Codex rollout line without trusting it.
//
// The file comes off disk and its grammar has already changed once, so
// every accessor here narrows rather than casts, and format detection is
// a decision the normalizer records instead of an assumption it makes.

/** The rollout grammars this normalizer reads. */
export const CODEX_FORMATS = ['codex-rollout-v2', 'codex-rollout-v1'] as const;

/** One of the supported rollout grammars. */
export type CodexFormat = (typeof CODEX_FORMATS)[number];

/** A response item: one conversation turn, tool call, or tool output. */
export interface CodexResponseItem {
  type: string;
  role?: string;
  content?: unknown;
  name?: string;
  arguments?: string;
  call_id?: string;
  output?: unknown;
  [key: string]: unknown;
}

/** What one line contributed, after the envelope is stripped. */
export interface CodexEnvelope {
  /** ISO 8601 time, when the line carries one. */
  timestamp: string | null;
  /** Working directory, when the line declares one. */
  cwd: string | null;
  /** The response item to turn into events, or null for a non-conversation line. */
  item: CodexResponseItem | null;
}

/** Session-level facts, gathered from whichever line carries them. */
export interface CodexSessionMeta {
  agentSessionId: string | null;
  startedAt: string | null;
  cwd: string | null;
  cliVersion: string | null;
}

/**
 * Decide which rollout grammar a parsed file is written in.
 *
 * v2 wraps every line as `{timestamp, type, payload}`. v1 has no
 * envelope: the first line is a bare session-meta object and the rest are
 * bare response items. Detection looks for the envelope rather than for a
 * version field, because neither format carries one.
 *
 * @param lines - The parsed lines, with nulls where parsing failed.
 * @returns The detected format; v2 when the file is empty, since that is
 *   what current Codex writes.
 */
export function detectCodexFormat(lines: unknown[]): CodexFormat {
  for (const line of lines) {
    if (!isObject(line)) continue;
    if (typeof line['type'] === 'string' && isObject(line['payload'])) {
      return 'codex-rollout-v2';
    }
    if (typeof line['type'] === 'string' || typeof line['role'] === 'string' || 'instructions' in line) {
      return 'codex-rollout-v1';
    }
  }
  return 'codex-rollout-v2';
}

/**
 * Strip the envelope from one line.
 *
 * @param value - The parsed line.
 * @param format - The detected grammar.
 * @returns The timestamp, cwd, and response item the line carried, or
 *   null when the line has no recognizable shape at all.
 */
export function readEnvelope(value: unknown, format: CodexFormat): CodexEnvelope | null {
  if (!isObject(value)) return null;

  if (format === 'codex-rollout-v1') {
    // No envelope: the object either is a response item or is the
    // session-meta line, which contributes facts but no event.
    const timestamp = readTimestamp(value['timestamp']);
    const cwd = typeof value['cwd'] === 'string' ? value['cwd'] : null;
    if (typeof value['type'] === 'string' || typeof value['role'] === 'string') {
      return { timestamp, cwd, item: value as CodexResponseItem };
    }
    return { timestamp, cwd, item: null };
  }

  const type = value['type'];
  if (typeof type !== 'string') return null;
  const payload = isObject(value['payload']) ? value['payload'] : null;
  const timestamp = readTimestamp(value['timestamp']);
  const cwd = payload && typeof payload['cwd'] === 'string' ? payload['cwd'] : null;

  if (type === 'response_item' && payload) {
    return { timestamp, cwd, item: payload as CodexResponseItem };
  }
  // session_meta, turn_context, event_msg, and anything newer contribute
  // their time and cwd but no conversation turn. event_msg in particular
  // duplicates what response_item already carries, so taking it too would
  // double every assistant message in the timeline.
  return { timestamp, cwd, item: null };
}

/**
 * Gather the session-level facts from wherever this format keeps them.
 *
 * @param lines - The parsed lines.
 * @param format - The detected grammar.
 * @returns Codex's session id, start time, cwd, and CLI version, each
 *   null when the log does not record it.
 */
export function readSessionMeta(lines: unknown[], format: CodexFormat): CodexSessionMeta {
  const meta: CodexSessionMeta = { agentSessionId: null, startedAt: null, cwd: null, cliVersion: null };

  for (const line of lines) {
    if (!isObject(line)) continue;
    const body = format === 'codex-rollout-v2'
      ? (line['type'] === 'session_meta' && isObject(line['payload']) ? line['payload'] : null)
      : (typeof line['type'] === 'string' || typeof line['role'] === 'string' ? null : line);
    if (!body) continue;

    // Codex has written the id as `id` and as `session_id` across
    // versions; both mean the same thing to the capture scope.
    const id = body['id'] ?? body['session_id'];
    if (meta.agentSessionId === null && typeof id === 'string') meta.agentSessionId = id;
    if (meta.startedAt === null) meta.startedAt = readTimestamp(body['timestamp'] ?? line['timestamp']);
    if (meta.cwd === null && typeof body['cwd'] === 'string') meta.cwd = body['cwd'];
    const version = body['cli_version'] ?? body['cliVersion'];
    if (meta.cliVersion === null && typeof version === 'string') meta.cliVersion = version;
    break;
  }
  return meta;
}

/** ISO 8601 or null; an unparseable time is not a time. */
function readTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return new Date(parsed).toISOString();
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
