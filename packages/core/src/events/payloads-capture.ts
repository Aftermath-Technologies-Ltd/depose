// packages/core/src/events/payloads-capture.ts
//
// Payload shapes written by the capture layer rather than read out of an
// agent's own logs: the pre-execution record, the post-execution effect
// that closes it, kernel-witnessed process spawns, and the record the
// hook writes when it could not capture at all.
//
// The intent and effect halves are a signed pair. The effect carries the
// intent's event id in its payload, which is hashed and therefore signed.
// The intent cannot carry the effect's id (it does not exist yet), so that
// direction lives in the event's `correlation` block, outside payloadHash
// but still covered by the signed files map over events.jsonl.
// See docs/bundle-format.md#intent-and-effect.

/**
 * Represents a shell command before execution (pre-execution capture).
 * Source is either the Claude Code PreToolUse hook or the shell shim.
 *
 * This is the v2 shape, which is what enters a bundle. v1 records on
 * disk carry neither `capturedAt` nor `sessionId`; normalizeCaptureRecords
 * upgrades them on read (deriving the time from the ULID filename) so
 * everything downstream sees one shape.
 *
 * v1 recorded no capture time at all, which forced the normalizer to
 * stamp events with the bundle production time. That put every capture
 * event minutes to months away from the command it described, so the
 * plus or minus 5s correlation window in mergeEvents could never match
 * and active capture linked nothing in real post-incident use.
 */
export interface ShellCommandPrePayload {
  argv: string[];
  cwd: string;
  envHash: string;
  envSubset: Record<string, string>;
  ttyId: string | null;
  user: string;
  hostname: string;
  parentProcessTree: ProcessNode[];
  fileArgs: Array<{
    path: string;
    preSha256: string | null;
    sizeBytes: number | null;
  }>;
  source: 'claude-pretooluse' | 'shell-shim' | 'reconstructed';
  captureSchemaVersion: 1 | 2 | 3;
  /**
   * SHA-256 of the canonical JSON of the tool input. Both hook halves
   * compute it the same way, so it is the fallback key when the pending
   * marker that carries the intent's event id is lost. Absent on records
   * written before the effect half existed.
   */
  inputHash?: string;
  /**
   * ISO 8601 time the capture was taken, not the time the bundle was
   * produced. Added in v2.
   */
  capturedAt: string;
  /**
   * Provenance of `capturedAt`. A derived or reconstructed time is weaker
   * evidence than a recorded one, and a bundle must never present them as
   * equal.
   *
   *   recorded            written by the hook or shim at capture time
   *   derived-from-mtime  v1 record, time taken from the file's mtime
   *   reconstructed       no capture happened; time comes from the
   *                       session log line this payload was rebuilt from
   */
  capturedAtSource: 'recorded' | 'derived-from-mtime' | 'reconstructed';
  /**
   * Agent session this capture belongs to, used to scope captures to the
   * session being reconstructed. Null for shell-shim records, which have
   * no agent session, and for upgraded v1 records, which predate the field.
   */
  sessionId: string | null;
}

/**
 * Represents a shell command after execution (post-execution capture from shim).
 */
export interface ShellCommandPostPayload {
  exitCode: number;
  durationMs: number;
  stdoutHash: string;
  stderrHash: string;
  signalReceived: string | null;
}

/**
 * Represents a process spawn (detected from shell history or shim).
 */
export interface ProcessSpawnPayload {
  pid: number;
  ppid: number;
  exe: string;
  argv: string[];
  cwd: string;
  /** Kernel comm (first 15 bytes of the executable name). Kernel source only. */
  comm?: string;
  /** Pid chain from the process up towards pid 1, nearest ancestor first. */
  ancestry?: number[];
  /** CLOCK_MONOTONIC nanoseconds at exec, as a decimal string. Kernel source only. */
  monoNs?: string;
  /**
   * Where the record came from. `kernel` means an eBPF execve probe saw it,
   * which is evidence independent of anything the agent reports.
   */
  source?: 'kernel' | 'reconstructed';
  /** Hook intent this execve was correlated to, or null when unwitnessed. */
  matchedIntentEventId?: string | null;
}

/**
 * The capture hook hit an exception and could not write a capture record.
 *
 * Written by the hook itself before it exits 0, so a lost capture leaves a
 * trace instead of a clean-looking timeline. The merger turns each one into
 * a `gap` event with reason `capture_failed`.
 */
export interface CaptureFailedPayload {
  /** Discriminator so the capture-store reader can tell it from a command record. */
  kind: 'capture_failed';
  /** Hook phase that threw (read-input, parse-input, env, file-hash, process-tree, write-record). */
  phase: string;
  /** Error constructor name, e.g. "TypeError" or "SyntaxError". */
  errorClass: string;
  /** First line of the error message, control characters stripped, capped in length. */
  message: string;
  /** process.hrtime.bigint() at failure, as a decimal string. */
  monoNs: string;
  /** ISO 8601 time the failure was recorded. */
  capturedAt: string;
  /** Agent session the hook was serving, when the input got far enough to know it. */
  sessionId: string | null;
  /** Tool the hook was capturing, when known. */
  toolName: string | null;
  /** Which collector failed. */
  source: 'claude-pretooluse' | 'claude-posttooluse' | 'kernel';
  captureSchemaVersion: 3;
}

/**
 * Represents a process tree node (used in ShellCommandPrePayload.parentProcessTree).
 */
export interface ProcessNode {
  pid: number;
  ppid: number;
  exe: string;
  argv0: string;
}


/**
 * Per-file outcome recorded by the post-execution half of a tool call.
 *
 * `preSha256` is copied from the intent record so the pair can be read on
 * its own; `postSha256` is hashed after the tool returned.
 */
export interface FileEffect {
  path: string;
  /** Hash the intent recorded before the call, or null if the intent is lost. */
  preSha256: string | null;
  /** Hash after the call, or null if the path no longer exists. */
  postSha256: string | null;
  /** Size after the call, or null if the path no longer exists. */
  sizeBytes: number | null;
  change: 'created' | 'modified' | 'deleted' | 'unchanged';
}

/**
 * The post-execution half of a tool call: what actually happened to the
 * files the intent named, and how the call ended.
 *
 * Written by the Claude Code PostToolUse hook. `intentEventId` is the id
 * of the `shell_command_pre` event the matching PreToolUse hook wrote, and
 * it is inside the payload, so it is hashed into payloadHash and covered
 * by the signature. `inputHash` is the fallback correlation key for the
 * case where the pending marker was lost between the two hooks.
 */
export interface ToolCallEffectPayload {
  /** Discriminator so the capture-store reader can tell it from other records. */
  kind: 'effect';
  toolName: string;
  cwd: string;
  /** Exit status when the tool reports one; null for tools that do not. */
  exitCode: number | null;
  durationMs: number | null;
  /** Event id of the intent this effect closes, or null when it was lost. */
  intentEventId: string | null;
  /**
   * Where `intentEventId` came from. `recorded` means the PostToolUse hook
   * read it from the pending marker the PreToolUse hook left; `correlated`
   * means the merge matched on `inputHash` and a time window, which is a
   * weaker claim; `none` means no intent was found at all.
   */
  intentEventIdSource: 'recorded' | 'correlated' | 'none';
  /** SHA-256 of the canonical JSON of the tool input, both hooks compute it the same way. */
  inputHash: string;
  files: FileEffect[];
  source: 'claude-posttooluse';
  captureSchemaVersion: 3;
  /** ISO 8601 time the effect was captured. */
  capturedAt: string;
  capturedAtSource: 'recorded' | 'reconstructed';
  /** process.hrtime.bigint() at capture, as a decimal string. */
  monoNs: string;
  sessionId: string | null;
}

/**
 * A kernel-witnessed execve, written by the optional eBPF collector.
 *
 * This is the on-disk record shape; the normalizer turns it into a
 * `process_spawn` event tagged `source: kernel`. See
 * docs/bundle-format.md#kernel-witnessed-execve.
 */
export interface ExecveRecordPayload {
  /** Discriminator so the capture-store reader can tell it from other records. */
  kind: 'execve';
  pid: number;
  ppid: number;
  /** Pid chain from ppid up towards pid 1, nearest ancestor first. */
  ancestry: number[];
  comm: string;
  /** Resolved executable path, or the filename the kernel reported. */
  exe: string;
  argv: string[];
  cwd: string;
  /** CLOCK_MONOTONIC nanoseconds at exec, as a decimal string. */
  monoNs: string;
  capturedAt: string;
  sessionId: string | null;
  source: 'kernel';
  captureSchemaVersion: 3;
}
