// packages/capture-claude/src/file-hash.ts
//
// File hashing for pre-execution capture.
// Hashes file-path arguments referenced in tool input.
//
// See docs/bundle-format.md#event-schema (ShellCommandPrePayload.fileArgs).
//
// F-16: Only destructive tools (Edit, Write, Bash with destructive
// commands) trigger file hashing. Non-destructive tools (Read, Glob,
// etc.) skip file hashing entirely and return an empty fileArgs[].
// A 100MB file size cap is enforced, files above the cap record
// preSha256: null with sizeBytes populated.

import { createHash } from 'node:crypto';
import { existsSync, statSync, openSync, readSync, closeSync } from 'node:fs';

// ── Constants ──────────────────────────────────────────────────────

/** Maximum file size to hash (100 MB). Above this, preSha256 is null. */
const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB

/** Read size per chunk when hashing. 1 MB is one page-cache readahead
 *  window on Linux and keeps the hook's resident set flat regardless of
 *  file size. */
const HASH_CHUNK_BYTES = 1024 * 1024;

/** Tool names that are always considered destructive (modify files). */
const DESTRUCTIVE_TOOL_NAMES = new Set(['Edit', 'Write', 'MultiEdit']);

/**
 * Bash sub-commands that are considered destructive.
 * A Bash invocation is destructive if the command string matches
 * any of these patterns (case-insensitive, anchored to the start
 * or after a pipe/redirect).
 */
const DESTRUCTIVE_BASH_PATTERNS: RegExp[] = [
  /\brm\s/i,
  /\bmv\s/i,
  /\bcp\s/i,
  /\bchmod\s/i,
  /\bchown\s/i,
  /\bdd\s/i,
  /\bmkfs/i,
  /\bformat\s/i,
  /\btruncate\s/i,
  /\bsed\s.*-i/i,
  /\bsed\s.*--in-place/i,
  /\bperl\s.*-i/i,
  /\bruby\s.*-i/i,
];

// ── shouldHashForTool ──────────────────────────────────────────────

/**
 * Determine whether a tool invocation should trigger file hashing.
 *
 * Only destructive tools (Edit, Write, MultiEdit, or Bash with
 * commands matching destructive patterns) trigger file hashing.
 * Non-destructive tools like Read, Glob, LS, etc. skip hashing
 * entirely and return an empty fileArgs[].
 *
 * This avoids unnecessary I/O for read-only operations and keeps
 * capture lightweight for the common case.
 */
export function shouldHashForTool(
  toolName: string,
  toolInput: Record<string, unknown>
): boolean {
  // Edit, Write, and MultiEdit are always destructive
  if (DESTRUCTIVE_TOOL_NAMES.has(toolName)) {
    return true;
  }

  // Bash commands are conditionally destructive
  if (toolName === 'Bash') {
    const cmd = toolInput['command'];
    if (typeof cmd === 'string') {
      return DESTRUCTIVE_BASH_PATTERNS.some((pattern) => pattern.test(cmd));
    }
    // Bash without a command string, assume destructive to be safe
    return true;
  }

  // All other tool names are non-destructive (Read, Glob, LS, etc.)
  return false;
}

// ── Hashing ────────────────────────────────────────────────────────

/**
 * Compute SHA-256 of a file (hex digest).
 * Returns null if the file doesn't exist or can't be read,
 * or if the file exceeds MAX_FILE_SIZE_BYTES (100MB).
 */
export function hashFile(path: string): string | null {
  if (!existsSync(path)) return null;
  let fd: number | null = null;
  try {
    const stat = statSync(path);
    if (stat.size > MAX_FILE_SIZE_BYTES) return null;
    // Streamed in fixed-size chunks rather than read whole. The hook runs
    // in the agent's critical path, and a readFileSync of a 100 MB file
    // holds 100 MB resident and stalls the tool call for as long as the
    // read takes; a chunked read holds one buffer and starts hashing on
    // the first block. Synchronous by necessity: the hook must finish
    // before it returns, so there is no event loop to yield to.
    fd = openSync(path, 'r');
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
    for (;;) {
      const read = readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
    }
    return hash.digest('hex');
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // The descriptor is going away with the process either way.
      }
    }
  }
}

/**
 * Get file size in bytes.
 * Returns null if the file doesn't exist or can't be stat'd.
 */
export function fileSize(path: string): number | null {
  try {
    const stat = statSync(path);
    return stat.size;
  } catch {
    return null;
  }
}

/**
 * A file argument descriptor for ShellCommandPrePayload.fileArgs.
 */
export interface FileArg {
  path: string;
  preSha256: string | null;
  sizeBytes: number | null;
}

/**
 * Hash all file-path arguments found in tool input.
 *
 * For Bash tool: extracts paths from the command string heuristically.
 * For Edit/Write tools: uses the file_path field directly.
 * For MultiEdit: uses the file_path from each edit.
 *
 * If shouldHashForTool() returns false for this tool, returns []
 * immediately without any file I/O.
 *
 * Files exceeding 100MB have preSha256 set to null and sizeBytes
 * populated from stat().
 *
 * Returns an array of FileArg descriptors.
 */
export function hashFileArgs(
  toolName: string,
  toolInput: Record<string, unknown>
): FileArg[] {
  // Skip file hashing entirely for non-destructive tools
  if (!shouldHashForTool(toolName, toolInput)) {
    return [];
  }

  const paths = extractFilePaths(toolName, toolInput);
  return paths.map((path) => {
    const size = fileSize(path);
    const preSha256 = hashFile(path);
    return {
      path,
      preSha256,
      sizeBytes: size,
    };
  });
}

/**
 * Extract file paths from tool input based on tool type.
 * Returns deduplicated paths.
 */
function extractFilePaths(
  toolName: string,
  toolInput: Record<string, unknown>
): string[] {
  const paths: string[] = [];

  if (toolName === 'Edit' || toolName === 'Write') {
    const fp = toolInput['file_path'];
    if (typeof fp === 'string') paths.push(fp);
  } else if (toolName === 'MultiEdit') {
    const edits = toolInput['edits'];
    if (Array.isArray(edits)) {
      for (const edit of edits) {
        if (typeof edit === 'object' && edit !== null && 'file_path' in edit) {
          const fp = (edit as Record<string, unknown>)['file_path'];
          if (typeof fp === 'string') paths.push(fp);
        }
      }
    }
    // MultiEdit may also have a top-level file_path
    const fp = toolInput['file_path'];
    if (typeof fp === 'string') paths.push(fp);
  } else if (toolName === 'Bash') {
    // Heuristic: extract paths from Bash command string
    const cmd = toolInput['command'];
    if (typeof cmd === 'string') {
      const extracted = extractPathsFromCommand(cmd);
      paths.push(...extracted);
    }
  }

  // Deduplicate
  return Array.from(new Set(paths));
}

/**
 * Heuristic extraction of file paths from a shell command string.
 * Looks for paths starting with / or ./ or patterns that look like file arguments.
 * This is best-effort, like the shim (docs/capture-coverage.md).
 */
function extractPathsFromCommand(cmd: string): string[] {
  const paths: string[] = [];
  // Match absolute paths and relative paths starting with ./ or ../
  // Character class excludes common shell metacharacters: whitespace, semicolon,
  // pipe, ampersand, angle brackets, parentheses, quotes, backtick, dollar.
  const backtick = '\u0060'; // backtick character, escaped to avoid template literal issues
  const pathRegex = new RegExp(
    '(?:^|\\s)(\\.{0,2}/[^\\s;|&<>()\'"' + backtick + '$]+)|(?:^|\\s)(/[^\\s;|&<>()\'"' + backtick + '$]+)',
    'g'
  );
  let match: RegExpExecArray | null;
  while ((match = pathRegex.exec(cmd)) !== null) {
    const p = match[1] || match[2];
    if (p && existsSync(p)) {
      paths.push(p);
    }
  }
  return paths;
}