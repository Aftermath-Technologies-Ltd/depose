// packages/capture-claude/src/file-hash.ts
//
// File hashing for pre-execution capture.
// Hashes file-path arguments referenced in tool input.
//
// See BUILD_PLAN.md §4.2 (ShellCommandPrePayload.fileArgs).

import { createHash } from 'node:crypto';
import { existsSync, statSync, readFileSync } from 'node:fs';

/**
 * Compute SHA-256 of a file (hex digest).
 * Returns null if the file doesn't exist or can't be read.
 */
export function hashFile(path: string): string | null {
  if (!existsSync(path)) return null;
  try {
    const content = readFileSync(path);
    return createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
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
 * Returns an array of FileArg descriptors.
 */
export function hashFileArgs(
  toolName: string,
  toolInput: Record<string, unknown>
): FileArg[] {
  const paths = extractFilePaths(toolName, toolInput);
  return paths.map((path) => ({
    path,
    preSha256: hashFile(path),
    sizeBytes: fileSize(path),
  }));
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
 * This is best-effort; the shim is best-effort per BUILD_PLAN.md §6 (Phase 3).
 */
function extractPathsFromCommand(cmd: string): string[] {
  const paths: string[] = [];
  // Match absolute paths and relative paths starting with ./ or ../
  const pathRegex = /(?:^|\s)(\.{0,2}\/[^\s;|&<>()'"`$]+)|(?:^|\s)(\/[^\s;|&<>()'"`$]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pathRegex.exec(cmd)) !== null) {
    const p = match[1] || match[2];
    if (p && existsSync(p)) {
      paths.push(p);
    }
  }
  return paths;
}