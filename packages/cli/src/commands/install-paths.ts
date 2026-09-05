// packages/cli/src/commands/install-paths.ts
//
// Shared locations and binary resolution for active-capture installation:
// the shim allowlist, the default bin and capture directories, and how the
// `depose-hook` entrypoint is found across dev, global, and packed layouts.

import { existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';

// ── Constants ────────────────────────────────────────────────────────

/** Default shim binary allowlist (docs/shim-installation.md) */
export const SHIM_ALLOWLIST = [
  'terraform',
  'aws',
  'gh',
  'kubectl',
  'psql',
  'gcloud',
  'railway',
  'rm',
] as const;

/** Default DEPOSE bin directory for shim symlinks */
export const DEFAULT_DEPOSE_BIN_DIR = join(homedir(), '.depose', 'bin');

/** Default capture directory */
export const DEFAULT_CAPTURE_DIR = join(homedir(), '.depose', 'captures');

/**
 * Build a hook command string for Claude Code settings.json.
 * Resolves an absolute path to the depose-hook binary so the setting
 * survives PATH changes and works regardless of shell configuration.
 *
 * @param half - Which half of the tool call the entry captures.
 * @returns The quoted command line for settings.json.
 */
export function buildHookCommand(half: 'pre' | 'post' = 'pre'): string {
  const hookBinary = resolveHookBinary();
  const binPath = hookBinary ?? 'depose-hook';
  return `"${binPath}" ${half === 'post' ? 'posttooluse' : 'pretooluse'}`;
}

/**
 * Pre-computed hook command using the resolved binary path.
 * For backward compatibility; prefer buildHookCommand() for dynamic resolution.
 */
export const HOOK_COMMAND = buildHookCommand();

/**
 * Resolve the absolute path to the depose-hook binary.
 *
 * The hook binary is `depose-hook`, a separate entrypoint from `depose`.
 * Two lookup paths:
 *   1. Next to the @depose/cli package itself (anchored via import.meta.url).
 *      This is the canonical path and works whether depose was installed
 *      globally, from a workspace, or run from the repo.
 *   2. Next to the entrypoint script (process.argv[1]), covers the case
 *      where the caller already *is* depose-hook.
 */
export function resolveHookBinary(): string | null {
  // 1. Anchor on this module's own location.
  //    dist/commands/install.js → ../../bin/depose-hook
  try {
    const here = fileURLToPath(import.meta.url);
    const pkgRoot = resolve(dirname(here), '..', '..');
    const hookCandidate = join(pkgRoot, 'bin', 'depose-hook');
    if (existsSync(hookCandidate)) return hookCandidate;
  } catch {
    // import.meta.url may be unavailable in some contexts; fall through.
  }

  // 2. Self-install case: caller is depose-hook itself.
  const arg0 = process.argv[1];
  if (arg0) {
    const resolved = resolve(arg0);
    if (resolved.endsWith('/depose-hook') && existsSync(resolved)) {
      return resolved;
    }
    const binDir = dirname(resolved);
    const sibling = join(binDir, 'depose-hook');
    if (existsSync(sibling)) return sibling;
  }

  return null;
}

/**
 * Check that the hook binary exists before attempting installation.
 * Returns the resolved absolute path, or throws if the binary cannot be found.
 */
export function requireHookBinary(): string {
  const binPath = resolveHookBinary();
  if (!binPath) {
    throw new Error(
      'Cannot locate depose-hook binary. Ensure @depose/cli is installed correctly.'
    );
  }
  return binPath;
}

