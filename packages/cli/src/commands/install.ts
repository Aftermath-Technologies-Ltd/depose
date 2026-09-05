// packages/cli/src/commands/install.ts
//
// `depose install | uninstall --claude | --shell`, Phase 3 active capture.
//
// --claude: writes the PreToolUse hook entry into ~/.claude/settings.json
//          (or project .claude/settings.json) and creates $DEPOSE_CAPTURE_DIR.
// --shell: installs shim entries to a configurable PATH-preceding directory
//          (default ~/.depose/bin) for an allowlist of destructive binaries.
//
// Install lives in install-claude.ts and install-shell.ts; shared paths and
// binary resolution in install-paths.ts. This file holds uninstall and
// re-exports the surface the CLI wires up.
//
// See docs/hook-installation.md and docs/shim-installation.md.

import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { SHIM_ALLOWLIST, DEFAULT_DEPOSE_BIN_DIR } from './install-paths.js';

export {
  SHIM_ALLOWLIST,
  DEFAULT_DEPOSE_BIN_DIR,
  DEFAULT_CAPTURE_DIR,
  HOOK_COMMAND,
  buildHookCommand,
  resolveHookBinary,
  requireHookBinary,
} from './install-paths.js';
export { installClaudeHook, type InstallClaudeOptions } from './install-claude.js';
export { installShellShims, type InstallShellOptions } from './install-shell.js';

// ── Uninstall ───────────────────────────────────────────────────────

/**
 * Remove the PreToolUse hook from Claude Code settings.json.
 * Restores from backup if available.
 */
export function uninstallClaudeHook(
  options: { project?: boolean; projectRoot?: string } = {}
): { removed: boolean; restored: boolean } {
  const settingsPath = options.project
    ? join(options.projectRoot || process.cwd(), '.claude', 'settings.json')
    : join(homedir(), '.claude', 'settings.json');

  if (!existsSync(settingsPath)) {
    return { removed: false, restored: false };
  }

  let settings: Record<string, unknown>;
  try {
    const content = readFileSync(settingsPath, 'utf-8');
    settings = JSON.parse(content);
  } catch {
    return { removed: false, restored: false };
  }

  // Remove depose hook entries
  const hooks = settings['hooks'] as Record<string, unknown[]> | undefined;
  if (hooks && hooks['PreToolUse']) {
    const entries = hooks['PreToolUse'] as Array<Record<string, unknown>>;
    hooks['PreToolUse'] = entries.filter((entry) => {
      const hooksArr = entry['hooks'] as Array<Record<string, string>> | undefined;
      if (hooksArr) {
        return !hooksArr.some((h) =>
          h['command'] && String(h['command']).includes('depose')
        );
      }
      return true;
    });

    if ((hooks['PreToolUse'] as unknown[]).length === 0) {
      delete hooks['PreToolUse'];
    }
    if (Object.keys(hooks).length === 0) {
      delete settings['hooks'];
    }

    writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');
  }

  return { removed: true, restored: false };
}

/**
 * Remove shell shim symlinks and bin directory.
 */
export function uninstallShellShims(
  options: { binDir?: string } = {}
): { removed: string[]; binDirRemoved: boolean } {
  const binDir = options.binDir || DEFAULT_DEPOSE_BIN_DIR;
  const removed: string[] = [];

  if (!existsSync(binDir)) {
    return { removed, binDirRemoved: false };
  }

  // Remove all symlinks
  for (const name of SHIM_ALLOWLIST) {
    const linkPath = join(binDir, name);
    try {
      if (existsSync(linkPath)) {
        unlinkSync(linkPath);
        removed.push(name);
      }
    } catch {
      // Best-effort
    }
  }

  // Remove depose-shim binary
  const shimPath = join(binDir, 'depose-shim');
  try {
    if (existsSync(shimPath)) {
      unlinkSync(shimPath);
      removed.push('depose-shim');
    }
  } catch {
    // Best-effort
  }

  return { removed, binDirRemoved: false };
}
