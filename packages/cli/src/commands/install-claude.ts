// packages/cli/src/commands/install-claude.ts
//
// `depose install --claude`: register the PreToolUse hook in Claude Code's
// settings.json (user-level or project-level) and create the capture dir.

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import {
  DEFAULT_CAPTURE_DIR,
  buildHookCommand,
  requireHookBinary,
} from './install-paths.js';

// ── Install --claude ────────────────────────────────────────────────

export interface InstallClaudeOptions {
  /** Use project-level settings.json instead of global */
  project?: boolean;
  /** Project root directory (default: cwd) */
  projectRoot?: string;
  /** Custom capture directory */
  captureDir?: string;
}

/**
 * Install the PreToolUse hook into Claude Code settings.json.
 *
 * Steps (BUILD_PLAN.md §6, Phase 3):
 *   1. Read existing settings.json (or create empty)
 *   2. Create backup: .claude/settings.json.depose-backup-<ts>
 *   3. Merge hook config with conflict detection
 *   4. Write updated settings.json
 *   5. Create $DEPOSE_CAPTURE_DIR with 0700 permissions
 */
export function installClaudeHook(
  options: InstallClaudeOptions = {}
): {
  settingsPath: string;
  backupPath: string | null;
  captureDir: string;
  conflicts: string[];
} {
  const captureDir = options.captureDir || DEFAULT_CAPTURE_DIR;

  // Pre-invocation check: verify the hook binary exists
  try {
    requireHookBinary();
  } catch (err) {
    return {
      settingsPath: '',
      backupPath: null,
      captureDir,
      conflicts: [(err instanceof Error ? err.message : String(err))],
    };
  }

  // Determine settings.json path
  const settingsPath = options.project
    ? join(options.projectRoot || process.cwd(), '.claude', 'settings.json')
    : join(homedir(), '.claude', 'settings.json');

  const settingsDir = dirname(settingsPath);
  if (!existsSync(settingsDir)) {
    mkdirSync(settingsDir, { recursive: true });
  }

  // Read existing settings
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try {
      const content = readFileSync(settingsPath, 'utf-8');
      settings = JSON.parse(content);
    } catch {
      // Treat as empty if malformed
    }
  }

  // Create backup before modifying
  let backupPath: string | null = null;
  if (existsSync(settingsPath)) {
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    backupPath = `${settingsPath}.depose-backup-${ts}`;
    const original = readFileSync(settingsPath, 'utf-8');
    writeFileSync(backupPath, original, 'utf-8');
  }

  // Merge hook config
  const conflicts: string[] = [];
  const hookConfig = buildHookConfig();

  if (!settings['hooks']) {
    settings['hooks'] = {};
  }
  const hooks = settings['hooks'] as Record<string, unknown[]>;
  if (!hooks['PreToolUse']) {
    hooks['PreToolUse'] = [];
  }

  // Check for conflicts
  const existing = hooks['PreToolUse'] as Array<Record<string, unknown>>;
  for (const entry of existing) {
    const hooksArr = entry['hooks'] as Array<Record<string, string>> | undefined;
    if (hooksArr) {
      for (const h of hooksArr) {
        if (h['command'] && String(h['command']).includes('depose')) {
          conflicts.push(`Existing depose hook found: "${h['command']}"`);
        }
      }
    }
  }

  // Add the hook entry if no existing depose hook
  if (conflicts.length === 0) {
    existing.push(hookConfig);
  }

  // Write updated settings
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');

  // Create capture directory
  if (!existsSync(captureDir)) {
    mkdirSync(captureDir, { recursive: true });
    chmodSync(captureDir, 0o700);
  }

  return {
    settingsPath,
    backupPath,
    captureDir,
    conflicts,
  };
}

/**
 * Build the PreToolUse hook config entry for Claude Code settings.json.
 */
function buildHookConfig(): Record<string, unknown> {
  return {
    matcher: 'Bash|Edit|Write',
    hooks: [
      {
        type: 'command',
        command: buildHookCommand(),
      },
    ],
  };
}

