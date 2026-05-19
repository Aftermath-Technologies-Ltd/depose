// packages/cli/src/commands/install.ts
//
// `depose install --claude | --shell` — Phase 3 active capture installation.
//
// --claude: Writes the PreToolUse hook entry into ~/.claude/settings.json
//          (or project .claude/settings.json) and creates $DEPOSE_CAPTURE_DIR.
// --shell: Installs shim entries to a configurable PATH-preceding directory
//          (default ~/.depose/bin) for an allowlist of destructive binaries.
//
// See BUILD_PLAN.md §6 (Phase 3).

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, symlinkSync, unlinkSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { homedir } from 'node:os';

// ── Constants ────────────────────────────────────────────────────────

/** Default shim binary allowlist (BUILD_PLAN.md §6) */
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

/** Hook command string for Claude Code settings.json */
export const HOOK_COMMAND = 'depose-hook pretooluse';

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
        command: HOOK_COMMAND,
      },
    ],
  };
}

// ── Install --shell ─────────────────────────────────────────────────

export interface InstallShellOptions {
  /** Custom bin directory for shim symlinks */
  binDir?: string;
  /** Custom list of binaries to shim (default: SHIM_ALLOWLIST) */
  binaries?: string[];
  /** Path to the depose-shim binary */
  shimBinary?: string;
  /** Custom capture directory */
  captureDir?: string;
}

/**
 * Install shell shim entries for destructive binaries.
 *
 * Steps (BUILD_PLAN.md §6, Phase 3):
 *   1. Create $DEPOSE_BIN_DIR (default ~/.depose/bin) with 0755
 *   2. Copy depose-shim binary to $DEPOSE_BIN_DIR/depose-shim
 *   3. Create symlinks for each binary in allowlist
 *   4. Create $DEPOSE_CAPTURE_DIR with 0700
 *   5. Print PATH instruction
 */
export function installShellShims(
  options: InstallShellOptions = {}
): {
  binDir: string;
  captureDir: string;
  installedBinaries: string[];
  pathInstruction: string;
} {
  const binDir = options.binDir || DEFAULT_DEPOSE_BIN_DIR;
  const captureDir = options.captureDir || DEFAULT_CAPTURE_DIR;
  const binaries = options.binaries || Array.from(SHIM_ALLOWLIST);

  // Create bin directory
  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: true });
    chmodSync(binDir, 0o755);
  }

  // Create capture directory
  if (!existsSync(captureDir)) {
    mkdirSync(captureDir, { recursive: true });
    chmodSync(captureDir, 0o700);
  }

  // Find or build the shim binary
  const shimBinary = options.shimBinary || findShimBinary();

  // Copy shim binary to bin dir (if it exists)
  const targetShim = join(binDir, 'depose-shim');
  if (shimBinary && existsSync(shimBinary)) {
    const content = readFileSync(shimBinary);
    writeFileSync(targetShim, content);
    chmodSync(targetShim, 0o755);
  }

  // Create symlinks
  const installedBinaries: string[] = [];
  for (const name of binaries) {
    const linkPath = join(binDir, name);
    try {
      // Remove existing symlink if present
      if (existsSync(linkPath)) {
        try {
          readFileSync(linkPath); // Will throw for broken symlinks
        } catch {
          // Broken symlink, remove it
        }
      }
      symlinkSync(targetShim, linkPath);
      installedBinaries.push(name);
    } catch (err) {
      // Symlink might already exist; best-effort
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('EEXIST')) {
        // Real error
      }
      // On EEXIST, just skip
    }
  }

  const pathInstruction = `Add to your shell profile:\n  export PATH="${binDir}:$PATH"`;

  return {
    binDir,
    captureDir,
    installedBinaries,
    pathInstruction,
  };
}

/**
 * Find the depose-shim binary.
 * Looks in well-known locations relative to the depose repo, then PATH.
 */
function findShimBinary(): string | null {
  // Check local build directory relative to the depose project root.
  // We resolve relative to cwd first (typical invocation from project root).
  const candidates = [
    resolve('apps/capture-shim/depose-shim'),
    resolve('apps/capture-shim/build/depose-shim'),
  ];

  // Also check platform-specific cross-compiled builds
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  const platform = process.platform === 'darwin' ? 'darwin' : 'linux';
  candidates.push(resolve(`apps/capture-shim/depose-shim-${platform}-${arch}`));

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  return null;
}

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