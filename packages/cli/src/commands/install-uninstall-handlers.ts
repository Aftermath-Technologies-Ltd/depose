// packages/cli/src/commands/install-uninstall-handlers.ts
//
// CLI-facing handlers for `depose install` and `depose uninstall`: argument
// validation and output. The filesystem work lives in install-claude.ts,
// install-shell.ts, and install.ts.

import { resolve } from 'node:path';
import {
  installClaudeHook,
  installShellShims,
  uninstallClaudeHook,
  uninstallShellShims,
  DEFAULT_CAPTURE_DIR,
} from './install.js';
import type { CliArgs } from './cli-args.js';

export async function handleInstall(args: CliArgs): Promise<void> {
  const isClaude = args['claude'] === true;
  const isShell = args['shell'] === true;
  const useProject = args['project'] === true;
  const binDir = args['bin-dir'] as string | undefined;
  const captureDir = args['capture-dir'] as string | undefined;

  if (!isClaude && !isShell) {
    console.error('ERROR: specify --claude or --shell (or both).');
    console.error('');
    console.error('Usage: depose install --claude');
    console.error('       depose install --shell');
    console.error('       depose install --claude --shell');
    process.exit(1);
    return;
  }

  if (isClaude) {
    console.log('Installing Claude Code PreToolUse hook...');
    const result = installClaudeHook({
      project: useProject,
      captureDir,
    });

    if (result.conflicts.length > 0) {
      console.log('');
      for (const conflict of result.conflicts) {
        console.log(`  CONFLICT: ${conflict}`);
      }
      console.log('');
      console.log('Hook already installed. No changes made.');
    } else {
      console.log(`  Settings: ${result.settingsPath}`);
      if (result.backupPath) {
        console.log(`  Backup:   ${result.backupPath}`);
      }
      console.log(`  Capture:  ${result.captureDir}`);
      console.log('');
      console.log('Hook installed. Claude Code will now capture pre-execution');
      console.log('records for Bash, Edit, and Write tool calls.');
    }
  }

  if (isShell) {
    console.log('');
    console.log('Installing shell shims...');
    const result = installShellShims({
      binDir: binDir ? resolve(binDir) : undefined,
      captureDir,
    });

    console.log(`  Bin dir:    ${result.binDir}`);
    console.log(`  Capture:   ${result.captureDir}`);
    console.log(`  Installed: ${result.installedBinaries.join(', ')}`);
    console.log('');
    console.log(result.pathInstruction);
  }

  if (isClaude || isShell) {
    console.log('');
    console.log('Capture records will be written to:');
    console.log(`  ${captureDir || DEFAULT_CAPTURE_DIR}`);
    console.log('');
    console.log('When you run `depose package`, capture records from this');
    console.log('directory will be automatically integrated into the bundle.');
  }
}

// ── Uninstall command (Phase 3, active capture) ─────────────────────

export async function handleUninstall(args: CliArgs): Promise<void> {
  const isClaude = args['claude'] === true;
  const isShell = args['shell'] === true;
  const binDir = args['bin-dir'] as string | undefined;

  if (!isClaude && !isShell) {
    console.error('ERROR: specify --claude or --shell (or both).');
    console.error('');
    console.error('Usage: depose uninstall --claude');
    console.error('       depose uninstall --shell');
    process.exit(1);
    return;
  }

  if (isClaude) {
    console.log('Removing Claude Code PreToolUse hook...');
    const result = uninstallClaudeHook();
    if (result.removed) {
      console.log('  Hook removed from settings.json.');
    } else {
      console.log('  No depose hook found in settings.json.');
    }
  }

  if (isShell) {
    console.log('Removing shell shims...');
    const result = uninstallShellShims({
      binDir: binDir ? resolve(binDir) : undefined,
    });
    if (result.removed.length > 0) {
      console.log(`  Removed: ${result.removed.join(', ')}`);
    } else {
      console.log('  No shims found to remove.');
    }
  }
}
