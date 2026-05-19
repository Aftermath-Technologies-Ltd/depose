// packages/cli/src/commands/main.ts
//
// CLI main entrypoint.
//
// Commands (BUILD_PLAN.md §3, §6):
//   depose reconstruct --from-claude <session-id>
//   depose package --from-claude <path>
//   depose verify <bundle>
//   depose install --claude | --shell
//   depose explain
//
// Argument parsing uses `commander`. Previously a hand-rolled
// parser silently mishandled `--key=value`, treated repeated flags
// as overwrites, and broke on values that begin with `-`. For a
// forensics CLI "trust me, I parsed your flag right" is the wrong
// posture.

import { resolve } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { Command } from 'commander';
import {
  buildTimeline,
  formatTimelineSummary,
  loadDestructiveRules,
  generateUlid,
  type AgentId,
} from '@depose/core';
import { writeBundle } from '@depose/bundle';
import { handlePackage, type PackageCommandArgs } from './package.js';
import { handleExplain, type ExplainCommandArgs } from './explain.js';
import { handleKeyFingerprint, type KeyCommandArgs } from './key.js';
import { DEFAULT_RULES_PATH } from '../rules-default.js';
import { VERIFIER_DOWNLOAD_URL } from '@depose/bundle';
import { loadAndMergeEvents } from '../pipeline.js';
import {
  installClaudeHook,
  installShellShims,
  uninstallClaudeHook,
  uninstallShellShims,
  DEFAULT_CAPTURE_DIR,
} from './install.js';

// ── Args shape (kebab-case keys, matches what handlers consume) ──────

interface CliArgs {
  [key: string]: string | boolean | string[] | undefined;
}

/**
 * Convert commander's camelCase options into the kebab-case shape
 * the existing handlers consume. Commander emits opts with names
 * derived from the long flag — so `--from-claude` becomes
 * `opts.fromClaude`. We rebuild a kebab-keyed object so handlers
 * see `args['from-claude']` as they always did.
 */
function camelToKebab(name: string): string {
  return name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

function optsToArgs(opts: Record<string, unknown>): CliArgs {
  const out: CliArgs = {};
  for (const [k, v] of Object.entries(opts)) {
    out[camelToKebab(k)] = v as string | boolean | string[] | undefined;
  }
  return out;
}

// ── Main ─────────────────────────────────────────────────────────────

/**
 * Fail fast on unsupported platforms.
 *
 * The signing-key store relies on POSIX 0600 permissions (a no-op on
 * Windows, leaving the private key world-readable). The shell shims
 * are POSIX shell scripts. Active capture via the Claude Code hook
 * assumes a POSIX hook command. Until those gaps close, Windows is
 * out of scope rather than silently degraded.
 */
function assertSupportedPlatform(): void {
  if (process.platform === 'win32') {
    console.error(
      'ERROR: depose is not supported on Windows.\n' +
      '  - The signing key store relies on POSIX 0600 permissions.\n' +
      '  - The capture shims are POSIX shell scripts.\n' +
      'Run depose under macOS, Linux, or WSL2.'
    );
    process.exit(1);
  }
}

export async function main(argv: string[]): Promise<void> {
  assertSupportedPlatform();
  const program = new Command();
  program
    .name('depose')
    .description('Depose the agent. Produce the record.')
    .exitOverride((err) => {
      // commander throws CommanderError on help/version/parse error.
      // For help/version it exits 0; for parse errors we want 1 so
      // the CLI's behavior matches the previous hand-rolled parser.
      if (err.code === 'commander.helpDisplayed' || err.code === 'commander.version') {
        return;
      }
      process.exit(err.exitCode || 1);
    })
    // Make argument parsing strict but explicit:
    //   --from-claude=foo (key=value) is accepted by commander.
    //   --rules <path> --rules <path2> — last wins; we don't declare
    //   repeatable flags because none of our options are repeatable.
    //   Values starting with `-` work via `--key=value` form, or by
    //   relying on commander's "next-token-is-the-value" semantics.
    .allowUnknownOption(false)
    .showHelpAfterError();

  // Shared option groups (commander has no built-in inheritance, so
  // we define them in helpers).
  const addReconstructOpts = (cmd: Command) =>
    cmd
      .option('--from-claude <path>', 'Claude Code JSONL session file')
      .option('--rules <path>', 'Destructive ruleset YAML')
      .option('--ruleset <path>', 'Alias for --rules')
      .option('--output <dir>', 'Output directory')
      .option('--output-dir <dir>', 'Alias for --output')
      .option('--session-id <id>', 'Session ID (ULID)')
      .option('--agent-id <id>', 'Agent ID', 'claude-code')
      .option('--capture-dir <path>', 'Capture directory');

  addReconstructOpts(
    program
      .command('reconstruct')
      .description('Reconstruct a session from JSONL (dev-unsigned bundle)')
      .action(async function (this: Command) {
        await handleReconstruct(optsToArgs(this.opts()));
      })
  );

  addReconstructOpts(
    program
      .command('package')
      .description('Produce a fully signed .depo bundle (default mode: signed)')
      .option('--skip-timestamp', 'Downgrade to dev-unsigned (no TSA, no signature)')
      .option('--key-dir <path>', 'Ed25519 key directory')
      .action(async function (this: Command) {
        await handlePackage(optsToArgs(this.opts()) as unknown as PackageCommandArgs);
      })
  );

  program
    .command('verify [bundle]')
    .description('Defer to the separate depose-verify Go binary')
    .action(() => {
      console.error('ERROR: `depose verify` uses the separate `depose-verify` Go binary.');
      console.error(`Install from: ${VERIFIER_DOWNLOAD_URL}`);
      console.error('Usage: depose-verify verify <path-to-bundle>');
      process.exit(1);
    });

  addReconstructOpts(
    program
      .command('explain')
      .description('Generate commentary.md (AI-generated, NOT evidence)')
      .option('--bundle <dir>', 'Existing bundle directory')
      .action(async function (this: Command) {
        await handleExplain(optsToArgs(this.opts()) as unknown as ExplainCommandArgs);
      })
  );

  program
    .command('install')
    .description('Install the Claude Code hook and/or shell shims')
    .option('--claude', 'Install the Claude Code PreToolUse hook')
    .option('--shell', 'Install shell shims for destructive binaries')
    .option('--project', 'Use project-level settings.json (with --claude)')
    .option('--bin-dir <path>', 'Shim install directory')
    .option('--capture-dir <path>', 'Capture directory')
    .action(async function (this: Command) {
      await handleInstall(optsToArgs(this.opts()));
    });

  const keyCmd = program
    .command('key')
    .description('Inspect the local Ed25519 signing key');
  keyCmd
    .command('fingerprint')
    .description('Print the SHA-256 fingerprint of the public signing key')
    .option('--key-dir <path>', 'Ed25519 key directory')
    .option('--ssh', 'Format as ssh-style SHA256:<base64> instead of hex')
    .action(async function (this: Command) {
      await handleKeyFingerprint(optsToArgs(this.opts()) as unknown as KeyCommandArgs);
    });

  program
    .command('uninstall')
    .description('Remove the Claude Code hook and/or shell shims')
    .option('--claude', 'Remove the Claude Code PreToolUse hook')
    .option('--shell', 'Remove shell shims')
    .option('--bin-dir <path>', 'Shim install directory (must match install)')
    .action(async function (this: Command) {
      await handleUninstall(optsToArgs(this.opts()));
    });

  // commander parses from a [node, script, ...] style; we receive a
  // sliced argv. Use parseAsync with the from:'user' source.
  try {
    await program.parseAsync(argv, { from: 'user' });
  } catch (err) {
    // exitOverride above re-exits on parse errors; this catch
    // handles handler-level rejections.
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

// ── Reconstruct command (Phase 1 — unsigned) ─────────────────────────

async function handleReconstruct(args: CliArgs): Promise<void> {
  const jsonlPath: string | undefined = typeof args['from-claude'] === 'string' ? args['from-claude'] : undefined;
  const rulesPath = (args['rules'] || args['ruleset']) as string | undefined;
  const outputDir = (args['output'] || args['output-dir']) as string | undefined;
  const sessionId = args['session-id'] as string | undefined;
  const agentId = (args['agent-id'] || 'claude-code') as string;

  if (!jsonlPath) {
    console.error('ERROR: --from-claude <path> is required.');
    console.error('');
    console.error('Usage: depose reconstruct --from-claude <path> [options]');
    process.exit(1);
    return;
  }

  // Resolve paths
  const resolvedJsonl = resolve(jsonlPath);
  const resolvedOutput = outputDir ? resolve(outputDir) : resolve('./depose-output');
  const resolvedRules = rulesPath ? resolve(rulesPath) : DEFAULT_RULES_PATH;

  // Validate input
  if (!existsSync(resolvedJsonl)) {
    console.error(`ERROR: Input file not found: ${resolvedJsonl}`);
    process.exit(1);
    return;
  }

  // Load destructive rules. Bytes are passed verbatim to the
  // bundle writer so the verifier can re-hash them against
  // manifest.rulesetHash.
  const rules = loadDestructiveRules(resolvedRules);
  const rulesetBytes = readFileSync(resolvedRules);

  // Load + normalize + merge all sources through the shared pipeline.
  const { events: merged, warnings, gapCount, linkedCount, captureRecordCount } = loadAndMergeEvents({
    jsonlPath: resolvedJsonl,
    sessionId,
    agentId: agentId as AgentId,
    captureDir: args['capture-dir'] as string | undefined,
  });

  // Build timeline + emit human-readable summary.
  const timeline = buildTimeline(merged, rules);
  const summary = formatTimelineSummary(timeline);
  console.log(summary);
  console.log('');
  if (captureRecordCount > 0) {
    console.log(`Loaded ${captureRecordCount} pre-execution capture records`);
  }
  console.log(`Gaps: ${gapCount}`);
  console.log(`Linked: ${linkedCount}`);
  console.log(`Warnings: ${warnings.length}`);
  for (const w of warnings) {
    console.log(`  WARN: ${w}`);
  }
  console.log('');

  const bundleId = sessionId || (merged[0]?.sessionId || generateUlid());
  const sessionStarted = merged.length > 0 ? (merged[0]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const sessionEnded = merged.length > 0 ? (merged[merged.length - 1]?.wallTs ?? new Date().toISOString()) : new Date().toISOString();
  const producedAt = new Date().toISOString();

  const { depopPath, manifest } = await writeBundle(merged, rules, {
    sessionId: bundleId,
    agentId,
    version: '0.1.0',
    producedAt,
    sessionStartedAt: sessionStarted,
    sessionEndedAt: sessionEnded,
    rules,
    rulesetBytes,
    outputDir: resolvedOutput,
    mode: 'dev-unsigned',
  });

  console.log(`Bundle written to: ${depopPath}`);
  console.log(`Manifest: ${JSON.stringify({
    bundleId: manifest.bundleId,
    events: manifest.counts.events,
    destructiveOps: manifest.counts.destructiveOperations,
    gaps: manifest.counts.gaps,
    rootHash: manifest.rootHash || '(empty)',
  }, null, 2)}`);
}

// ── Install command (Phase 3 — active capture) ──────────────────────

async function handleInstall(args: CliArgs): Promise<void> {
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

// ── Uninstall command (Phase 3 — active capture) ─────────────────────

async function handleUninstall(args: CliArgs): Promise<void> {
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