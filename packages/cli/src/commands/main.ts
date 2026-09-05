// packages/cli/src/commands/main.ts
//
// CLI main entrypoint.
//
// Commands:
//   depose record --from-claude <path>     ← canonical production verb
//   depose package --from-claude <path>    ← alias (adds --skip-timestamp for dev)
//   depose reconstruct --from-claude <session-id>  ← deprecated, use record
//   depose verify <bundle>
//   depose install --claude | --shell
//   depose explain
//
// Argument parsing uses `commander`. Previously a hand-rolled
// parser silently mishandled `--key=value`, treated repeated flags
// as overwrites, and broke on values that begin with `-`. For a
// forensics CLI "trust me, I parsed your flag right" is the wrong
// posture.

import { Command } from 'commander';
import { handlePackage, type PackageCommandArgs } from './package.js';
import { handleExplain, type ExplainCommandArgs } from './explain.js';
import {
  handleKeyFingerprint,
  handleKeyRotate,
  handleKeyRevoke,
  handleKeyCatalog,
  type KeyCommandArgs,
} from './key.js';
import { VERIFIER_DOWNLOAD_URL } from '@depose/bundle';
import { handleReconstruct } from './reconstruct.js';
import { handleDisclose, type DiscloseCommandArgs } from './disclose.js';
import { handleInstall, handleUninstall } from './install-uninstall-handlers.js';
import { optsToArgs } from './cli-args.js';
import { CLI_VERSION } from '../version.js';
import {
  handleCapturesList,
  handleCapturesPrune,
  type CapturesCommandArgs,
} from './captures.js';

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
    .version(CLI_VERSION, '-V, --version', 'Print the depose version')
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
    //   --rules <path> --rules <path2>, last wins; we don't declare
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
      .option('--capture-dir <path>', 'Capture directory')
      .option(
        '--include-unscoped-captures',
        'Merge capture records that carry no session id (off by default)'
      );

  addReconstructOpts(
    program
      .command('reconstruct')
      .description('Reconstruct a session from JSONL (dev-unsigned bundle)')
      .action(async function (this: Command) {
        console.error('WARNING: depose reconstruct is deprecated. Use depose record --from-claude <path> instead.');
        await handleReconstruct(optsToArgs(this.opts()));
      })
  );

  addReconstructOpts(
    program
      .command('package')
      .description('Produce a fully signed .depo bundle (default mode: signed)')
      .option('--skip-timestamp', 'Downgrade to dev-unsigned (no TSA, no signature)')
      .option('--key-dir <path>', 'Ed25519 key directory')
      .option('--fixed-seed <ms>', 'Pin ULID generation to a deterministic seed (for reproducibility tests only)')
      .option('--produced-at <iso>', 'Override producedAt timestamp (ISO 8601, for reproducibility tests)')
      .action(async function (this: Command) {
        await handlePackage(optsToArgs(this.opts()) as unknown as PackageCommandArgs);
      })
  );

  // `depose record` is an alias for `depose package` that always signs
  // (no --skip-timestamp option). It is the canonical production verb.
  addReconstructOpts(
    program
      .command('record')
      .description('Record a session as a signed .depo bundle (alias for package, always signed)')
      .option('--key-dir <path>', 'Ed25519 key directory')
      .action(async function (this: Command) {
        const args = optsToArgs(this.opts());
        // `record` always signs, force skip-timestamp off
        args['skip-timestamp'] = false;
        await handlePackage(args as unknown as PackageCommandArgs);
      })
  );

  program
    .command('disclose <bundle>')
    .description('Produce a verifiable partial disclosure of a sealed bundle')
    .option('--events <spec>', 'Event ids, zero-based indices, or ranges (3-7), comma-separated; or "all"', 'all')
    .option('--fields <spec>', 'JSON pointers to disclose (/toolInput,/output), or "all" or "none"', 'none')
    .option('--out <dir>', 'Output directory (default: <bundle>-disclosure)')
    .option('--include <path...>', 'Sealed files to carry verbatim (default: rules/destructive.yaml)')
    .option('--consistent-with <dir>', 'Earlier disclosure to prove consistency with')
    .action(async function (this: Command, bundle: string) {
      await handleDisclose(bundle, optsToArgs(this.opts()) as unknown as DiscloseCommandArgs);
    });

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
      .description('Generate commentary.md (deterministic template, NOT evidence)')
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

  const capturesCmd = program
    .command('captures')
    .description('Inspect and prune the local capture store');
  capturesCmd
    .command('list')
    .description('Report capture store size, record count, and age range')
    .option('--capture-dir <path>', 'Capture directory')
    .action(function (this: Command) {
      handleCapturesList(optsToArgs(this.opts()) as CapturesCommandArgs);
    });
  capturesCmd
    .command('prune')
    .description('Remove capture records older than a retention window (dry run by default)')
    .option('--older-than <duration>', 'Retention window, e.g. 90d, 12h, 30m')
    .option('--capture-dir <path>', 'Capture directory')
    .option('--yes', 'Actually delete. Without it, prune only reports.')
    .action(function (this: Command) {
      handleCapturesPrune(optsToArgs(this.opts()) as CapturesCommandArgs);
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
  keyCmd
    .command('rotate')
    .description('Archive the active key and generate a new active one')
    .option('--key-dir <path>', 'Ed25519 key directory')
    .action(async function (this: Command) {
      await handleKeyRotate(optsToArgs(this.opts()) as unknown as KeyCommandArgs);
    });
  keyCmd
    .command('revoke <fingerprint>')
    .description('Mark a fingerprint as revoked in the local catalog')
    .requiredOption('--reason <text>', 'Reason for revocation (required)')
    .option('--key-dir <path>', 'Ed25519 key directory')
    .action(async function (this: Command, fingerprint: string) {
      await handleKeyRevoke(
        fingerprint,
        optsToArgs(this.opts()) as unknown as KeyCommandArgs,
      );
    });
  keyCmd
    .command('catalog')
    .description('Print or export the local key catalog')
    .option('--key-dir <path>', 'Ed25519 key directory')
    .option('--export <path>', 'Write the catalog to <path> instead of stdout')
    .action(async function (this: Command) {
      await handleKeyCatalog(optsToArgs(this.opts()) as unknown as KeyCommandArgs);
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

// ── Reconstruct command (Phase 1, unsigned) ─────────────────────────

