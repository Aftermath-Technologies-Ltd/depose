// packages/cli/src/commands/install-shell.ts
//
// `depose install --shell`: symlink the capture shim into a PATH-preceding
// directory under an allowlist of destructive binary names.

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  chmodSync,
  symlinkSync,
  unlinkSync,
  lstatSync,
  readlinkSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import {
  SHIM_ALLOWLIST,
  DEFAULT_DEPOSE_BIN_DIR,
  DEFAULT_CAPTURE_DIR,
} from './install-paths.js';

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
  /** Force overwriting existing symlinks that point elsewhere (default: false) */
  force?: boolean;
}

/**
 * Install shell shim entries for destructive binaries.
 *
 * Steps (docs/shim-installation.md):
 *   1. Create $DEPOSE_BIN_DIR (default ~/.depose/bin) with 0755
 *   2. Copy depose-shim binary to $DEPOSE_BIN_DIR/depose-shim
 *   3. Create symlinks for each binary in allowlist (idempotent)
 *   4. Create $DEPOSE_CAPTURE_DIR with 0700
 *   5. Print PATH instruction
 *
 * Idempotent behavior (F-23):
 *   - If a symlink already points to the correct target, skip it.
 *   - If a symlink points elsewhere, error unless --force is set.
 *   - If a regular file exists at the symlink path, error unless --force.
 */
export function installShellShims(
  options: InstallShellOptions = {}
): {
  binDir: string;
  captureDir: string;
  installedBinaries: string[];
  skippedBinaries: string[];
  pathInstruction: string;
} {
  const binDir = options.binDir || DEFAULT_DEPOSE_BIN_DIR;
  const captureDir = options.captureDir || DEFAULT_CAPTURE_DIR;
  const binaries = options.binaries || Array.from(SHIM_ALLOWLIST);
  const force = options.force ?? false;

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

  // Find the shim binary. Fail closed, without it, the symlinks below
  // would all dangle (notably "rm" → missing target), and the user's
  // shell would break in dangerous ways once they put binDir on PATH.
  const shimBinary = options.shimBinary || findShimBinary();
  if (!shimBinary || !existsSync(shimBinary)) {
    throw new Error(
      'depose-shim binary not found. Build it first:\n' +
      '  (cd apps/capture-shim && make build-local)\n' +
      'Or install a release that includes depose-shim. Refusing to install ' +
      'shell shims because that would leave dangling symlinks (including "rm") ' +
      'on your PATH.'
    );
  }

  // Copy shim binary to bin dir.
  const targetShim = join(binDir, 'depose-shim');
  const content = readFileSync(shimBinary);
  writeFileSync(targetShim, content);
  chmodSync(targetShim, 0o755);

  // Create symlinks (idempotent)
  const installedBinaries: string[] = [];
  const skippedBinaries: string[] = [];

  for (const name of binaries) {
    const linkPath = join(binDir, name);

    try {
      // Check if symlink already exists and points to the correct target
      if (lstatSync(linkPath).isSymbolicLink()) {
        const currentTarget = readlinkSync(linkPath);
        if (currentTarget === targetShim) {
          // Already points to the correct target, skip
          skippedBinaries.push(name);
          continue;
        }
        // Points elsewhere, require --force to override
        if (!force) {
          throw new Error(
            `Symlink "${linkPath}" already exists pointing to "${currentTarget}". ` +
            `Use --force to override.`
          );
        }
        // Force: remove and recreate
        unlinkSync(linkPath);
      } else {
        // Regular file or directory exists at the path
        if (!force) {
          throw new Error(
            `Path "${linkPath}" already exists and is not a symlink. ` +
            `Use --force to override.`
          );
        }
        // Force: remove and recreate
        unlinkSync(linkPath);
      }
    } catch (err: unknown) {
      // lstatSync throws for non-existent paths; that's fine, we create below
      if (err instanceof Error && !err.message.includes('ENOENT')) {
        // Re-throw unless it's just "does not exist"
        throw err;
      }
    }

    // Create the symlink
    try {
      symlinkSync(targetShim, linkPath);
      installedBinaries.push(name);
    } catch (err) {
      // EEXIST can still happen in race conditions, skip
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('EEXIST')) {
        throw err;
      }
    }
  }

  const pathInstruction = `Add to your shell profile:\n  export PATH="${binDir}:$PATH"`;

  return {
    binDir,
    captureDir,
    installedBinaries,
    skippedBinaries,
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

