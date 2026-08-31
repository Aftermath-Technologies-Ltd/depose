// tests/setup/isolate-env.ts
//
// Vitest global setup: pin every host-derived path to a per-file temp
// directory before any source module is imported.
//
// Without this, `normalizeCaptureRecords` reads the developer's real
// ~/.depose/captures and merges it into fixtures. That made the CLI
// suite report 18,831 events for a 5-line fixture on a machine with the
// hook installed, and pass in CI only because runners have an empty
// home. Same suite, different answers per host, asserting nothing.
//
// Two levers, both required:
//   - DEPOSE_CAPTURE_DIR wins at call time (normalize/capture.ts).
//   - HOME backstops the module-level DEFAULT_CAPTURE_DIR consts and
//     getDefaultKeyDir(), which resolve through os.homedir().
//
// This file runs before the test module graph is loaded, so the
// module-level constants close over the isolated home, not the real one.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll } from 'vitest';

const HOST_HOME = process.env.HOME;

const sandbox = mkdtempSync(join(tmpdir(), 'depose-test-'));
const captureDir = join(sandbox, '.depose', 'captures');

process.env.HOME = sandbox;
process.env.DEPOSE_CAPTURE_DIR = captureDir;

/**
 * Absolute path to this test file's isolated home directory.
 * Suites that need to plant fixture state (capture records, keys) should
 * write under here rather than reaching for os.homedir() themselves.
 */
export const TEST_HOME = sandbox;

/**
 * Absolute path to this test file's isolated capture directory.
 * Matches $DEPOSE_CAPTURE_DIR for the duration of the file.
 */
export const TEST_CAPTURE_DIR = captureDir;

afterAll(() => {
  if (HOST_HOME === undefined) {
    delete process.env.HOME;
  } else {
    process.env.HOME = HOST_HOME;
  }

  // Refuse to recurse outside the temp root even if something upstream
  // reassigned the sandbox path. Deleting a real home on a test teardown
  // is not a failure mode worth risking for a tidier temp dir.
  if (sandbox.startsWith(tmpdir())) {
    rmSync(sandbox, { recursive: true, force: true });
  }
});
