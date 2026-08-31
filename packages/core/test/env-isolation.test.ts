// packages/core/test/env-isolation.test.ts
//
// Guards tests/setup/isolate-env.ts. If the global setup stops running,
// every suite silently starts reading the developer's real
// ~/.depose/captures again and fixtures grow by whatever that host
// happens to hold. That failure is invisible without an explicit check:
// the suite still passes, it just stops testing the fixture.

import { describe, it, expect } from 'vitest';
import { tmpdir, homedir } from 'node:os';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { normalizeCaptureRecords } from '../src/normalize/capture.js';

describe('test environment isolation', () => {
  it('points HOME at a temp sandbox rather than the host home', () => {
    expect(homedir().startsWith(tmpdir())).toBe(true);
  });

  it('points DEPOSE_CAPTURE_DIR inside that sandbox', () => {
    const captureDir = process.env.DEPOSE_CAPTURE_DIR;
    expect(captureDir).toBeDefined();
    expect(captureDir!.startsWith(tmpdir())).toBe(true);
    expect(captureDir!.startsWith(homedir())).toBe(true);
  });

  it('reads capture records from the sandbox, not the host store', () => {
    const captureDir = process.env.DEPOSE_CAPTURE_DIR!;
    mkdirSync(captureDir, { recursive: true });
    writeFileSync(
      join(captureDir, '01JGARD0000000000000000001.json'),
      JSON.stringify({
        argv: ['echo', 'sandbox-only'],
        cwd: '/sandbox',
        envHash: '0'.repeat(64),
        envSubset: {},
        ttyId: null,
        user: 'test',
        hostname: 'test',
        parentProcessTree: [],
        fileArgs: [],
        source: 'claude-pretooluse',
        captureSchemaVersion: 1,
      }),
      'utf-8',
    );

    const { events, recordCount } = normalizeCaptureRecords();

    // Exactly the record this test planted. On an unisolated run against a
    // developer machine with the hook installed, this was 9,391.
    expect(recordCount).toBe(1);
    expect(events).toHaveLength(1);
  });

  it('leaves the host capture store untouched', () => {
    // The sandbox home is fresh, so the real store cannot be reachable
    // through it. Asserting the path shape catches a setup file that sets
    // DEPOSE_CAPTURE_DIR but forgets HOME (or vice versa).
    const hostStore = join(homedir(), '.depose', 'captures');
    const planted = process.env.DEPOSE_CAPTURE_DIR!;
    expect(hostStore).toBe(planted);
    expect(existsSync(planted)).toBe(true);
  });
});
