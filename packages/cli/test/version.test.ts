// packages/cli/test/version.test.ts
//
// CLI_VERSION is a build-time constant because the shipped CLI is a single
// esbuild bundle with no package.json guaranteed beside it. That trade
// only holds if the constant tracks the manifest, so assert it here rather
// than discovering a mismatch from a published tarball.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CLI_VERSION } from '../src/version.js';

describe('CLI_VERSION', () => {
  it('matches the version in package.json', () => {
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', 'package.json'), 'utf-8')
    ) as { version: string };

    expect(CLI_VERSION).toBe(pkg.version);
  });

  it('is a semver string', () => {
    expect(CLI_VERSION).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  });
});
