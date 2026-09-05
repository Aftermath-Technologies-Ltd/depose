// packages/core/test/reconstruct.ruleset-tsa.test.ts
//
// The ruleset's `tsa` list: which timestamp authorities a seal is
// anchored to, and why a malformed entry is named rather than dropped.
// Rule matching itself is in reconstruct.destructive.test.ts.

import { describe, it, expect } from 'vitest';
import { parseRulesetYaml, parseTsaList } from '../src/index.js';

describe('parseTsaList', () => {
  it('returns nothing when the ruleset names no authority', () => {
    expect(parseTsaList(undefined)).toEqual([]);
    expect(parseTsaList(null)).toEqual([]);
  });

  it('keeps the configured order, which is the order they are tried before shuffling', () => {
    const parsed = parseTsaList([
      { name: 'internal', url: 'https://tsa.corp.example/tsr' },
      { name: 'FreeTSA', url: 'https://freetsa.org/tsr' },
    ]);
    expect(parsed.map((t) => t.name)).toEqual(['internal', 'FreeTSA']);
  });

  it('carries the pinned signer fingerprint, lowercased', () => {
    const [tsa] = parseTsaList([
      { name: 'internal', url: 'https://tsa.corp.example/tsr', signerFingerprint: 'AABB' },
    ]);
    expect(tsa!.signerFingerprint).toBe('aabb');
  });

  it('names the offending entry rather than silently dropping it', () => {
    expect(() => parseTsaList('freetsa')).toThrow(/must be a list/);
    expect(() => parseTsaList([{ url: 'https://x/tsr' }])).toThrow(/tsa\[0\] needs/);
    expect(() => parseTsaList([{ name: 'x', url: 'ftp://x/tsr' }])).toThrow(/must be http or https/);
  });
});

describe('parseRulesetYaml with a tsa list', () => {
  it('reads the authorities alongside the rules', () => {
    const ruleset = parseRulesetYaml(`
version: 1
tsa:
  - name: internal
    url: https://tsa.corp.example/tsr
    signerFingerprint: deadbeef
rules: []
`);
    expect(ruleset.tsa).toEqual([
      { name: 'internal', url: 'https://tsa.corp.example/tsr', signerFingerprint: 'deadbeef' },
    ]);
  });

  it('leaves the list empty when the key is absent, so the built-in authorities apply', () => {
    expect(parseRulesetYaml('version: 1\nrules: []\n').tsa).toEqual([]);
  });
});

// ── Global options before the subcommand ─────────────────────────────
//
// Found while building examples/kiro-cost-explorer: the incident's own
// command was `terraform -chdir=infra/prod destroy -auto-approve`, and a
// rule written as ["terraform", "destroy"] did not fire on it. A tool's
// global options are not part of the act; the subcommand is.
