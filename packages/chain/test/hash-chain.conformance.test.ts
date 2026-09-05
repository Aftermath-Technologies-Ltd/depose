// packages/chain/test/hash-chain.conformance.test.ts
//
// Shared hash-chain vectors. apps/verify/chain/conformance_test.go runs
// the same file; a divergence means a chain sealed here does not replay
// in the verifier. See docs/bundle-format.md#hash-chain.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseEventLine } from '@depose/core';
import { buildHashChain, verifyHashChain } from '../src/hash-chain.js';

interface ChainVector {
  name: string;
  events: Record<string, unknown>[];
  expected?: { chainHashes: string[]; rootHash: string };
  expectedError?: string;
}

const file = JSON.parse(
  readFileSync(join(__dirname, '../../../tests/conformance/hash-chain-vectors.json'), 'utf-8')
) as { vectors: ChainVector[] };

describe('hash chain conformance vectors', () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const events = vector.events.map((e) => parseEventLine(JSON.stringify(e)));
    if (vector.expectedError) {
      expect(() => buildHashChain(events)).toThrow(vector.expectedError);
      return;
    }
    const { chainedEvents, rootHash } = buildHashChain(events);
    expect(chainedEvents.map((e) => e.chainHash)).toEqual(vector.expected!.chainHashes);
    expect(rootHash).toBe(vector.expected!.rootHash);
    expect(verifyHashChain(chainedEvents, rootHash).valid).toBe(true);
  });

  it('carries monoNs above 2^53 without losing digits', () => {
    const vector = file.vectors.find((v) => v.name === 'monons-above-2-53')!;
    const events = vector.events.map((e) => parseEventLine(JSON.stringify(e)));
    expect(events[0]!.monoNs).toBe(9007199254740993n);
    expect(events[1]!.monoNs - events[0]!.monoNs).toBe(1n);
  });
});
