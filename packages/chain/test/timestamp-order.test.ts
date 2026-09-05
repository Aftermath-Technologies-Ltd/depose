// packages/chain/test/timestamp-order.test.ts
//
// Which authority gets asked, in what order, and how many times.
//
// A fixed order means the first authority in the list witnesses nearly
// every bundle a producer ever makes, which concentrates the load on one
// service and the trust in one operator. A single attempt turns a
// momentary rate limit into a bundle that cannot be sealed. Both are
// behaviours worth pinning, and neither needs a network to test: the
// endpoints here are unroutable, so every request fails immediately and
// what is under test is the order and the retry count.

import { describe, it, expect } from 'vitest';
import { tryTimestamps } from '../src/timestamp-rfc3161.js';
import type { TsaEndpoint } from '../src/rfc3161-types.js';

const endpoint = (name: string): TsaEndpoint => ({
  name,
  // 127.0.0.1:1 refuses immediately, so no test waits on a timeout.
  url: 'http://127.0.0.1:1/tsr',
  contentType: 'application/timestamp-query',
});

const three = [endpoint('alpha'), endpoint('beta'), endpoint('gamma')];

describe('tryTimestamps', () => {
  it('reports every failure instead of throwing, so the caller can seal pending an anchor', async () => {
    const result = await tryTimestamps('data', {
      tsaEndpoints: three,
      attempts: 1,
      sleep: async () => {},
    });

    expect(result.tokens).toEqual([]);
    expect(result.errors).toHaveLength(3);
    for (const name of ['alpha', 'beta', 'gamma']) {
      expect(result.errors.some((e) => e.startsWith(name))).toBe(true);
    }
  });

  it('retries each endpoint before moving on, with a doubling backoff', async () => {
    const slept: number[] = [];
    const result = await tryTimestamps('data', {
      tsaEndpoints: [endpoint('alpha')],
      attempts: 4,
      backoffMs: 100,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    expect(slept).toEqual([100, 200, 400]);
    expect(result.errors[0]).toContain('4 attempt(s)');
  });

  it('makes exactly one attempt when asked for one', async () => {
    const slept: number[] = [];
    await tryTimestamps('data', {
      tsaEndpoints: [endpoint('alpha')],
      attempts: 1,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });

    expect(slept).toEqual([]);
  });

  it('shuffles the endpoints so one authority does not witness everything', async () => {
    // Fisher-Yates with a source that always picks index 0 takes
    // [alpha, beta, gamma] to [beta, gamma, alpha]: a fixed permutation,
    // and one that is not the input order.
    const result = await tryTimestamps('data', {
      tsaEndpoints: three,
      attempts: 1,
      random: () => 0,
      sleep: async () => {},
    });

    expect(result.errors.map((e) => e.split(' ')[0])).toEqual(['beta', 'gamma', 'alpha']);
  });

  it('keeps the caller order when preserveOrder is set', async () => {
    const result = await tryTimestamps('data', {
      tsaEndpoints: three,
      attempts: 1,
      preserveOrder: true,
      sleep: async () => {},
    });

    expect(result.errors.map((e) => e.split(' ')[0])).toEqual(['alpha', 'beta', 'gamma']);
  });

  it('does not reorder the array the caller passed in', async () => {
    const given = [...three];
    await tryTimestamps('data', { tsaEndpoints: given, attempts: 1, random: () => 0, sleep: async () => {} });

    expect(given.map((e) => e.name)).toEqual(['alpha', 'beta', 'gamma']);
  });
});
