// packages/core/test/events.ids.test.ts
//
// ids.ts produces every event id in every evidence bundle and had no
// tests. That is how generateUlid() shipped randomizing all 16 bytes,
// timestamp prefix included, while encodeUlid's own doc comment
// documented chars 0-9 as the 48-bit timestamp. Real capture filenames
// decoded to 1970, 6375, and the year 10888.

import { describe, it, expect, afterEach } from 'vitest';
import {
  generateUlid,
  ulidFromTime,
  ulidToTime,
  isValidUlid,
  setFixedUlidSeed,
  clearFixedUlidSeed,
} from '../src/events/ids.js';

describe('generateUlid', () => {
  afterEach(clearFixedUlidSeed);

  it('produces a 26-character Crockford Base32 string', () => {
    expect(isValidUlid(generateUlid())).toBe(true);
  });

  it('encodes the current time in the timestamp prefix', () => {
    const before = Date.now();
    const decoded = ulidToTime(generateUlid());
    const after = Date.now();

    expect(decoded).toBeGreaterThanOrEqual(before);
    expect(decoded).toBeLessThanOrEqual(after);
  });

  it('sorts lexicographically in creation order', () => {
    const first = ulidFromTime(1_700_000_000_000);
    const second = ulidFromTime(1_700_000_001_000);
    const third = ulidFromTime(1_700_000_002_000);

    const shuffled = [third, first, second];
    expect([...shuffled].sort()).toEqual([first, second, third]);
  });

  it('returns a different value on each call', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateUlid()));
    expect(ids.size).toBe(100);
  });

  it('stays deterministic under a fixed seed', () => {
    setFixedUlidSeed(1_700_000_000_000);
    const firstRun = [generateUlid(), generateUlid(), generateUlid()];

    setFixedUlidSeed(1_700_000_000_000);
    const secondRun = [generateUlid(), generateUlid(), generateUlid()];

    expect(secondRun).toEqual(firstRun);
  });
});

describe('ulidFromTime and ulidToTime', () => {
  it('round-trips a millisecond timestamp', () => {
    const ms = 1_735_689_600_123;
    expect(ulidToTime(ulidFromTime(ms))).toBe(ms);
  });

  it('round-trips the top of the 48-bit range', () => {
    // 2^48 - 1 ms, the largest timestamp a ULID can hold.
    const ms = 281_474_976_710_655;
    expect(ulidToTime(ulidFromTime(ms))).toBe(ms);
  });

  it('round-trips the epoch', () => {
    expect(ulidToTime(ulidFromTime(0))).toBe(0);
  });
});

describe('isValidUlid', () => {
  it('accepts a generated ULID', () => {
    expect(isValidUlid(generateUlid())).toBe(true);
  });

  it('rejects a string of the wrong length', () => {
    expect(isValidUlid('0123456789')).toBe(false);
  });

  it('rejects the ambiguous Crockford characters I, L, O, and U', () => {
    for (const ch of ['I', 'L', 'O', 'U']) {
      expect(isValidUlid(ch.repeat(26))).toBe(false);
    }
  });

  it('rejects a non-string input', () => {
    expect(isValidUlid(undefined as unknown as string)).toBe(false);
  });
});
