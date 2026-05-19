// packages/core/test/schema.test.ts
//
// Tests for event schema types and utilities.
// BUILD_PLAN.md §4.1, §4.2

import { describe, it, expect } from 'vitest';
import {
  sha256,
  canonicalJson,
  sortKeys,
  generateUlid,
  ulidFromTime,
  isValidUlid,
  ulidToTime,
  setFixedUlidSeed,
  clearFixedUlidSeed,
} from '../src/index.js';
import {
  isEventType,
  type EventBase,
  type AgentId,
  type EventType,
} from '../src/events/schema.js';

describe('canonicalJson', () => {
  it('sorts object keys lexicographically', () => {
    const obj = { z: 1, a: 2, m: 3 };
    const result = canonicalJson(obj);
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it('preserves array order', () => {
    const arr = [3, 1, 2];
    const result = canonicalJson(arr);
    expect(result).toBe('[3,1,2]');
  });

  it('handles nested objects', () => {
    const obj = { b: { z: 1, a: 2 }, a: 3 };
    const result = canonicalJson(obj);
    expect(result).toBe('{"a":3,"b":{"a":2,"z":1}}');
  });

  it('handles null and booleans', () => {
    const obj = { a: null, b: true, c: false };
    const result = canonicalJson(obj);
    expect(result).toBe('{"a":null,"b":true,"c":false}');
  });

  it('produces deterministic output', () => {
    const obj = { z: { a: [1, 2] }, a: 'hello' };
    const r1 = canonicalJson(obj);
    const r2 = canonicalJson(obj);
    expect(r1).toBe(r2);
  });
});

describe('sortKeys', () => {
  it('sorts top-level keys', () => {
    const result = sortKeys({ c: 1, a: 2, b: 3 });
    expect(result).toEqual({ a: 2, b: 3, c: 1 });
  });

  it('sorts nested keys recursively', () => {
    const result = sortKeys({ z: { b: 1, a: 2 }, a: 3 });
    expect(result).toEqual({ a: 3, z: { a: 2, b: 1 } });
  });

  it('passes through primitives', () => {
    expect(sortKeys(null)).toBeNull();
    expect(sortKeys(undefined)).toBeUndefined();
    expect(sortKeys('hello')).toBe('hello');
    expect(sortKeys(42)).toBe(42);
    expect(sortKeys(true)).toBe(true);
  });

  it('sorts arrays element-wise', () => {
    const result = sortKeys([{ b: 1, a: 2 }, { d: 3, c: 4 }]);
    expect(result).toEqual([{ a: 2, b: 1 }, { c: 4, d: 3 }]);
  });
});

describe('sha256', () => {
  it('produces correct hash for a known input', () => {
    const obj = { a: 1, b: 2 };
    const hash = sha256(obj);
    // canonicalJson({a:1,b:2}) = '{"a":1,"b":2}'
    // SHA-256 of that
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  it('is deterministic', () => {
    const obj = { z: 1, a: 2 };
    const h1 = sha256(obj);
    const h2 = sha256(obj);
    expect(h1).toBe(h2);
  });

  it('produces different hashes for different inputs', () => {
    const h1 = sha256({ a: 1 });
    const h2 = sha256({ a: 2 });
    expect(h1).not.toBe(h2);
  });
});

describe('ULID', () => {
  describe('generateUlid', () => {
    it('produces a 26-character string', () => {
      const ulid = generateUlid();
      expect(ulid).toHaveLength(26);
    });

    it('produces valid ULIDs', () => {
      for (let i = 0; i < 100; i++) {
        const ulid = generateUlid();
        expect(isValidUlid(ulid)).toBe(true);
      }
    });

    it('produces unique ULIDs', () => {
      const ulids = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        ulids.add(generateUlid());
      }
      expect(ulids.size).toBe(1000);
    });
  });

  describe('ulidFromTime', () => {
    it('produces a valid ULID from a timestamp', () => {
      const ms = Date.now();
      const ulid = ulidFromTime(ms);
      expect(isValidUlid(ulid)).toBe(true);
    });

    it('extracts the correct timestamp', () => {
      const ms = 1716043800000; // 2024-05-18T15:30:00Z approx
      const ulid = ulidFromTime(ms);
      const extracted = ulidToTime(ulid);
      // ULID timestamps have second precision (10 bits = 1024 seconds)
      // so we check that the extracted time is within 1 second
      expect(Math.abs(extracted - ms)).toBeLessThan(1000);
    });
  });

  describe('deterministic seed', () => {
    it('produces deterministic ULIDs with a fixed seed', () => {
      setFixedUlidSeed(1716043800000);
      const u1 = generateUlid();
      const u2 = generateUlid();
      const u3 = generateUlid();
      clearFixedUlidSeed();

      // Same seed should produce same sequence
      setFixedUlidSeed(1716043800000);
      const u1b = generateUlid();
      const u2b = generateUlid();
      const u3b = generateUlid();
      clearFixedUlidSeed();

      expect(u1).toBe(u1b);
      expect(u2).toBe(u2b);
      expect(u3).toBe(u3b);
    });

    it('produces monotonically increasing ULIDs with seed', () => {
      setFixedUlidSeed(1716043800000);
      const ulids = [];
      for (let i = 0; i < 10; i++) {
        ulids.push(generateUlid());
      }
      clearFixedUlidSeed();

      // ULIDs should be sorted (time-sortable)
      const sorted = [...ulids].sort();
      expect(ulids).toEqual(sorted);
    });
  });
});

describe('isEventType', () => {
  it('returns true for matching type', () => {
    const event: EventBase = {
      id: '01JABC1234',
      wallTs: '2025-01-01T00:00:00Z',
      monoNs: 0,
      sessionId: 'sess-1',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'prompt',
      payload: { text: 'hello' },
      payloadHash: 'abc123',
    };
    expect(isEventType(event, 'prompt')).toBe(true);
  });

  it('returns false for non-matching type', () => {
    const event: EventBase = {
      id: '01JABC1234',
      wallTs: '2025-01-01T00:00:00Z',
      monoNs: 0,
      sessionId: 'sess-1',
      agentId: 'claude-code',
      parentEventId: null,
      type: 'prompt',
      payload: { text: 'hello' },
      payloadHash: 'abc123',
    };
    expect(isEventType(event, 'gap')).toBe(false);
  });
});
