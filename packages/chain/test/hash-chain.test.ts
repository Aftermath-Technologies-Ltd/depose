// packages/chain/test/hash-chain.test.ts
//
// Tests for IRONROOT-style hash chain construction and verification.

import { describe, it, expect } from 'vitest';
import {
  buildHashChain,
  verifyHashChain,
  computeChainHash,
  extractEventMetadata,
} from '../src/hash-chain.js';
import { sha256, setFixedUlidSeed, clearFixedUlidSeed, generateUlid } from '@depose/core';
import type { Event } from '@depose/core';
import { Buffer } from 'node:buffer';

// ── Helpers ────────────────────────────────────────────────────────────

function makeTestEvent(overrides: Partial<Event> = {}): Event {
  const id = generateUlid();
  const payload = { text: `test event ${id}` };
  return {
    id,
    wallTs: '2025-05-18T15:30:00.000Z',
    monoNs: 0n,
    sessionId: '01JTEST0000000000000000001',
    agentId: 'claude-code',
    parentEventId: null,
    type: 'prompt',
    payload,
    payloadHash: sha256(payload),
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────

describe('extractEventMetadata', () => {
  it('extracts the 8 required fields', () => {
    const event = makeTestEvent();
    const metadata = extractEventMetadata(event);

    expect(Object.keys(metadata).sort()).toEqual([
      'agentId', 'id', 'monoNs', 'parentEventId',
      'payloadHash', 'sessionId', 'type', 'wallTs',
    ]);
  });

  it('includes payloadHash in metadata (IRONROOT intentional duplication)', () => {
    const event = makeTestEvent();
    const metadata = extractEventMetadata(event);
    expect(metadata.payloadHash).toBe(event.payloadHash);
  });
});

describe('computeChainHash', () => {
  it('produces a 32-byte SHA-256 hash', () => {
    const zero32 = Buffer.alloc(32, 0);
    const result = computeChainHash(zero32, 'abc123', { id: 'test' });
    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBe(32);
  });

  it('is deterministic for same inputs', () => {
    const zero32 = Buffer.alloc(32, 0);
    const a = computeChainHash(zero32, 'abc', { id: '1' });
    const b = computeChainHash(zero32, 'abc', { id: '1' });
    expect(a.equals(b)).toBe(true);
  });

  it('differs for different payloadHash', () => {
    const zero32 = Buffer.alloc(32, 0);
    const a = computeChainHash(zero32, 'abc', { id: '1' });
    const b = computeChainHash(zero32, 'def', { id: '1' });
    expect(a.equals(b)).toBe(false);
  });

  it('differs for different metadata', () => {
    const zero32 = Buffer.alloc(32, 0);
    const a = computeChainHash(zero32, 'abc', { id: '1' });
    const b = computeChainHash(zero32, 'abc', { id: '2' });
    expect(a.equals(b)).toBe(false);
  });

  it('differs for different prevHash', () => {
    const zero32 = Buffer.alloc(32, 0);
    const other = Buffer.alloc(32, 1);
    const a = computeChainHash(zero32, 'abc', { id: '1' });
    const b = computeChainHash(other, 'abc', { id: '1' });
    expect(a.equals(b)).toBe(false);
  });
});

describe('buildHashChain', () => {
  it('returns empty results for empty events', () => {
    const { chainedEvents, rootHash } = buildHashChain([]);
    expect(chainedEvents).toEqual([]);
    expect(rootHash).toBe('');
  });

  it('chains a single event using zero32 as prev', () => {
    setFixedUlidSeed(1000);
    const event = makeTestEvent();
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain([event]);

    expect(chainedEvents).toHaveLength(1);
    expect(chainedEvents[0]!.chainHash).toBeDefined();
    expect(chainedEvents[0]!.chainHash).toBe(rootHash);
  });

  it('chains multiple events in order', () => {
    setFixedUlidSeed(2000);
    const e1 = makeTestEvent();
    const e2 = makeTestEvent({ parentEventId: e1.id });
    const e3 = makeTestEvent({ parentEventId: e2.id });
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain([e1, e2, e3]);

    expect(chainedEvents).toHaveLength(3);
    expect(chainedEvents[0]!.chainHash).toBeDefined();
    expect(chainedEvents[1]!.chainHash).toBeDefined();
    expect(chainedEvents[2]!.chainHash).toBeDefined();

    // rootHash is the last event's chainHash
    expect(rootHash).toBe(chainedEvents[2]!.chainHash);

    // Each chainHash should be different (linking creates different inputs)
    expect(chainedEvents[0]!.chainHash).not.toBe(chainedEvents[1]!.chainHash);
    expect(chainedEvents[1]!.chainHash).not.toBe(chainedEvents[2]!.chainHash);
  });

  it('preserves all original event fields', () => {
    setFixedUlidSeed(3000);
    const event = makeTestEvent();
    clearFixedUlidSeed();

    const { chainedEvents } = buildHashChain([event]);
    const chained = chainedEvents[0]!;

    expect(chained.id).toBe(event.id);
    expect(chained.wallTs).toBe(event.wallTs);
    expect(chained.monoNs).toBe(event.monoNs);
    expect(chained.sessionId).toBe(event.sessionId);
    expect(chained.agentId).toBe(event.agentId);
    expect(chained.parentEventId).toBe(event.parentEventId);
    expect(chained.type).toBe(event.type);
    expect(chained.payloadHash).toBe(event.payloadHash);
    expect(chained.chainHash).toBeDefined();
  });

  it('produces deterministic results for same inputs', () => {
    setFixedUlidSeed(4000);
    const e1 = makeTestEvent();
    const e2 = makeTestEvent({ parentEventId: e1.id });
    clearFixedUlidSeed();

    const result1 = buildHashChain([e1, e2]);
    const result2 = buildHashChain([e1, e2]);

    expect(result1.rootHash).toBe(result2.rootHash);
    expect(result1.chainedEvents[0]!.chainHash).toBe(result2.chainedEvents[0]!.chainHash);
    expect(result1.chainedEvents[1]!.chainHash).toBe(result2.chainedEvents[1]!.chainHash);
  });
});

describe('verifyHashChain', () => {
  it('accepts a valid chain', () => {
    setFixedUlidSeed(5000);
    const events = [makeTestEvent(), makeTestEvent(), makeTestEvent()];
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain(events);
    const result = verifyHashChain(chainedEvents, rootHash);

    expect(result.valid).toBe(true);
    expect(result.computedRootHash).toBe(rootHash);
    expect(result.failedAtIndex).toBeNull();
    expect(result.failureDetail).toBeNull();
  });

  it('rejects empty chain with non-empty expected rootHash', () => {
    const result = verifyHashChain([], 'somehash');
    expect(result.valid).toBe(false);
    expect(result.failureDetail).toContain('expected rootHash');
  });

  it('accepts empty chain with empty expected rootHash', () => {
    const result = verifyHashChain([], '');
    expect(result.valid).toBe(true);
  });

  it('detects tampered payload', () => {
    setFixedUlidSeed(6000);
    const e1 = makeTestEvent();
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain([e1]);

    // Tamper: change the payloadHash but keep the chainHash
    const tampered = {
      ...chainedEvents[0]!,
      payloadHash: 'deadbeef' + chainedEvents[0]!.payloadHash.slice(8),
    };

    const result = verifyHashChain([tampered], rootHash);

    expect(result.valid).toBe(false);
    expect(result.failedAtIndex).toBe(0);
    expect(result.failureDetail).toContain('chain hash mismatch');
  });

  it('detects wrong rootHash', () => {
    setFixedUlidSeed(7000);
    const events = [makeTestEvent()];
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain(events);
    const result = verifyHashChain(chainedEvents, 'wrong' + rootHash.slice(6));

    expect(result.valid).toBe(false);
    expect(result.failureDetail).toContain('rootHash mismatch');
  });

  it('detects event reordering', () => {
    setFixedUlidSeed(8000);
    const e1 = makeTestEvent();
    const e2 = makeTestEvent({ parentEventId: e1.id });
    clearFixedUlidSeed();

    const { chainedEvents, rootHash } = buildHashChain([e1, e2]);

    // Reverse order, chain hashes will no longer be valid
    const reversed = [chainedEvents[1]!, chainedEvents[0]!];
    // But note: the chainHash values themselves are wrong for the reversed order
    // because they were computed for the original order
    const result = verifyHashChain(reversed, rootHash);

    expect(result.valid).toBe(false);
  });
});