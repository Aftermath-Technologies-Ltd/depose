// packages/chain/test/timestamp-rfc3161.test.ts
//
// Tests for RFC 3161 timestamp request building and TSR validation.
// NOTE: Live TSA requests are tested as integration tests (skipped in CI
// by default; they require network access and the TSA must be available).

import { describe, it, expect } from 'vitest';
import {
  buildTimeStampReq,
} from '../src/timestamp-rfc3161.js';
import { createHash } from 'node:crypto';

// ── DER structure tests ───────────────────────────────────────────────

describe('buildTimeStampReq', () => {
  it('produces valid DER-encoded timestamp request with nonce', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const { der, nonce } = buildTimeStampReq(hashHex);

    // DER structure must start with SEQUENCE tag (0x30)
    expect(der[0]).toBe(0x30);
    expect(der.length).toBeGreaterThan(20);
    // Nonce must be 8 bytes (CSPRNG)
    expect(nonce).toHaveLength(8);
  });

  it('produces different requests for different hashes', () => {
    const hash1 = createHash('sha256').update('data1', 'utf-8').digest('hex');
    const hash2 = createHash('sha256').update('data2', 'utf-8').digest('hex');

    const { der: req1 } = buildTimeStampReq(hash1);
    const { der: req2 } = buildTimeStampReq(hash2);

    // Different messageImprint should produce different requests
    // (nonce is also random, so they're always different)
    expect(req1).not.toEqual(req2);
  });

  it('includes the SHA-256 hash in the request', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const { der } = buildTimeStampReq(hashHex);

    // The hash bytes should appear somewhere in the DER blob
    const hashBytes = Buffer.from(hashHex, 'hex');
    const found = der.includes(hashBytes);
    expect(found).toBe(true);
  });

  it('generates distinct CSPRNG nonces across 10000 requests (B3)', () => {
    // Sanity check: with a CSPRNG we should never see a collision in
    // 10k 8-byte nonces. With Math.random the chance is still tiny
    // but the entropy source is the regression we're guarding.
    const hashHex = createHash('sha256').update('nonce-test', 'utf-8').digest('hex');
    const seen = new Set<string>();
    const N = 10_000;
    for (let i = 0; i < N; i++) {
      const { nonce } = buildTimeStampReq(hashHex);
      seen.add(nonce.toString('hex'));
    }
    expect(seen.size).toBe(N);
  });
});

// ── DER parser + validation tests ────────────────────────────────────
