// packages/chain/test/timestamp-rfc3161.test.ts
//
// Tests for RFC 3161 timestamp request building and local verification.
// NOTE: Live TSA requests are tested as integration tests (skipped in CI
// by default — they require network access and the TSA must be available).

import { describe, it, expect } from 'vitest';
import {
  buildTimeStampReq,
  extractTimestampFromTsr,
  verifyTimestamp,
  DEFAULT_TSA_ENDPOINTS,
} from '../src/timestamp-rfc3161.js';
import { createHash } from 'node:crypto';

// ── DER structure tests ───────────────────────────────────────────────

describe('buildTimeStampReq', () => {
  it('produces valid DER-encoded timestamp request', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const req = buildTimeStampReq(hashHex);

    // DER structure must start with SEQUENCE tag (0x30)
    expect(req[0]).toBe(0x30);
    expect(req.length).toBeGreaterThan(20);
  });

  it('produces different requests for different hashes', () => {
    const hash1 = createHash('sha256').update('data1', 'utf-8').digest('hex');
    const hash2 = createHash('sha256').update('data2', 'utf-8').digest('hex');

    const req1 = buildTimeStampReq(hash1);
    const req2 = buildTimeStampReq(hash2);

    // Different messageImprint should produce different requests
    // (nonce is also random, so they're always different)
    expect(req1).not.toEqual(req2);
  });

  it('includes the SHA-256 hash in the request', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const req = buildTimeStampReq(hashHex);

    // The hash bytes should appear somewhere in the DER blob
    const hashBytes = Buffer.from(hashHex, 'hex');
    const found = req.includes(hashBytes);
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
      const req = buildTimeStampReq(hashHex);
      // The nonce is a DER INTEGER appearing after the messageImprint.
      // We approximate by taking a fingerprint of the whole request,
      // which differs whenever the nonce differs.
      seen.add(req.toString('hex'));
    }
    expect(seen.size).toBe(N);
  });
});

describe('extractTimestampFromTsr', () => {
  it('returns null for invalid DER', () => {
    const result = extractTimestampFromTsr(Buffer.from('not valid der'));
    expect(result).toBeNull();
  });

  it('returns null for empty buffer', () => {
    const result = extractTimestampFromTsr(Buffer.alloc(0));
    expect(result).toBeNull();
  });

  it('extracts timestamp from a synthetic GeneralizedTime', () => {
    // Construct a minimal DER with a GeneralizedTime field
    // GeneralizedTime tag: 0x18, length: 15, value: "20250518153000Z"
    const timeStr = '20250518153000Z';
    const timeBytes = Buffer.from(timeStr, 'ascii');
    const der = Buffer.concat([
      Buffer.from([0x30, timeBytes.length + 4]), // SEQUENCE wrapper
      Buffer.from([0x18, timeBytes.length]),      // GeneralizedTime
      timeBytes,
      Buffer.from([0x05, 0x00]),                   // NULL
    ]);

    const result = extractTimestampFromTsr(der);
    expect(result).toBe('2025-05-18T15:30:00.000Z');
  });
});

describe('verifyTimestamp', () => {
  it('rejects invalid base64', () => {
    const result = verifyTimestamp('not-valid-base64!!!', 'abc123');
    expect(result.valid).toBe(false);
  });

  it('rejects DER without SEQUENCE tag', () => {
    const badDer = Buffer.alloc(10, 0x05); // not SEQUENCE
    const result = verifyTimestamp(badDer.toString('base64'), 'abc123');
    expect(result.valid).toBe(false);
    expect(result.detail).toContain('SEQUENCE');
  });

  it('accepts a token that contains the expected hash', () => {
    // Build a synthetic DER that contains our hash
    const hashHex = createHash('sha256').update('test manifest', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');

    // Synthetic DER: SEQUENCE + hash bytes + some padding
    const inner = Buffer.concat([
      Buffer.from([0x04, hashBytes.length]),
      hashBytes,
      Buffer.alloc(4, 0x00), // padding
    ]);
    const der = Buffer.concat([
      Buffer.from([0x30]),
      Buffer.from([inner.length]),
      inner,
    ]);

    const result = verifyTimestamp(der.toString('base64'), hashHex);
    expect(result.valid).toBe(true);
  });

  it('rejects a token that does not contain the expected hash', () => {
    const hashHex = createHash('sha256').update('test manifest', 'utf-8').digest('hex');
    const wrongHash = createHash('sha256').update('wrong data', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(wrongHash, 'hex');

    const inner = Buffer.concat([
      Buffer.from([0x04, hashBytes.length]),
      hashBytes,
    ]);
    const der = Buffer.concat([
      Buffer.from([0x30]),
      Buffer.from([inner.length]),
      inner,
    ]);

    const result = verifyTimestamp(der.toString('base64'), hashHex);
    expect(result.valid).toBe(false);
    expect(result.detail).toContain('mismatch');
  });
});

describe('DEFAULT_TSA_ENDPOINTS', () => {
  it('has exactly 2 endpoints (FreeTSA + DigiCert)', () => {
    expect(DEFAULT_TSA_ENDPOINTS).toHaveLength(2);
  });

  it('FreeTSA is first (primary)', () => {
    expect(DEFAULT_TSA_ENDPOINTS[0]!.name).toBe('FreeTSA');
  });

  it('DigiCert is second (fallback)', () => {
    expect(DEFAULT_TSA_ENDPOINTS[1]!.name).toBe('DigiCert');
  });

  it('all endpoints have HTTPS URLs', () => {
    for (const endpoint of DEFAULT_TSA_ENDPOINTS) {
      expect(endpoint.url).toMatch(/^https:\/\//);
    }
  });
});