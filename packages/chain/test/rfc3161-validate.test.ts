// packages/chain/test/rfc3161-validate.test.ts
//
// Validating a TimeStampResp: the nonce has to be the one we sent and
// the messageImprint the hash we asked about, or the token dates
// something else. Request encoding is in timestamp-rfc3161.test.ts.

import { describe, it, expect } from 'vitest';
import {
  validateTsr,
  TsrValidationError,
  DEFAULT_TSA_ENDPOINTS,
} from '../src/timestamp-rfc3161.js';
import { createHash, randomBytes } from 'node:crypto';
import {
  buildMinimalTimeStampResp,
  buildMinimalTimeStampRespWithAlgId,
  buildMinimalTimeStampRespWithGenTime,
  buildMinimalTimeStampRespWithRawNonceBytes,
  derSequence,
} from './rfc3161-der-fixtures.js';

// ── DER structure tests ───────────────────────────────────────────────


describe('validateTsr', () => {
  it('rejects invalid DER', () => {
    expect(() => validateTsr(Buffer.from('not valid der'), randomBytes(8), 'ab')).toThrow(TsrValidationError);
  });

  it('rejects empty buffer', () => {
    expect(() => validateTsr(Buffer.alloc(0), randomBytes(8), 'ab')).toThrow(TsrValidationError);
  });

  it('rejects a TSR with wrong nonce (replay/mismatch)', () => {
    // Build a full TimeStampResp structure with a known nonce and hash,
    // then validate with a different nonce.
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');
    const correctNonce = randomBytes(8);

    // Build a minimal TimeStampResp with the correct nonce and hash
    const tsr = buildMinimalTimeStampResp(hashBytes, correctNonce);

    const wrongNonce = Buffer.from(correctNonce);
    wrongNonce[0]! ^= 0xff; // flip first byte

    expect(() => validateTsr(tsr, wrongNonce, hashHex)).toThrow(/Nonce mismatch/);
  });

  it('rejects a TSR with wrong messageImprint hash', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');
    const nonce = randomBytes(8);

    const tsr = buildMinimalTimeStampResp(hashBytes, nonce);

    const wrongHashHex = createHash('sha256').update('wrong data', 'utf-8').digest('hex');
    expect(() => validateTsr(tsr, nonce, wrongHashHex)).toThrow(/MessageImprint hash mismatch/);
  });

  it('accepts a valid TSR with matching nonce and hash', () => {
    const hashHex = createHash('sha256').update('test data', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');
    const nonce = randomBytes(8);

    const tsr = buildMinimalTimeStampResp(hashBytes, nonce);

    const result = validateTsr(tsr, nonce, hashHex);
    expect(result.timestamp).toBe('2025-05-18T15:30:00.000Z');
    expect(result.nonce).not.toBeNull();
    expect(result.messageImprint.hashedMessage.toString('hex')).toBe(hashHex);
  });

  it('rejects a TSR with a non-SHA-256 algorithm in messageImprint', () => {
    const hashBytes = randomBytes(32);
    const nonce = randomBytes(8);

    // Use SHA-1 OID instead of SHA-256
    // SHA-1 OID: 1.3.14.3.2.26 → 06 05 2b 0e 03 02 1a
    const sha1OidDer = Buffer.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    const sha1AlgId = derSequence([sha1OidDer, Buffer.from([0x05, 0x00])]); // AlgId with NULL param

    const tsr = buildMinimalTimeStampRespWithAlgId(hashBytes, nonce, sha1AlgId);
    const hashHex = hashBytes.toString('hex');

    expect(() => validateTsr(tsr, nonce, hashHex)).toThrow(/not SHA-256/);
  });

  it('extracts genTime with fractional seconds', () => {
    const hashHex = createHash('sha256').update('fractional test', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');
    const nonce = randomBytes(8);

    // Build TSR with fractional-second genTime: 20250518153000.123Z
    const tsr = buildMinimalTimeStampRespWithGenTime(hashBytes, nonce, '20250518153000.123Z');

    const result = validateTsr(tsr, nonce, hashHex);
    expect(result.timestamp).toBe('2025-05-18T15:30:00.123Z');
  });

  it('accepts a TSR whose nonce omits the DER sign-padding byte (FreeTSA laxity)', () => {
    // Regression for the FreeTSA encoding quirk that broke verify-examples
    // in CI. The request nonce starts with 0x00 followed by a high-bit
    // byte, so strict DER keeps the 0x00 sign pad. FreeTSA echoes back
    // the same integer without the pad. Both are the same unsigned
    // integer value; validateTsr must treat them as equal.
    const hashHex = createHash('sha256').update('lax-nonce test', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');

    // 8-byte request nonce: first byte 0x00, second byte 0xfe (high bit set).
    const requestNonce = Buffer.from([0x00, 0xfe, 0x5f, 0x90, 0x16, 0xaf, 0xe3, 0x5d]);
    // The lax TSA emits the INTEGER content as just the 7 significant
    // bytes (no sign pad), which is invalid strict DER but interoperable.
    const laxNonceContent = Buffer.from([0xfe, 0x5f, 0x90, 0x16, 0xaf, 0xe3, 0x5d]);

    const tsr = buildMinimalTimeStampRespWithRawNonceBytes(hashBytes, laxNonceContent);

    const result = validateTsr(tsr, requestNonce, hashHex);
    expect(result.nonce).not.toBeNull();
  });

  it('still rejects a TSR whose nonce has a different integer value', () => {
    const hashHex = createHash('sha256').update('mismatch test', 'utf-8').digest('hex');
    const hashBytes = Buffer.from(hashHex, 'hex');
    const requestNonce = Buffer.from([0x00, 0xfe, 0x5f, 0x90, 0x16, 0xaf, 0xe3, 0x5d]);
    const differentNonce = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02]);

    const tsr = buildMinimalTimeStampResp(hashBytes, differentNonce);
    expect(() => validateTsr(tsr, requestNonce, hashHex)).toThrow(/Nonce mismatch/);
  });
});

// ── Constant-time comparison test ─────────────────────────────────────

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

