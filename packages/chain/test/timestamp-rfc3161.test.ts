// packages/chain/test/timestamp-rfc3161.test.ts
//
// Tests for RFC 3161 timestamp request building and TSR validation.
// NOTE: Live TSA requests are tested as integration tests (skipped in CI
// by default; they require network access and the TSA must be available).

import { describe, it, expect } from 'vitest';
import {
  buildTimeStampReq,
  validateTsr,
  TsrValidationError,
  DEFAULT_TSA_ENDPOINTS,
} from '../src/timestamp-rfc3161.js';
import { createHash, randomBytes } from 'node:crypto';

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

// ── Helpers for constructing synthetic TSR DER ────────────────────────

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derSequence(contents: Buffer[]): Buffer {
  const inner = Buffer.concat(contents);
  return Buffer.concat([Buffer.from([0x30]), derLength(inner.length), inner]);
}

function derOctetString(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x04]), derLength(data.length), data]);
}

function derIntegerFromBuffer(value: Buffer): Buffer {
  let content = value;
  if (content[0]! & 0x80) {
    content = Buffer.concat([Buffer.from([0x00]), content]);
  }
  return Buffer.concat([Buffer.from([0x02]), derLength(content.length), content]);
}

/**
 * Emit an INTEGER whose content bytes are exactly what was passed in,
 * with no sign-pad normalization. Models the lax-DER behavior of TSAs
 * (notably FreeTSA) that omit the sign-pad byte even when strict DER
 * would require it for positive integers.
 */
function derIntegerRawContent(value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x02]), derLength(value.length), value]);
}

function derGeneralizedTime(timeStr: string): Buffer {
  const timeBytes = Buffer.from(timeStr, 'ascii');
  return Buffer.concat([Buffer.from([0x18]), derLength(timeBytes.length), timeBytes]);
}

// SHA-256 AlgorithmIdentifier
const SHA256_ALG_ID = Buffer.from([
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
]);

/**
 * Build a minimal TimeStampResp DER structure for testing.
 *
 * TimeStampResp ::= SEQUENCE {
 *   status  PKIStatusInfo,
 *   token   ContentInfo OPTIONAL
 * }
 *
 * PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString DisplayText OPTIONAL }
 *
 * ContentInfo wraps SignedData → encapContentInfo → OCTET STRING(TSTInfo)
 */
function buildMinimalTimeStampResp(hashBytes: Buffer, nonce: Buffer): Buffer {
  return buildMinimalTimeStampRespWithAlgId(hashBytes, nonce, SHA256_ALG_ID);
}

function buildMinimalTimeStampRespWithAlgId(
  hashBytes: Buffer,
  nonce: Buffer,
  algId: Buffer
): Buffer {
  const genTimeStr = '20250518153000Z';
  return buildMinimalTimeStampRespWithAlgIdAndGenTime(hashBytes, nonce, algId, genTimeStr);
}

function buildMinimalTimeStampRespWithGenTime(
  hashBytes: Buffer,
  nonce: Buffer,
  genTimeStr: string
): Buffer {
  return buildMinimalTimeStampRespWithAlgIdAndGenTime(hashBytes, nonce, SHA256_ALG_ID, genTimeStr);
}

/**
 * Build a TimeStampResp whose nonce INTEGER is encoded with the raw
 * content bytes you supply (no sign-pad normalization). Use to model
 * a TSA that returns a non-strict-DER nonce encoding.
 */
function buildMinimalTimeStampRespWithRawNonceBytes(
  hashBytes: Buffer,
  rawNonceContent: Buffer,
): Buffer {
  return buildMinimalTimeStampRespCore(
    hashBytes,
    derIntegerRawContent(rawNonceContent),
    SHA256_ALG_ID,
    '20250518153000Z',
  );
}

function buildMinimalTimeStampRespWithAlgIdAndGenTime(
  hashBytes: Buffer,
  nonce: Buffer,
  algId: Buffer,
  genTimeStr: string
): Buffer {
  return buildMinimalTimeStampRespCore(
    hashBytes,
    derIntegerFromBuffer(nonce),
    algId,
    genTimeStr,
  );
}

function buildMinimalTimeStampRespCore(
  hashBytes: Buffer,
  nonceDer: Buffer,
  algId: Buffer,
  genTimeStr: string,
): Buffer {
  // ── TSTInfo ──
  // TSTInfo (using UNIVERSAL tags to match typical DER output):
  // SEQUENCE {
  //   version          INTEGER 1,
  //   policy           OID (any),
  //   messageImprint   SEQUENCE { SHA256AlgId, OCTET STRING hashBytes },
  //   serialNumber     INTEGER 1,
  //   genTime          GeneralizedTime,
  //   nonce            INTEGER nonce,
  // }
  const policyOid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1e]); // arbitrary OID

  const messageImprint = derSequence([algId, derOctetString(hashBytes)]);

  const tstInfo = derSequence([
    derIntegerFromBuffer(Buffer.from([0x01])),     // version
    policyOid,                                      // policy
    messageImprint,                                  // messageImprint
    derIntegerFromBuffer(Buffer.from([0x01])),     // serialNumber
    derGeneralizedTime(genTimeStr),                 // genTime
    nonceDer,                                       // nonce (pre-encoded)
  ]);

  // Wrap TSTInfo in OCTET STRING (eContent)
  const tstInfoContent = derOctetString(tstInfo);

  // encapContentInfo = SEQUENCE { eContentType OID, [0] EXPLICIT eContent }
  const eContentTypeOid = Buffer.from([
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x0d,
  ]); // id-ct-TSTInfo OID
  const encapContentInfo = derSequence([
    eContentTypeOid,
    Buffer.concat([Buffer.from([0xa0]), derLength(tstInfoContent.length), tstInfoContent]),
  ]);

  // digestAlgorithms = SEQUENCE { SEQUENCE { SHA-256 OID, NULL } }
  const digestAlgorithms = derSequence([SHA256_ALG_ID]);

  // version = INTEGER 3 (for SignedData v3)
  const signedDataVersion = derIntegerFromBuffer(Buffer.from([0x03]));

  // SignedData = SEQUENCE { version, digestAlgorithms, encapContentInfo }
  const signedData = derSequence([signedDataVersion, digestAlgorithms, encapContentInfo]);

  // ContentInfo = SEQUENCE { OID, [0] EXPLICIT SignedData }
  const contentTypeOid = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
  ]); // id-signedData OID (1.2.840.113549.1.7.2)
  const contentInfo = derSequence([
    contentTypeOid,
    Buffer.concat([Buffer.from([0xa0]), derLength(signedData.length), signedData]),
  ]);

  // PKIStatusInfo = SEQUENCE { status INTEGER 0 (granted) }
  const pkiStatusInfo = derSequence([
    derIntegerFromBuffer(Buffer.from([0x00])),
  ]);

  // TimeStampResp = SEQUENCE { status, token }
  return derSequence([pkiStatusInfo, contentInfo]);
}