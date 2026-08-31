// packages/chain/src/rfc3161-request.ts
//
// DER encoding for the RFC 3161 TimeStampReq we send to a TSA.
// Encoding only: parsing the response lives in rfc3161-asn1.ts.

import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import type { TimeStampReqResult } from './rfc3161-types.js';

// ── DER encoding helpers (request builder) ────────────────────────────

/**
 * SHA-256 AlgorithmIdentifier (with NULL parameter):
 * SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
 */
const SHA256_ALG_ID = Buffer.from([
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
]);

/**
 * SHA-256 OID DER (tag + length + value):
 * 06 09 60 86 48 01 65 03 04 02 01
 */
export const SHA256_OID_DER = Buffer.from([
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
]);

/**
 * Generate a CSPRNG 8-byte nonce for the RFC 3161 request.
 *
 * The nonce binds the TSA's response to a particular request so a
 * replay of an older response is detectable. A predictable nonce
 * would let an attacker prepare a response in advance.
 */
function generateNonce(): Buffer {
  return cryptoRandomBytes(8);
}

/** DER-encode an INTEGER tag + length + value */
function derInteger(value: Buffer): Buffer {
  // If high bit is set, prepend a zero byte
  let content = value;
  if (content[0]! & 0x80) {
    content = Buffer.concat([Buffer.from([0x00]), content]);
  }
  return Buffer.concat([
    Buffer.from([0x02]),
    derLength(content.length),
    content,
  ]);
}

/** DER-encode a BOOLEAN */
function derBoolean(val: boolean): Buffer {
  return Buffer.from([0x01, 0x01, val ? 0xff : 0x00]);
}

/** DER-encode length octets */
function derLength(len: number): Buffer {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  if (len < 0x100) {
    return Buffer.from([0x81, len]);
  }
  // 2-byte length
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

/** DER-encode a SEQUENCE */
function derSequence(contents: Buffer[]): Buffer {
  const inner = Buffer.concat(contents);
  return Buffer.concat([
    Buffer.from([0x30]),
    derLength(inner.length),
    inner,
  ]);
}

/** DER-encode an OCTET STRING */
function derOctetString(data: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0x04]),
    derLength(data.length),
    data,
  ]);
}

/**
 * Build an RFC 3161 TimeStampReq DER blob for the given SHA-256 hash.
 *
 * @returns The DER-encoded request and the 8-byte nonce (for response
 *          validation). The nonce MUST be compared to the nonce echoed
 *          in the TSR to detect replay or mismatched responses.
 */
export function buildTimeStampReq(hashHex: string): TimeStampReqResult {
  const hashBytes = Buffer.from(hashHex, 'hex');

  // MessageImprint
  const messageImprint = derSequence([
    SHA256_ALG_ID,
    derOctetString(hashBytes),
  ]);

  // version = 1
  const version = derInteger(Buffer.from([0x01]));

  // nonce
  const nonce = generateNonce();
  const nonceDer = derInteger(nonce);

  // certReq = true (request TSA certificate in response)
  const certReq = derBoolean(true);

  // TimeStampReq
  const der = derSequence([version, messageImprint, nonceDer, certReq]);
  return { der, nonce };
}

