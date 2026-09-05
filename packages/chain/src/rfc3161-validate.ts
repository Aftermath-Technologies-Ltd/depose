// packages/chain/src/rfc3161-validate.ts
//
// Validating a TimeStampResp before it is ever treated as evidence: the
// TSTInfo has to parse, the nonce has to be the one this producer sent,
// and the messageImprint has to be the hash that was asked about.
//
// A token that fails any of these is not a weaker token, it is a
// different token, and shipping one would let a TSA (or anything on the
// wire) date something the producer never submitted. Signature and
// certificate-chain verification live in the Go verifier
// (apps/verify/timestamp/rfc3161.go), which is what a recipient runs.

import { timingSafeEqual } from 'node:crypto';
import { TsrValidationError } from './rfc3161-types.js';
import type { TsrValidationResult } from './rfc3161-types.js';
import { SHA256_OID_DER } from './rfc3161-request.js';
import { findTstInfoBytes, parseTstInfoFields, trimLeadingZeroBytes } from './rfc3161-asn1.js';

/**
 * Validate a TSR (TimeStampResp or bare TimeStampToken) by:
 *   1. Parsing the DER structure to find TSTInfo
 *   2. Extracting genTime, nonce, and messageImprint
 *   3. Verifying nonce matches the request nonce (if echoed)
 *   4. Verifying messageImprint uses SHA-256
 *   5. Verifying messageImprint hashedMessage matches the expected hash
 *
 * Throws {@link TsrValidationError} on any failure.  Callers should
 * discard the token and try the next TSA.
 */
export function validateTsr(
  tsrDer: Buffer,
  expectedNonce: Buffer,
  expectedHashHex: string
): TsrValidationResult {
  // 1. Navigate to TSTInfo bytes
  const tstInfoBytes = findTstInfoBytes(tsrDer);

  // 2. Parse TSTInfo fields
  const { genTime, nonce, messageImprint } = parseTstInfoFields(tstInfoBytes);

  // 3. Verify nonce (if the TSA echoed one).
  //
  // The nonce is logically an unsigned big-endian integer. The request
  // encodes it as a DER INTEGER, prepending 0x00 when the high bit of
  // the first byte is set (so the value is unambiguously positive).
  // Real-world TSAs are inconsistent about strict-DER re-encoding:
  // FreeTSA in particular has been observed to echo back the nonce
  // *without* the sign-padding byte, so an 8-byte request nonce starting
  // with 0xfe comes back as 7 bytes. parseTstInfoFields() already strips
  // a leading 0x00 sign-pad on the response side; we apply the same
  // normalization to the request-side bytes before comparing so the
  // two are compared as integer values, not as raw buffers. This is
  // safe because the nonce's only job is replay protection, and equal
  // integer values give equal replay-protection guarantees regardless
  // of which encoding the TSA chose to send back.
  if (nonce !== null) {
    const normalizedExpected = trimLeadingZeroBytes(expectedNonce);
    const normalizedActual = trimLeadingZeroBytes(nonce);
    if (
      normalizedActual.length !== normalizedExpected.length ||
      !timingSafeEqual(normalizedActual, normalizedExpected)
    ) {
      throw new TsrValidationError(
        `Nonce mismatch: TSR nonce ${nonce.toString('hex')} != request nonce ${expectedNonce.toString('hex')}`,
      );
    }
  }

  // 4. Verify messageImprint algorithm is SHA-256
  if (!messageImprint.algorithmOidDer.equals(SHA256_OID_DER)) {
    throw new TsrValidationError(
      `MessageImprint algorithm is not SHA-256 (got DER: ${messageImprint.algorithmOidDer.toString('hex')})`
    );
  }

  // 5. Verify messageImprint hashedMessage matches the expected hash
  const expectedHash = Buffer.from(expectedHashHex, 'hex');
  if (
    messageImprint.hashedMessage.length !== expectedHash.length ||
    !timingSafeEqual(messageImprint.hashedMessage, expectedHash)
  ) {
    throw new TsrValidationError(
      `MessageImprint hash mismatch: TSR has ${messageImprint.hashedMessage.toString('hex')}, expected ${expectedHashHex}`
    );
  }

  return { timestamp: genTime, nonce, messageImprint };
}

