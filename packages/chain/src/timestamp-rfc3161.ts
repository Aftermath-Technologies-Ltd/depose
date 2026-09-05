// packages/chain/src/timestamp-rfc3161.ts
//
// RFC 3161 timestamping for DEPOSE evidence bundles.
//
// TSA configuration:
//   Primary: FreeTSA (https://freetsa.org)
//   Fallback: DigiCert
//   Record which TSA responded in the token metadata.
//
// A bundle MUST have at least one RFC 3161 timestamp.
// If both TSAs fail, the bundle is not produced (build plan: "Never produce
// a bundle without a timestamp; that defeats the purpose").
//
// F-04 remediation: proper ASN.1 DER parsing replaces the heuristic byte-scan,
// nonce verification and messageImprint verification are mandatory, and the
// local-clock fallback is removed entirely. A TSR that fails validation is
// discarded and the next TSA is tried, no bundle ever ships an unvalidated
// token.
//
// Request encoding lives in rfc3161-request.ts and response parsing in
// rfc3161-asn1.ts; this file is the validate-and-fetch flow that uses them.

import { createHash, timingSafeEqual } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { buildTimeStampReq, SHA256_OID_DER } from './rfc3161-request.js';
import {
  findTstInfoBytes,
  parseTstInfoFields,
  trimLeadingZeroBytes,
} from './rfc3161-asn1.js';
import { DEFAULT_TSA_ENDPOINTS, TsrValidationError } from './rfc3161-types.js';
import type {
  TsaEndpoint,
  Rfc3161Token,
  TimestampOptions,
  TsrValidationResult,
} from './rfc3161-types.js';

export { DEFAULT_TSA_ENDPOINTS, TsrValidationError } from './rfc3161-types.js';
export { buildTimeStampReq } from './rfc3161-request.js';
export type {
  TsaEndpoint,
  Rfc3161Token,
  TimestampOptions,
  TimeStampReqResult,
  TsrValidationResult,
} from './rfc3161-types.js';

// ── Validate TSR ─────────────────────────────────────────────────────

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

// ── TSA HTTP request ──────────────────────────────────────────────────

/**
 * Send a timestamp request to a TSA endpoint.
 * Returns the raw .tsr response body on success.
 */
function sendTsaRequest(
  endpoint: TsaEndpoint,
  queryDer: Buffer,
  timeoutMs: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint.url);
    const isHttps = url.protocol === 'https:';
    const requestFn = isHttps ? httpsRequest : httpRequest;

    const req = requestFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': endpoint.contentType,
        'Content-Length': queryDer.length,
        'Accept': 'application/timestamp-reply',
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body);
        } else {
          reject(new Error(
            `TSA ${endpoint.name} returned HTTP ${res.statusCode}: ${body.toString('utf-8').slice(0, 200)}`
          ));
        }
      });
    });

    req.on('error', (err: Error) => {
      reject(new Error(`TSA ${endpoint.name} request failed: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`TSA ${endpoint.name} timed out after ${timeoutMs}ms`));
    });

    req.write(queryDer);
    req.end();
  });
}

// ── Main timestamping function ────────────────────────────────────────

/**
 * Request an RFC 3161 timestamp from a TSA, with fallback.
 *
 * Iterates the configured endpoints in order. For each endpoint:
 *   1. Send a TimeStampReq with a CSPRNG nonce and the manifest's SHA-256.
 *   2. Parse and validate the TSR: proper DER walk to find TSTInfo,
 *      nonce verification, messageImprint hash verification, algorithm check.
 *   3. If validation fails, discard the token and try the next TSA.
 *      Never ship an unvalidated token.
 *
 * The old heuristic byte-scan for 0x18 and the local-clock fallback
 * (`new Date().toISOString()`) have been removed (F-04). If no TSA
 * produces a valid token, the bundle is not produced.
 *
 * @param dataToTimestamp - canonical JSON of manifest (or any bytes)
 * @param options - TSA endpoints / per-request timeout / multi-anchor
 * @returns Array of RFC 3161 tokens, length 1 by default, up to
 *          `endpoints.length` when `requireAll: true`
 */
export async function requestTimestamps(
  dataToTimestamp: string,
  options?: TimestampOptions
): Promise<Rfc3161Token[]> {
  const endpoints = options?.tsaEndpoints ?? DEFAULT_TSA_ENDPOINTS;
  const timeoutMs = options?.timeoutMs ?? 15000;
  const requireAll = options?.requireAll === true;
  const tokens: Rfc3161Token[] = [];
  const errors: string[] = [];

  // Compute SHA-256 of the data
  const hashHex = createHash('sha256').update(dataToTimestamp, 'utf-8').digest('hex');

  // Build the RFC 3161 request (includes a CSPRNG nonce for response binding)
  const { der: queryDer, nonce } = buildTimeStampReq(hashHex);

  for (const endpoint of endpoints) {
    try {
      const tsrDer = await sendTsaRequest(endpoint, queryDer, timeoutMs);

      // Validate the TSR: parse TSTInfo, verify nonce and messageImprint.
      // If validation fails, the error propagates to the catch block below,
      // and we try the next TSA. We never ship an unvalidated token.
      const result = validateTsr(tsrDer, nonce, hashHex);

      tokens.push({
        tsa: endpoint.name,
        timestamp: result.timestamp,
        tokenBase64: tsrDer.toString('base64'),
      });

      // Stop after first success unless multi-anchor was requested.
      if (!requireAll) {
        break;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`${endpoint.name}: ${msg}`);
    }
  }

  if (tokens.length === 0) {
    throw new Error(
      `All RFC 3161 TSA endpoints failed. Cannot produce bundle without timestamp.\n` +
      `Errors:\n  ${errors.join('\n  ')}\n` +
      `A bundle without a timestamp defeats the purpose of evidence integrity.`
    );
  }

  return tokens;
}

// F-04: The old `extractTimestampFromTsr` (heuristic byte-scan for 0x18)
// and the `new Date().toISOString()` fallback have been removed. All TSR
// validation now goes through `validateTsr`, which performs proper ASN.1
// DER parsing, nonce verification, and messageImprint verification.
// Cryptographic signature + cert-chain verification still lives in the
// Go verifier (apps/verify/timestamp/rfc3161.go).
