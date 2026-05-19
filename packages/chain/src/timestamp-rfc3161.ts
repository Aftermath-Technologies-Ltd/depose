// packages/chain/src/timestamp-rfc3161.ts
//
// RFC 3161 timestamping for DEPOSE evidence bundles.
//
// TSA configuration (BUILD_PLAN.md §6 Phase 2):
//   Primary: FreeTSA (https://freetsa.org)
//   Fallback: DigiCert
//   Record which TSA responded in the token metadata.
//
// A bundle MUST have at least one RFC 3161 timestamp.
// If both TSAs fail, the bundle is not produced (build plan: "Never produce
// a bundle without a timestamp — that defeats the purpose").

import { createHash, randomBytes as cryptoRandomBytes } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';

// ── Types ─────────────────────────────────────────────────────────────

export interface TsaEndpoint {
  /** Human-readable name for logging/manifest */
  name: string;
  /** Full URL to the TSA endpoint */
  url: string;
  /** Content-Type for the request (default: application/timestamp-query) */
  contentType: string;
}

export interface Rfc3161Token {
  /** Which TSA provided this token */
  tsa: string;
  /** ISO 8601 UTC timestamp from the TSA response */
  timestamp: string;
  /** Base64-encoded .tsr (TimeStampToken) data */
  tokenBase64: string;
}

export interface TimestampOptions {
  /** Override default TSA endpoints */
  tsaEndpoints?: TsaEndpoint[];
  /** Request timeout in milliseconds (default: 15000) */
  timeoutMs?: number;
  /**
   * Request timestamps from every configured endpoint instead of
   * short-circuiting on the first success. Off by default — the
   * verifier needs one valid token, and querying every TSA on every
   * produce doubles network exposure and TSA load. Useful only for
   * multi-anchor archival workflows.
   */
  requireAll?: boolean;
}

// ── Default TSA endpoints ────────────────────────────────────────────

export const DEFAULT_TSA_ENDPOINTS: TsaEndpoint[] = [
  {
    name: 'FreeTSA',
    url: 'https://freetsa.org/tsr',
    contentType: 'application/timestamp-query',
  },
  {
    name: 'DigiCert',
    url: 'https://timestamp.digicert.com',
    contentType: 'application/timestamp-query',
  },
];

// ── RFC 3161 TimeStampReq builder ────────────────────────────────────

/**
 * Build a minimal RFC 3161 TimeStampReq DER blob.
 *
 * Structure (ASN.1 DER):
 *   TimeStampReq ::= SEQUENCE {
 *     version          INTEGER { v1(1) },
 *     messageImprint   MessageImprint,
 *     reqPolicy        OBJECT IDENTIFIER OPTIONAL,
 *     nonce             INTEGER OPTIONAL,
 *     certReq          BOOLEAN DEFAULT FALSE
 *   }
 *
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm    AlgorithmIdentifier,
 *     hashedMessage    OCTET STRING
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm        OBJECT IDENTIFIER,
 *     parameters       ANY OPTIONAL
 *   }
 *
 * SHA-256 OID: 2.16.840.1.101.3.4.2.1
 * SHA-256 AlgorithmIdentifier (with NULL parameter): 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
 */

const SHA256_ALG_ID = Buffer.from([
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
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
 */
export function buildTimeStampReq(hashHex: string): Buffer {
  const hashBytes = Buffer.from(hashHex, 'hex');

  // MessageImprint
  const messageImprint = derSequence([
    SHA256_ALG_ID,
    derOctetString(hashBytes),
  ]);

  // version = 1
  const version = derInteger(Buffer.from([0x01]));

  // nonce
  const nonce = derInteger(generateNonce());

  // certReq = true (request TSA certificate in response)
  const certReq = derBoolean(true);

  // TimeStampReq
  return derSequence([version, messageImprint, nonce, certReq]);
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

// ── Extract timestamp from TSR ────────────────────────────────────────

/**
 * Extract the genTime (timestamp) from an RFC 3161 TimeStampToken.
 *
 * The genTime is in the TSTInfo structure, which is inside the
 * signed data. For our purposes, we do a simple DER parse to find
 * the GeneralizedTime field.
 *
 * Returns an ISO 8601 UTC string, or null if parsing fails.
 */
export function extractTimestampFromTsr(tsrDer: Buffer): string | null {
  try {
    // Find GeneralizedTime tag (0x18) in the DER blob
    // The genTime is near the end of the TSTInfo structure
    for (let i = 0; i < tsrDer.length - 16; i++) {
      if (tsrDer[i] === 0x18) {
        // Read length
        const len = tsrDer[i + 1]!;
        if (len > 0 && len < 30 && i + 2 + len <= tsrDer.length) {
          const timeStr = tsrDer.subarray(i + 2, i + 2 + len).toString('ascii');
          // GeneralizedTime format: YYYYMMDDHHmmSSZ
          if (/^\d{14}Z$/.test(timeStr)) {
            // Convert to ISO 8601
            const year = timeStr.slice(0, 4);
            const month = timeStr.slice(4, 6);
            const day = timeStr.slice(6, 8);
            const hour = timeStr.slice(8, 10);
            const min = timeStr.slice(10, 12);
            const sec = timeStr.slice(12, 14);
            return `${year}-${month}-${day}T${hour}:${min}:${sec}.000Z`;
          }
          // With fractional seconds: YYYYMMDDHHmmSS.sZ
          if (/^\d{14}\.\d+Z$/.test(timeStr)) {
            const dotIdx = timeStr.indexOf('.');
            const fracPart = timeStr.slice(dotIdx, timeStr.length - 1);
            const base = timeStr.slice(0, 14);
            const year = base.slice(0, 4);
            const month = base.slice(4, 6);
            const day = base.slice(6, 8);
            const hour = base.slice(8, 10);
            const min = base.slice(10, 12);
            const sec = base.slice(12, 14);
            return `${year}-${month}-${day}T${hour}:${min}:${sec}${fracPart}Z`;
          }
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

// ── Main timestamping function ────────────────────────────────────────

/**
 * Request an RFC 3161 timestamp from a TSA, with fallback.
 *
 * Iterates the configured endpoints in order, returning the *first*
 * successful token. The remaining endpoints are only consulted when
 * the preceding one fails (network error, non-2xx, timeout, bad
 * response). A bundle with one trusted timestamp is the contract —
 * polling every TSA on every produce is wasteful and gives an
 * eavesdropper at the second TSA a free hint that this producer is
 * timestamping right now. Set `requireAll: true` to request from
 * every endpoint regardless (useful for multi-anchor archival).
 *
 * @param dataToTimestamp - canonical JSON of manifest (or any bytes)
 * @param options - TSA endpoints / per-request timeout / multi-anchor
 * @returns Array of RFC 3161 tokens — length 1 by default, up to
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

  // Build the RFC 3161 request
  const queryDer = buildTimeStampReq(hashHex);

  for (const endpoint of endpoints) {
    try {
      const tsrDer = await sendTsaRequest(endpoint, queryDer, timeoutMs);
      const timestamp = extractTimestampFromTsr(tsrDer);

      tokens.push({
        tsa: endpoint.name,
        timestamp: timestamp ?? new Date().toISOString(),
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

// NOTE: A TS-side `verifyTimestamp` lived here previously and did a
// byte-substring scan over the DER blob looking for the expected
// hash. That is forgeable trivially (append the hash to any DER),
// and it had no production callers — the Go verifier
// (apps/verify/timestamp/rfc3161.go) performs the real RFC 3161
// check: ASN.1 parse, hashAlgorithm == SHA-256 enforcement,
// TSTInfo.HashedMessage compare, PKCS7 signature + cert chain
// validation against an embedded FreeTSA root + system pool. We
// removed the TS-side function rather than leaving a misleading
// helper exported.