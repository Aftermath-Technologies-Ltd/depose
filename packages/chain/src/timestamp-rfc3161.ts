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
// Request encoding lives in rfc3161-request.ts, response parsing in
// rfc3161-asn1.ts, and response validation in rfc3161-validate.ts; this
// file is the fetch flow that uses them: which authority to ask, in what
// order, and how many times.

import { createHash } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { buildTimeStampReq } from './rfc3161-request.js';
import { DEFAULT_TSA_ENDPOINTS } from './rfc3161-types.js';
import { validateTsr } from './rfc3161-validate.js';
import type { TsaEndpoint, Rfc3161Token, TimestampOptions } from './rfc3161-types.js';

export { DEFAULT_TSA_ENDPOINTS, TsrValidationError } from './rfc3161-types.js';
export { validateTsr } from './rfc3161-validate.js';
export { buildTimeStampReq } from './rfc3161-request.js';
export type {
  TsaEndpoint,
  Rfc3161Token,
  TimestampOptions,
  TimeStampReqResult,
  TsrValidationResult,
} from './rfc3161-types.js';

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
  const { tokens, errors } = await tryTimestamps(dataToTimestamp, options);
  if (tokens.length === 0) {
    throw new Error(
      `All RFC 3161 TSA endpoints failed. Cannot produce bundle without timestamp.\n` +
        `Errors:\n  ${errors.join('\n  ')}\n` +
        `A bundle without a timestamp defeats the purpose of evidence integrity.`
    );
  }
  return tokens;
}

/** What one timestamping attempt produced, successes and failures alike. */
export interface TimestampAttempt {
  tokens: Rfc3161Token[];
  /** One line per endpoint that failed, naming the endpoint and the reason. */
  errors: string[];
}

/**
 * Request timestamps and report what happened, without throwing.
 *
 * This is the form the writer uses: a bundle whose TSA calls all failed
 * is sealed pending an anchor rather than not sealed at all, and the
 * caller needs the error list to record why.
 *
 * Endpoints are tried in a random order unless `preserveOrder` is set,
 * and each is retried with exponential backoff before the next is tried.
 *
 * @param dataToTimestamp - Canonical JSON of the manifest, or any bytes.
 * @param options - Endpoints, timeout, attempts, backoff, and injectables.
 * @returns The tokens obtained and the errors from every endpoint that failed.
 */
export async function tryTimestamps(
  dataToTimestamp: string,
  options?: TimestampOptions
): Promise<TimestampAttempt> {
  const configured = options?.tsaEndpoints ?? DEFAULT_TSA_ENDPOINTS;
  const endpoints = options?.preserveOrder === true
    ? configured
    : shuffleEndpoints(configured, options?.random ?? Math.random);
  const timeoutMs = options?.timeoutMs ?? 15000;
  const requireAll = options?.requireAll === true;
  const attempts = Math.max(1, options?.attempts ?? 3);
  const backoffMs = options?.backoffMs ?? 500;
  const sleep = options?.sleep ?? defaultSleep;
  const tokens: Rfc3161Token[] = [];
  const errors: string[] = [];

  const hashHex = createHash('sha256').update(dataToTimestamp, 'utf-8').digest('hex');
  const { der: queryDer, nonce } = buildTimeStampReq(hashHex);

  for (const endpoint of endpoints) {
    let lastError = '';
    for (let attempt = 0; attempt < attempts; attempt++) {
      if (attempt > 0) {
        await sleep(backoffMs * 2 ** (attempt - 1));
      }
      try {
        const tsrDer = await sendTsaRequest(endpoint, queryDer, timeoutMs);
        // Validate the TSR: parse TSTInfo, verify nonce and messageImprint.
        // An unvalidated token is never shipped.
        const result = validateTsr(tsrDer, nonce, hashHex);
        tokens.push({
          tsa: endpoint.name,
          timestamp: result.timestamp,
          tokenBase64: tsrDer.toString('base64'),
        });
        lastError = '';
        break;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      }
    }
    if (lastError !== '') {
      errors.push(`${endpoint.name} (${attempts} attempt(s)): ${lastError}`);
      continue;
    }
    if (!requireAll) break;
  }

  return { tokens, errors };
}

/** Fisher-Yates over a copy; the caller's list is never reordered. */
function shuffleEndpoints(endpoints: TsaEndpoint[], random: () => number): TsaEndpoint[] {
  const out = [...endpoints];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// F-04: The old `extractTimestampFromTsr` (heuristic byte-scan for 0x18)
// and the `new Date().toISOString()` fallback have been removed. All TSR
// validation now goes through `validateTsr`, which performs proper ASN.1
// DER parsing, nonce verification, and messageImprint verification.
// Cryptographic signature + cert-chain verification still lives in the
// Go verifier (apps/verify/timestamp/rfc3161.go).
