// packages/chain/src/rfc3161-types.ts
//
// Shared shapes and TSA endpoint configuration for RFC 3161 timestamping.
// Split out of timestamp-rfc3161.ts, which had grown to 890 lines across
// four unrelated concerns: types, DER encoding, DER parsing, and the
// request/validate flow.

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
   * short-circuiting on the first success. Off by default, the
   * verifier needs one valid token, and querying every TSA on every
   * produce doubles network exposure and TSA load. Useful only for
   * multi-anchor archival workflows.
   */
  requireAll?: boolean;
}

/** Return type for {@link buildTimeStampReq}: DER bytes plus the nonce. */
export interface TimeStampReqResult {
  /** DER-encoded TimeStampReq, ready to POST to a TSA */
  der: Buffer;
  /** The 8-byte CSPRNG nonce embedded in the request (for response validation) */
  nonce: Buffer;
}

/** Validated fields extracted from a TSR by {@link validateTsr}. */
export interface TsrValidationResult {
  /** ISO 8601 UTC timestamp from TSTInfo.genTime */
  timestamp: string;
  /** Nonce from TSTInfo (null if the TSA did not echo one) */
  nonce: Buffer | null;
  /** messageImprint from TSTInfo: algorithm OID DER + digest */
  messageImprint: {
    algorithmOidDer: Buffer;
    hashedMessage: Buffer;
  };
}

/** Thrown when TSR validation fails (bad parse, nonce mismatch, hash mismatch). */
export class TsrValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TsrValidationError';
  }
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

