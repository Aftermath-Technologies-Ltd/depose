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
//
// F-04 remediation: proper ASN.1 DER parsing replaces the heuristic byte-scan,
// nonce verification and messageImprint verification are mandatory, and the
// local-clock fallback is removed entirely. A TSR that fails validation is
// discarded and the next TSA is tried — no bundle ever ships an unvalidated
// token.

import { createHash, randomBytes as cryptoRandomBytes, timingSafeEqual } from 'node:crypto';
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
const SHA256_OID_DER = Buffer.from([
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

// ── Minimal ASN.1 DER parser ─────────────────────────────────────────
//
// Walks the DER structure to find TSTInfo.genTime, messageImprint, and
// nonce.  This replaces the old heuristic byte-scan for 0x18 (F-04).

// Universal tag numbers
const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_OID = 0x06;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;

// Tag class constants
// const TAG_CLASS_UNIVERSAL = 0;  // not currently referenced inline
const TAG_CLASS_CONTEXT = 2;

interface DerElement {
  /** Raw first tag byte */
  tagByte: number;
  /** Tag class: 0=universal, 1=application, 2=context, 3=private */
  tagClass: number;
  /** True for constructed types (SEQUENCE, SET, context-constructed) */
  constructed: boolean;
  /** Tag number within the class */
  tagNumber: number;
  /** Byte length of the tag + length header */
  headerLen: number;
  /** Offset where value bytes start (absolute, within the source buffer) */
  valueOffset: number;
  /** Byte length of the value */
  valueLen: number;
  /** Total byte length: headerLen + valueLen */
  totalLen: number;
}

/**
 * Parse one DER tag-length-value at the given offset.
 * Returns null if the buffer is too short or the encoding is invalid.
 */
function parseDerElement(buf: Buffer, offset: number): DerElement | null {
  if (offset >= buf.length) return null;

  const byte0 = buf[offset]!;
  const tagClass = (byte0 & 0xc0) >>> 6;
  const constructed = !!(byte0 & 0x20);
  let tagNumber = byte0 & 0x1f;
  let headerLen = 1;

  // Long-form tag number (low 5 bits all 1s)
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (offset + headerLen < buf.length) {
      const b = buf[offset + headerLen]!;
      headerLen++;
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      if (!(b & 0x80)) break;
      if (tagNumber > 0x7fffffff) return null; // overflow guard
    }
  }

  if (offset + headerLen >= buf.length) return null;

  // Length
  const lenByte = buf[offset + headerLen]!;
  let valueLen: number;

  if (lenByte < 0x80) {
    valueLen = lenByte;
    headerLen += 1;
  } else if (lenByte === 0x80) {
    // Indefinite length — not valid DER
    return null;
  } else {
    const numLenBytes = lenByte & 0x7f;
    if (numLenBytes > 4 || offset + headerLen + 1 + numLenBytes > buf.length) {
      return null;
    }
    valueLen = 0;
    headerLen += 1; // count the length byte itself
    for (let i = 0; i < numLenBytes; i++) {
      valueLen = (valueLen << 8) | buf[offset + headerLen]!;
      headerLen++;
    }
  }

  const valueOffset = offset + headerLen;
  if (valueOffset + valueLen > buf.length) return null;

  return {
    tagByte: byte0,
    tagClass,
    constructed,
    tagNumber,
    headerLen,
    valueOffset,
    valueLen,
    totalLen: headerLen + valueLen,
  };
}

/** Collect all child TLV elements of a constructed element into an array. */
function getChildren(buf: Buffer, elem: DerElement): DerElement[] {
  const result: DerElement[] = [];
  let offset = elem.valueOffset;
  const end = elem.valueOffset + elem.valueLen;
  while (offset < end) {
    const child = parseDerElement(buf, offset);
    if (!child) break;
    if (child.valueOffset + child.valueLen > end) break; // overflows parent
    result.push(child);
    offset += child.totalLen;
  }
  return result;
}

// ── Navigate DER structure to find TSTInfo ───────────────────────────

/**
 * Given a TimeStampResp or bare ContentInfo/TimeStampToken, navigate
 * the DER structure to find the TSTInfo bytes and return them as a
 * standalone Buffer (so downstream parsing uses offset 0).
 *
 * Structure:
 *   TimeStampResp = SEQUENCE { PKIStatusInfo, ContentInfo OPTIONAL }
 *   ContentInfo   = SEQUENCE { OID, [0] EXPLICIT ANY }
 *
 * Inside ContentInfo → SignedData → encapContentInfo → eContent
 * contains the DER-encoded TSTInfo.
 */
function findTstInfoBytes(tsrDer: Buffer): Buffer {
  const outer = parseDerElement(tsrDer, 0);
  if (!outer || !outer.constructed) {
    throw new TsrValidationError('TSR is not a valid DER SEQUENCE at top level');
  }

  const children = getChildren(tsrDer, outer);
  if (children.length === 0) {
    throw new TsrValidationError('Outer DER SEQUENCE has no children');
  }

  // Determine whether this is a full TimeStampResp or a bare
  // ContentInfo / TimeStampToken.
  let contentInfo: DerElement;

  if (children[0]!.tagClass === TAG_CLASS_CONTEXT ||
      children[0]!.tagByte === TAG_OID) {
    // First child is an OID (ContentInfo) or a context tag — bare token.
    contentInfo = outer;
  } else if (children[0]!.tagByte === TAG_SEQUENCE ||
             children[0]!.constructed) {
    // First child is constructed — likely PKIStatusInfo.
    // Verify PKIStatus: status should be 0 (granted) or 1 (grantedWithMods).
    const statusInfo = children[0]!;
    const statusChildren = getChildren(tsrDer, statusInfo);
    if (statusChildren.length > 0 && statusChildren[0]!.tagByte === TAG_INTEGER) {
      const statusElem = statusChildren[0]!;
      const statusValue = tsrDer[statusElem.valueOffset]!;
      if (statusValue !== 0 && statusValue !== 1) {
        throw new TsrValidationError(
          `TSA returned PKIStatus ${statusValue} (not granted/grantedWithMods)`
        );
      }
    }

    if (children.length < 2) {
      throw new TsrValidationError(
        'TimeStampResp has no timeStampToken (status ok but no token)'
      );
    }
    contentInfo = children[1]!;
  } else {
    // Try using the outer element directly as ContentInfo
    contentInfo = outer;
  }

  // ---- Navigate ContentInfo ----
  // ContentInfo = SEQUENCE { OID, [0] EXPLICIT { SignedData } }

  if (contentInfo.tagByte !== TAG_SEQUENCE && contentInfo.tagByte !== 0x30) {
    throw new TsrValidationError('Expected ContentInfo SEQUENCE');
  }
  const ciChildren = getChildren(tsrDer, contentInfo);
  if (ciChildren.length < 2) {
    throw new TsrValidationError('ContentInfo has fewer than 2 children');
  }

  // ciChildren[1] is [0] EXPLICIT wrapping the content
  const explicit0 = ciChildren[1]!;
  if (explicit0.tagClass !== TAG_CLASS_CONTEXT || explicit0.tagNumber !== 0 || !explicit0.constructed) {
    throw new TsrValidationError('ContentInfo [0] EXPLICIT wrapper not found');
  }

  // Inside [0] EXPLICIT: SignedData SEQUENCE
  const e0Children = getChildren(tsrDer, explicit0);
  if (e0Children.length === 0) {
    throw new TsrValidationError('ContentInfo [0] is empty');
  }
  const signedData = e0Children[0]!;
  if (signedData.tagByte !== TAG_SEQUENCE) {
    throw new TsrValidationError('Expected SignedData SEQUENCE inside ContentInfo [0]');
  }

  // ---- Navigate SignedData ----
  // SignedData = SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
  const sdChildren = getChildren(tsrDer, signedData);
  if (sdChildren.length < 3) {
    throw new TsrValidationError('SignedData has fewer than 3 children');
  }

  const encapContentInfo = sdChildren[2]!;
  if (encapContentInfo.tagByte !== TAG_SEQUENCE) {
    throw new TsrValidationError('encapContentInfo is not a SEQUENCE');
  }

  // ---- Navigate encapContentInfo ----
  // encapContentInfo = SEQUENCE { eContentType OID, [0] EXPLICIT eContent }
  const eciChildren = getChildren(tsrDer, encapContentInfo);
  if (eciChildren.length < 2) {
    throw new TsrValidationError('encapContentInfo has fewer than 2 children');
  }

  const eContent0 = eciChildren[1]!;
  if (eContent0.tagClass !== TAG_CLASS_CONTEXT || eContent0.tagNumber !== 0 || !eContent0.constructed) {
    throw new TsrValidationError('encapContentInfo [0] EXPLICIT eContent not found');
  }

  // Inside [0] EXPLICIT: the eContent (usually an OCTET STRING wrapping TSTInfo)
  const e0cChildren = getChildren(tsrDer, eContent0);
  if (e0cChildren.length === 0) {
    throw new TsrValidationError('eContent [0] is empty');
  }

  const firstChild = e0cChildren[0]!;

  // Case 1: OCTET STRING containing TSTInfo DER
  if (firstChild.tagByte === TAG_OCTET_STRING) {
    const tstInfoDer = Buffer.from(
      tsrDer.subarray(firstChild.valueOffset, firstChild.valueOffset + firstChild.valueLen)
    );
    const tstInfo = parseDerElement(tstInfoDer, 0);
    if (!tstInfo || tstInfo.tagByte !== TAG_SEQUENCE) {
      throw new TsrValidationError('OCTET STRING content is not a TSTInfo SEQUENCE');
    }
    return tstInfoDer;
  }

  // Case 2: direct SEQUENCE (bare TSTInfo, no OCTET STRING wrapper)
  if (firstChild.tagByte === TAG_SEQUENCE) {
    return Buffer.from(
      tsrDer.subarray(firstChild.valueOffset - firstChild.headerLen, firstChild.valueOffset + firstChild.valueLen)
    );
  }

  // Case 3: context-tagged constructed element (some encodings)
  if (firstChild.constructed) {
    // Try treating it as a SEQUENCE-like structure
    return Buffer.from(
      tsrDer.subarray(firstChild.valueOffset - firstChild.headerLen, firstChild.valueOffset + firstChild.valueLen)
    );
  }

  throw new TsrValidationError('Cannot find TSTInfo in eContent');
}

// ── Parse TSTInfo fields ─────────────────────────────────────────────

/**
 * Parse a GeneralizedTime value from DER, handling both UNIVERSAL tag 0x18
 * and context-specific [4] IMPLICIT tag 0x84.
 *
 * GeneralizedTime format: YYYYMMDDHHmmSSZ or YYYYMMDDHHmmSS.sZ
 */
function parseGeneralizedTimeStr(buf: Buffer, elem: DerElement): string {
  if (elem.tagByte !== TAG_GENERALIZED_TIME && elem.tagByte !== 0x84) {
    throw new TsrValidationError(
      `Expected GeneralizedTime (tag 0x18 or 0x84), got 0x${elem.tagByte.toString(16)}`
    );
  }

  const timeStr = buf.subarray(elem.valueOffset, elem.valueOffset + elem.valueLen).toString('ascii');

  // GeneralizedTime format: YYYYMMDDHHmmSSZ
  if (/^\d{14}Z$/.test(timeStr)) {
    const year = timeStr.slice(0, 4);
    const month = timeStr.slice(4, 6);
    const day = timeStr.slice(6, 8);
    const hour = timeStr.slice(8, 10);
    const min = timeStr.slice(10, 12);
    const sec = timeStr.slice(12, 14);
    return `${year}-${month}-${day}T${hour}:${min}:${sec}.000Z`;
  }

  // GeneralizedTime format with fractional seconds: YYYYMMDDHHmmSS.sZ
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

  throw new TsrValidationError(`Cannot parse GeneralizedTime: "${timeStr}"`);
}

/**
 * Parse a MessageImprint SEQUENCE (or [2] IMPLICIT SEQUENCE):
 *   MessageImprint = SEQUENCE { AlgorithmIdentifier, OCTET STRING }
 *
 * Extracts the AlgorithmIdentifier OID DER and the hashedMessage bytes.
 */
function parseMessageImprint(
  buf: Buffer,
  miElement: DerElement
): { algorithmOidDer: Buffer; hashedMessage: Buffer } {
  const miChildren = getChildren(buf, miElement);
  if (miChildren.length < 2) {
    throw new TsrValidationError('MessageImprint has fewer than 2 children');
  }

  // First child: AlgorithmIdentifier SEQUENCE { OID, optional params }
  const algIdElement = miChildren[0]!;
  if (algIdElement.tagByte !== TAG_SEQUENCE) {
    throw new TsrValidationError('MessageImprint AlgorithmIdentifier is not a SEQUENCE');
  }
  const algIdChildren = getChildren(buf, algIdElement);
  if (algIdChildren.length === 0) {
    throw new TsrValidationError('AlgorithmIdentifier has no children');
  }

  // The OID element inside AlgorithmIdentifier
  const oidElement = algIdChildren[0]!;
  if (oidElement.tagByte !== TAG_OID) {
    throw new TsrValidationError('AlgorithmIdentifier first child is not an OID');
  }

  // Extract the OID DER bytes (tag + length + value)
  const algorithmOidDer = Buffer.from(
    buf.subarray(oidElement.valueOffset - oidElement.headerLen, oidElement.valueOffset + oidElement.valueLen)
  );

  // Second child: hashedMessage OCTET STRING
  const hashElement = miChildren[1]!;
  if (hashElement.tagByte !== TAG_OCTET_STRING) {
    throw new TsrValidationError('MessageImprint hashedMessage is not an OCTET STRING');
  }
  const hashedMessage = Buffer.from(
    buf.subarray(hashElement.valueOffset, hashElement.valueOffset + hashElement.valueLen)
  );

  return { algorithmOidDer, hashedMessage };
}

/**
 * Strip DER INTEGER sign-padding: a leading 0x00 byte that was added
 * because the next byte has its high bit set (to keep the value positive).
 * DER requires minimal encoding, so a leading 0x00 is sign padding only
 * when the second byte's high bit is set. In all other cases the 0x00
 * is a legitimate part of the value.
 */
function stripDerIntegerPadding(buf: Buffer): Buffer {
  if (buf.length >= 2 && buf[0] === 0x00 && (buf[1]! & 0x80)) {
    return buf.subarray(1);
  }
  return buf;
}

/**
 * Extract genTime, nonce, and messageImprint from a TSTInfo SEQUENCE.
 *
 * TSTInfo (RFC 3161 with IMPLICIT TAGS):
 *   SEQUENCE {
 *     [0] INTEGER           version (v1),
 *     [1] OID               policy,
 *     [2] MessageImprint    (SEQUENCE or [2] IMPLICIT),
 *     [3] INTEGER           serialNumber,
 *     [4] GeneralizedTime   genTime,
 *     [5] Accuracy OPTIONAL,
 *     [6] BOOLEAN OPTIONAL  ordering (DEFAULT FALSE),
 *     [7] INTEGER OPTIONAL  nonce,
 *     [8] GeneralNames OPTIONAL tsa,
 *     [0] Extensions OPTIONAL (different [0])
 *   }
 *
 * Some TSAs use UNIVERSAL tags instead of context-specific tags.
 * We detect which convention is used and handle both.
 */
function parseTstInfoFields(buf: Buffer): {
  genTime: string;
  nonce: Buffer | null;
  messageImprint: { algorithmOidDer: Buffer; hashedMessage: Buffer };
} {
  const tstInfo = parseDerElement(buf, 0);
  if (!tstInfo || tstInfo.tagByte !== TAG_SEQUENCE) {
    throw new TsrValidationError('TSTInfo is not a valid DER SEQUENCE');
  }

  const children = getChildren(buf, tstInfo);
  if (children.length < 5) {
    throw new TsrValidationError(
      `TSTInfo has only ${children.length} fields (need at least 5: version, policy, messageImprint, serialNumber, genTime)`
    );
  }

  // Detect tag style: [0] IMPLICIT INTEGER (0x80) or UNIVERSAL INTEGER (0x02)
  const usesContextTags = children[0]!.tagByte === 0x80;

  // ---- Field 2: messageImprint ----
  const miElement = children[2]!;
  if (usesContextTags) {
    // [2] IMPLICIT SEQUENCE → tag 0xA2
    if (miElement.tagByte !== 0xA2) {
      throw new TsrValidationError(
        `TSTInfo field 2: expected [2] IMPLICIT SEQUENCE (0xA2), got 0x${miElement.tagByte.toString(16)}`
      );
    }
  } else {
    if (miElement.tagByte !== TAG_SEQUENCE) {
      throw new TsrValidationError(
        `TSTInfo field 2: expected SEQUENCE (0x30), got 0x${miElement.tagByte.toString(16)}`
      );
    }
  }
  const messageImprint = parseMessageImprint(buf, miElement);

  // ---- Field 4: genTime ----
  const genTimeElement = children[4]!;
  const genTime = parseGeneralizedTimeStr(buf, genTimeElement);

  // ---- Fields 5+: nonce (optional) ----
  let nonce: Buffer | null = null;
  for (let i = 5; i < children.length; i++) {
    const child = children[i]!;
    if (usesContextTags) {
      // [7] IMPLICIT INTEGER → tag 0x87
      if (child.tagByte === 0x87) {
        nonce = stripDerIntegerPadding(
          Buffer.from(buf.subarray(child.valueOffset, child.valueOffset + child.valueLen))
        );
        break;
      }
    } else {
      // The first INTEGER after genTime is the nonce (accuracy is SEQUENCE,
      // ordering is BOOLEAN, serialNumber was at position 3).
      if (child.tagByte === TAG_INTEGER) {
        nonce = stripDerIntegerPadding(
          Buffer.from(buf.subarray(child.valueOffset, child.valueOffset + child.valueLen))
        );
        break;
      }
    }
  }

  return { genTime, nonce, messageImprint };
}

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

  // 3. Verify nonce (if the TSA echoed one)
  if (nonce !== null) {
    if (nonce.length !== expectedNonce.length || !timingSafeEqual(nonce, expectedNonce)) {
      throw new TsrValidationError(
        `Nonce mismatch: TSR nonce ${nonce.toString('hex')} != request nonce ${expectedNonce.toString('hex')}`
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