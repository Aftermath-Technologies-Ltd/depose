// packages/chain/src/rfc3161-asn1.ts
//
// TSTInfo navigation and field parsing for an RFC 3161 TimeStampResp:
// locate TSTInfo, then read genTime, messageImprint, and nonce.
//
// F-04 remediation: this replaced a heuristic byte-scan for 0x18. A parser
// that guesses at structure cannot be trusted to reject a malformed or
// hostile token, which is the whole job here.
//
// Generic DER decoding lives in asn1-der.ts.

import { TsrValidationError } from './rfc3161-types.js';
import {
  parseDerElement,
  getChildren,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_OID,
  TAG_GENERALIZED_TIME,
  TAG_SEQUENCE,
  TAG_CLASS_CONTEXT,
  type DerElement,
} from './asn1-der.js';

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
export function findTstInfoBytes(tsrDer: Buffer): Buffer {
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
    // First child is an OID (ContentInfo) or a context tag, bare token.
    contentInfo = outer;
  } else if (children[0]!.tagByte === TAG_SEQUENCE ||
             children[0]!.constructed) {
    // First child is constructed, likely PKIStatusInfo.
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
 * Trim all leading 0x00 bytes, leaving at least one byte. Treats the
 * input as an unsigned big-endian integer; equal integer values
 * compare equal regardless of leading-zero padding. Used for nonce
 * comparison where DER encoders disagree about sign-padding.
 */
export function trimLeadingZeroBytes(buf: Buffer): Buffer {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i++;
  return buf.subarray(i);
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
export function parseTstInfoFields(buf: Buffer): {
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


