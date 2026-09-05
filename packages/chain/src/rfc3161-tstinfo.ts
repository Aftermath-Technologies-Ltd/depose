// packages/chain/src/rfc3161-tstinfo.ts
//
// Reading the fields out of a TSTInfo once it has been located: the
// message imprint, the generalized time, and the nonce.
//
// Locating it inside the SignedData is rfc3161-asn1.ts's job. The split
// is where the two questions differ: that file asks where the timestamp
// is, this one asks what it says.

import { TsrValidationError } from './rfc3161-types.js';
import {
  parseDerElement,
  getChildren,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_OID,
  TAG_GENERALIZED_TIME,
  TAG_SEQUENCE,
  type DerElement,
} from './asn1-der.js';

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


