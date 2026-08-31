// packages/chain/src/asn1-der.ts
//
// Generic ASN.1 DER reader: tag/length/value decoding and child iteration.
// Knows nothing about RFC 3161; rfc3161-asn1.ts layers the TSTInfo
// structure on top.

// ── Minimal ASN.1 DER parser ─────────────────────────────────────────
//
// Walks the DER structure to find TSTInfo.genTime, messageImprint, and
// nonce.  This replaces the old heuristic byte-scan for 0x18 (F-04).

// Universal tag numbers (only those referenced inline are kept;
// others were removed to satisfy strict no-unused-vars lint).
export const TAG_INTEGER = 0x02;
export const TAG_OCTET_STRING = 0x04;
export const TAG_OID = 0x06;
export const TAG_GENERALIZED_TIME = 0x18;
export const TAG_SEQUENCE = 0x30;

// Tag class constants
// const TAG_CLASS_UNIVERSAL = 0;  // not currently referenced inline
export const TAG_CLASS_CONTEXT = 2;

export interface DerElement {
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
export function parseDerElement(buf: Buffer, offset: number): DerElement | null {
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
    // Indefinite length, not valid DER
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
export function getChildren(buf: Buffer, elem: DerElement): DerElement[] {
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

