// packages/chain/src/rfc3161-asn1.ts
//
// TSTInfo navigation and field parsing for an RFC 3161 TimeStampResp:
// locate TSTInfo, then read genTime, messageImprint, and nonce.
//
// F-04 remediation: this replaced a heuristic byte-scan for 0x18. A parser
// that guesses at structure cannot be trusted to reject a malformed or
// hostile token, which is the whole job here.
//
// Generic DER decoding lives in asn1-der.ts, and reading the fields out
// of a TSTInfo once it has been located lives in rfc3161-tstinfo.ts.

import { TsrValidationError } from './rfc3161-types.js';
import {
  parseDerElement,
  getChildren,
  TAG_INTEGER,
  TAG_OCTET_STRING,
  TAG_OID,
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
