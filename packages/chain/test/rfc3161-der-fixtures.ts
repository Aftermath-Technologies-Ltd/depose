// packages/chain/test/rfc3161-der-fixtures.ts
//
// Builders for synthetic TSR DER. The validation tests need tokens that
// are well-formed in every way but one, and there is no way to get those
// from a real TSA, so they are constructed here.

// ── Helpers for constructing synthetic TSR DER ────────────────────────

export function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

export function derSequence(contents: Buffer[]): Buffer {
  const inner = Buffer.concat(contents);
  return Buffer.concat([Buffer.from([0x30]), derLength(inner.length), inner]);
}

export function derOctetString(data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x04]), derLength(data.length), data]);
}

export function derIntegerFromBuffer(value: Buffer): Buffer {
  let content = value;
  if (content[0]! & 0x80) {
    content = Buffer.concat([Buffer.from([0x00]), content]);
  }
  return Buffer.concat([Buffer.from([0x02]), derLength(content.length), content]);
}

/**
 * Emit an INTEGER whose content bytes are exactly what was passed in,
 * with no sign-pad normalization. Models the lax-DER behavior of TSAs
 * (notably FreeTSA) that omit the sign-pad byte even when strict DER
 * would require it for positive integers.
 */
export function derIntegerRawContent(value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x02]), derLength(value.length), value]);
}

export function derGeneralizedTime(timeStr: string): Buffer {
  const timeBytes = Buffer.from(timeStr, 'ascii');
  return Buffer.concat([Buffer.from([0x18]), derLength(timeBytes.length), timeBytes]);
}

// SHA-256 AlgorithmIdentifier
export const SHA256_ALG_ID = Buffer.from([
  0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
]);

/**
 * Build a minimal TimeStampResp DER structure for testing.
 *
 * TimeStampResp ::= SEQUENCE {
 *   status  PKIStatusInfo,
 *   token   ContentInfo OPTIONAL
 * }
 *
 * PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString DisplayText OPTIONAL }
 *
 * ContentInfo wraps SignedData → encapContentInfo → OCTET STRING(TSTInfo)
 */
export function buildMinimalTimeStampResp(hashBytes: Buffer, nonce: Buffer): Buffer {
  return buildMinimalTimeStampRespWithAlgId(hashBytes, nonce, SHA256_ALG_ID);
}

export function buildMinimalTimeStampRespWithAlgId(
  hashBytes: Buffer,
  nonce: Buffer,
  algId: Buffer
): Buffer {
  const genTimeStr = '20250518153000Z';
  return buildMinimalTimeStampRespWithAlgIdAndGenTime(hashBytes, nonce, algId, genTimeStr);
}

export function buildMinimalTimeStampRespWithGenTime(
  hashBytes: Buffer,
  nonce: Buffer,
  genTimeStr: string
): Buffer {
  return buildMinimalTimeStampRespWithAlgIdAndGenTime(hashBytes, nonce, SHA256_ALG_ID, genTimeStr);
}

/**
 * Build a TimeStampResp whose nonce INTEGER is encoded with the raw
 * content bytes you supply (no sign-pad normalization). Use to model
 * a TSA that returns a non-strict-DER nonce encoding.
 */
export function buildMinimalTimeStampRespWithRawNonceBytes(
  hashBytes: Buffer,
  rawNonceContent: Buffer,
): Buffer {
  return buildMinimalTimeStampRespCore(
    hashBytes,
    derIntegerRawContent(rawNonceContent),
    SHA256_ALG_ID,
    '20250518153000Z',
  );
}

export function buildMinimalTimeStampRespWithAlgIdAndGenTime(
  hashBytes: Buffer,
  nonce: Buffer,
  algId: Buffer,
  genTimeStr: string
): Buffer {
  return buildMinimalTimeStampRespCore(
    hashBytes,
    derIntegerFromBuffer(nonce),
    algId,
    genTimeStr,
  );
}

function buildMinimalTimeStampRespCore(
  hashBytes: Buffer,
  nonceDer: Buffer,
  algId: Buffer,
  genTimeStr: string,
): Buffer {
  // ── TSTInfo ──
  // TSTInfo (using UNIVERSAL tags to match typical DER output):
  // SEQUENCE {
  //   version          INTEGER 1,
  //   policy           OID (any),
  //   messageImprint   SEQUENCE { SHA256AlgId, OCTET STRING hashBytes },
  //   serialNumber     INTEGER 1,
  //   genTime          GeneralizedTime,
  //   nonce            INTEGER nonce,
  // }
  const policyOid = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1e]); // arbitrary OID

  const messageImprint = derSequence([algId, derOctetString(hashBytes)]);

  const tstInfo = derSequence([
    derIntegerFromBuffer(Buffer.from([0x01])),     // version
    policyOid,                                      // policy
    messageImprint,                                  // messageImprint
    derIntegerFromBuffer(Buffer.from([0x01])),     // serialNumber
    derGeneralizedTime(genTimeStr),                 // genTime
    nonceDer,                                       // nonce (pre-encoded)
  ]);

  // Wrap TSTInfo in OCTET STRING (eContent)
  const tstInfoContent = derOctetString(tstInfo);

  // encapContentInfo = SEQUENCE { eContentType OID, [0] EXPLICIT eContent }
  const eContentTypeOid = Buffer.from([
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x0d,
  ]); // id-ct-TSTInfo OID
  const encapContentInfo = derSequence([
    eContentTypeOid,
    Buffer.concat([Buffer.from([0xa0]), derLength(tstInfoContent.length), tstInfoContent]),
  ]);

  // digestAlgorithms = SEQUENCE { SEQUENCE { SHA-256 OID, NULL } }
  const digestAlgorithms = derSequence([SHA256_ALG_ID]);

  // version = INTEGER 3 (for SignedData v3)
  const signedDataVersion = derIntegerFromBuffer(Buffer.from([0x03]));

  // SignedData = SEQUENCE { version, digestAlgorithms, encapContentInfo }
  const signedData = derSequence([signedDataVersion, digestAlgorithms, encapContentInfo]);

  // ContentInfo = SEQUENCE { OID, [0] EXPLICIT SignedData }
  const contentTypeOid = Buffer.from([
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
  ]); // id-signedData OID (1.2.840.113549.1.7.2)
  const contentInfo = derSequence([
    contentTypeOid,
    Buffer.concat([Buffer.from([0xa0]), derLength(signedData.length), signedData]),
  ]);

  // PKIStatusInfo = SEQUENCE { status INTEGER 0 (granted) }
  const pkiStatusInfo = derSequence([
    derIntegerFromBuffer(Buffer.from([0x00])),
  ]);

  // TimeStampResp = SEQUENCE { status, token }
  return derSequence([pkiStatusInfo, contentInfo]);
}