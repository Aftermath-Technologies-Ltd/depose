// packages/chain/src/cose-sign1.ts
//
// COSE_Sign1 (RFC 9052 §4.2) over Ed25519, which is what a SCITT Signed
// Statement is (draft-ietf-scitt-architecture):
//
//   Signed_Statement = #6.18(COSE_Sign1)
//   COSE_Sign1 = [ protected: bstr .cbor Protected_Header,
//                  unprotected: Unprotected_Header,
//                  payload: bstr / nil,
//                  signature: bstr ]
//
// The signature is over the Sig_structure of RFC 9052 §4.4:
//
//   Sig_structure = [ "Signature1", body_protected: bstr, external_aad: bstr, payload: bstr ]
//
// Ed25519 signatures are deterministic (RFC 8032 §5.1.6), so the same
// statement over the same bundle and key is byte-identical every time,
// which is what makes the golden exports checkable.

import { sign, verify, createPublicKey, createPrivateKey } from 'node:crypto';
import { encodeCbor, type CborValue } from './cbor.js';
import type { Ed25519KeyPair } from './sign-ed25519.js';

/** COSE header parameter labels used here (IANA COSE Header Parameters). */
export const COSE_HEADER = {
  alg: 1,
  contentType: 3,
  kid: 4,
  /** CWT_Claims, registered for SCITT Signed Statements. */
  cwtClaims: 15,
} as const;

/** CWT claim keys used here (IANA CBOR Web Token Claims). */
export const CWT_CLAIM = {
  iss: 1,
  sub: 2,
  iat: 6,
} as const;

/** COSE algorithm identifier for Ed25519. */
export const COSE_ALG_EDDSA = -8;

/** CBOR tag for a COSE_Sign1 message. */
export const COSE_SIGN1_TAG = 18;

/** Inputs for one signed statement. */
export interface CoseSign1Input {
  /** Protected header map. Encoded as a bstr and covered by the signature. */
  protectedHeader: Map<CborValue, CborValue>;
  /** Unprotected header map. Not covered by the signature. */
  unprotectedHeader?: Map<CborValue, CborValue>;
  /** Payload bytes. Attached; SCITT also allows a detached payload, which DEPOSE does not emit. */
  payload: Uint8Array;
  /** External additional authenticated data. Empty unless a profile requires it. */
  externalAad?: Uint8Array;
}

/**
 * Build and sign a COSE_Sign1 message.
 *
 * @param input - Headers and payload.
 * @param keyPair - The Ed25519 key to sign with.
 * @returns The tagged COSE_Sign1 bytes, ready to submit to a
 *   transparency service.
 * @throws Error when the key is not an Ed25519 key.
 */
export function signCoseSign1(input: CoseSign1Input, keyPair: Ed25519KeyPair): Uint8Array {
  const key = createPrivateKey(keyPair.privateKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(
      `COSE_Sign1 here signs with Ed25519 only; the key provided is ${key.asymmetricKeyType ?? 'of unknown type'}. ` +
        `Export with the key that sealed the bundle.`
    );
  }
  const protectedBytes = encodeCbor(input.protectedHeader);
  const toBeSigned = sigStructure(protectedBytes, input.externalAad ?? new Uint8Array(0), input.payload);
  // Ed25519 in Node takes a null digest algorithm: the algorithm is fixed
  // by the key type and hashing happens inside the signature scheme.
  const signature = new Uint8Array(sign(null, Buffer.from(toBeSigned), key));
  return encodeCbor({
    tag: COSE_SIGN1_TAG,
    value: [protectedBytes, input.unprotectedHeader ?? new Map(), input.payload, signature],
  });
}

/**
 * Verify a COSE_Sign1 signature against its parts.
 *
 * @param protectedBytes - The encoded protected header from the message.
 * @param payload - The attached payload.
 * @param signature - The signature bytes.
 * @param publicKeyPem - The signer's public key.
 * @param externalAad - The same external AAD used when signing.
 * @returns True when the signature is valid.
 */
export function verifyCoseSign1(
  protectedBytes: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
  publicKeyPem: string,
  externalAad: Uint8Array = new Uint8Array(0)
): boolean {
  const toBeSigned = sigStructure(protectedBytes, externalAad, payload);
  return verify(null, Buffer.from(toBeSigned), createPublicKey(publicKeyPem), Buffer.from(signature));
}

/** RFC 9052 §4.4 Sig_structure for a COSE_Sign1. */
function sigStructure(protectedBytes: Uint8Array, externalAad: Uint8Array, payload: Uint8Array): Uint8Array {
  return encodeCbor(['Signature1', protectedBytes, externalAad, payload]);
}

/**
 * The 32 raw Ed25519 public key bytes inside an SPKI PEM.
 *
 * COSE `kid` and did:key both want the raw key, not the SPKI wrapper.
 *
 * @param publicKeyPem - An Ed25519 SPKI PEM.
 * @returns The 32-byte public key.
 * @throws Error when the DER is not a 44-byte Ed25519 SPKI.
 */
export function rawEd25519PublicKey(publicKeyPem: string): Uint8Array {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  if (der.length !== 44) {
    throw new Error(
      `expected a 44-byte Ed25519 SPKI, got ${der.length} bytes; the bundle was sealed with a key this exporter cannot represent`
    );
  }
  return new Uint8Array(der.subarray(12));
}
