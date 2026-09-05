// packages/chain/src/did-key.ts
//
// did:key identifiers for Ed25519 public keys (W3C DID Method: Key).
//
// The identifier is `did:key:z` followed by the base58btc encoding of the
// multicodec-prefixed raw public key: 0xed 0x01 then the 32 key bytes.
// Every Ed25519 did:key therefore starts `did:key:z6Mk`.
//
// Exporters need this because the receipt and statement profiles identify
// an issuer by a decentralized identifier rather than by a certificate,
// and DEPOSE's signer is an Ed25519 key with no certificate at all.

import { rawEd25519PublicKey } from './cose-sign1.js';

/** Bitcoin base58 alphabet, as used by multibase 'z'. */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Multicodec prefix for an Ed25519 public key, varint-encoded. */
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

/**
 * Encode bytes as base58btc.
 *
 * @param bytes - The bytes to encode.
 * @returns The base58 string, with one leading '1' per leading zero byte.
 */
export function base58btcEncode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros++;

  const digits: number[] = [];
  for (let i = leadingZeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '1'.repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!];
  }
  return out;
}

/**
 * The did:key identifier for an Ed25519 public key.
 *
 * @param publicKeyPem - The signer's SPKI PEM.
 * @returns `did:key:z6Mk...`.
 */
export function didKeyFromEd25519Pem(publicKeyPem: string): string {
  const raw = rawEd25519PublicKey(publicKeyPem);
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + raw.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(raw, ED25519_MULTICODEC.length);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

/**
 * The same identifier with the `did:` scheme stripped.
 *
 * draft-marques-asqav-compliance-receipts takes issuer identifiers in
 * bare form, so a DID appears as `key:z6Mk...`.
 *
 * @param publicKeyPem - The signer's SPKI PEM.
 * @returns `key:z6Mk...`.
 */
export function bareDidKeyFromEd25519Pem(publicKeyPem: string): string {
  return didKeyFromEd25519Pem(publicKeyPem).slice('did:'.length);
}
