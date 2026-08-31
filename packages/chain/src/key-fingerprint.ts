// Key fingerprint helpers, DEPOSE producer identity in the
// air-gapped key flow.
//
// A fingerprint is `SHA-256(<SPKI-DER-bytes of the public key>)`,
// formatted as lowercase hex. The recipient knows what fingerprint
// to expect because the producer published it out-of-band (their
// .well-known/, a key catalog, a printed handshake). The
// `producer.keyFingerprint` field in the manifest, plus the
// verifier's `--expected-key-fingerprint`, close the loop.

import { createPublicKey, createHash } from 'node:crypto';

/**
 * Compute the SHA-256 fingerprint of an Ed25519 public key in PEM
 * form. Returns a lowercase hex string (no separators, no prefix).
 *
 * The hash is over the SPKI DER bytes (the same byte sequence
 * pem.Decode in Go returns as `block.Bytes`), so producers in TS
 * and verifiers in Go arrive at the same value.
 */
export function fingerprintPublicKeyPem(publicKeyPem: string): string {
  const key = createPublicKey({ key: publicKeyPem, format: 'pem' });
  const der = key.export({ format: 'der', type: 'spki' }) as Buffer;
  return createHash('sha256').update(der).digest('hex');
}

/**
 * Format a hex fingerprint as ssh-style (`SHA256:<base64>`) for
 * human-friendly display. The on-the-wire format in the manifest
 * remains lowercase hex.
 */
export function formatFingerprintSshStyle(hexFingerprint: string): string {
  const buf = Buffer.from(hexFingerprint, 'hex');
  // No padding, base64 URL-safe, matches ssh-keygen -lf output
  // for ed25519 keys.
  return 'SHA256:' + buf.toString('base64').replace(/=+$/, '');
}
