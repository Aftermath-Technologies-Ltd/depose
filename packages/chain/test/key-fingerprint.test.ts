// Tests for the C4 key-fingerprint helpers.

import { describe, it, expect } from 'vitest';
import { generateEd25519KeyPair, fingerprintPublicKeyPem, formatFingerprintSshStyle } from '../src/index.js';

describe('fingerprintPublicKeyPem', () => {
  it('returns a 64-char lowercase hex string', () => {
    const { publicKeyPem } = generateEd25519KeyPair();
    const fp = fingerprintPublicKeyPem(publicKeyPem);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is stable for the same key', () => {
    const { publicKeyPem } = generateEd25519KeyPair();
    expect(fingerprintPublicKeyPem(publicKeyPem)).toBe(fingerprintPublicKeyPem(publicKeyPem));
  });

  it('differs across distinct keys', () => {
    const a = fingerprintPublicKeyPem(generateEd25519KeyPair().publicKeyPem);
    const b = fingerprintPublicKeyPem(generateEd25519KeyPair().publicKeyPem);
    expect(a).not.toBe(b);
  });
});

describe('formatFingerprintSshStyle', () => {
  it('renders SHA256:<base64> from a hex fingerprint', () => {
    // hex of 32 zero bytes → base64 == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    const formatted = formatFingerprintSshStyle('00'.repeat(32));
    expect(formatted).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });
});
