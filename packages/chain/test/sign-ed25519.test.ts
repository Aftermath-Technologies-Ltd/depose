// packages/chain/test/sign-ed25519.test.ts
//
// Tests for Ed25519 signing and verification.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
  signManifest,
  verifyManifestSignature,
  loadOrGenerateKeyPair,
} from '../src/sign-ed25519.js';
import { existsSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ── Tests ─────────────────────────────────────────────────────────────

describe('generateEd25519KeyPair', () => {
  it('produces PEM-encoded keys', () => {
    const keyPair = generateEd25519KeyPair();
    expect(keyPair.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
    expect(keyPair.privateKeyPem).toContain('-----END PRIVATE KEY-----');
    expect(keyPair.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(keyPair.publicKeyPem).toContain('-----END PUBLIC KEY-----');
  });

  it('generates unique keys each call', () => {
    const a = generateEd25519KeyPair();
    const b = generateEd25519KeyPair();
    expect(a.privateKeyPem).not.toBe(b.privateKeyPem);
    expect(a.publicKeyPem).not.toBe(b.publicKeyPem);
  });
});

describe('signEd25519 / verifyEd25519', () => {
  it('signs and verifies data correctly', () => {
    const keyPair = generateEd25519KeyPair();
    const data = 'hello world';
    const sig = signEd25519(data, keyPair.privateKeyPem);
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);

    const valid = verifyEd25519(data, sig, keyPair.publicKeyPem);
    expect(valid).toBe(true);
  });

  it('rejects tampered data', () => {
    const keyPair = generateEd25519KeyPair();
    const data = 'hello world';
    const sig = signEd25519(data, keyPair.privateKeyPem);

    const valid = verifyEd25519('hello worlD', sig, keyPair.publicKeyPem);
    expect(valid).toBe(false);
  });

  it('rejects wrong public key', () => {
    const keyPair1 = generateEd25519KeyPair();
    const keyPair2 = generateEd25519KeyPair();
    const data = 'hello world';
    const sig = signEd25519(data, keyPair1.privateKeyPem);

    const valid = verifyEd25519(data, sig, keyPair2.publicKeyPem);
    expect(valid).toBe(false);
  });

  it('returns false for malformed signature', () => {
    const keyPair = generateEd25519KeyPair();
    const valid = verifyEd25519('data', 'not-base64!!!', keyPair.publicKeyPem);
    expect(valid).toBe(false);
  });
});

describe('signManifest / verifyManifestSignature', () => {
  it('signs and verifies a manifest', () => {
    const keyPair = generateEd25519KeyPair();
    const manifestJson = '{"schemaVersion":1,"bundleId":"test"}';

    const result = signManifest(manifestJson, keyPair);
    expect(result.scheme).toBe('ed25519');
    expect(result.signatureBase64).toBeDefined();
    expect(result.publicKeyPem).toBe(keyPair.publicKeyPem);

    const valid = verifyManifestSignature(
      manifestJson,
      result.signatureBase64,
      keyPair.publicKeyPem
    );
    expect(valid).toBe(true);
  });

  it('rejects manifest tampering', () => {
    const keyPair = generateEd25519KeyPair();
    const manifestJson = '{"schemaVersion":1,"bundleId":"test"}';
    const result = signManifest(manifestJson, keyPair);

    const valid = verifyManifestSignature(
      '{"schemaVersion":1,"bundleId":"TAMPERED"}',
      result.signatureBase64,
      keyPair.publicKeyPem
    );
    expect(valid).toBe(false);
  });

  it('signs the canonical JSON bytes directly (no pre-hash)', () => {
    // B2: signature is over the raw canonical JSON bytes; Ed25519
    // hashes internally per RFC 8032, so the previous SHA-256 +
    // hex-encode step was both redundant and a cross-language seam.
    const keyPair = generateEd25519KeyPair();
    const manifestJson = '{"schemaVersion":1}';

    const result = signManifest(manifestJson, keyPair);

    // Verify against the bytes directly — same input signManifest used.
    const valid = verifyEd25519(manifestJson, result.signatureBase64, keyPair.publicKeyPem);
    expect(valid).toBe(true);
  });
});

describe('loadOrGenerateKeyPair', () => {
  let testKeyDir: string;

  beforeEach(() => {
    testKeyDir = join(tmpdir(), `depose-test-keys-${Date.now()}`);
  });

  afterEach(() => {
    if (testKeyDir && existsSync(testKeyDir)) {
      rmSync(testKeyDir, { recursive: true, force: true });
    }
  });

  it('generates new key pair when none exists', () => {
    const keyPair = loadOrGenerateKeyPair(testKeyDir);
    expect(keyPair.privateKeyPem).toContain('PRIVATE KEY');
    expect(keyPair.publicKeyPem).toContain('PUBLIC KEY');
    expect(existsSync(join(testKeyDir, 'signing.key'))).toBe(true);
    expect(existsSync(join(testKeyDir, 'signing.pub'))).toBe(true);
  });

  it('loads existing key pair on subsequent calls', () => {
    const first = loadOrGenerateKeyPair(testKeyDir);
    const second = loadOrGenerateKeyPair(testKeyDir);
    expect(first.privateKeyPem).toBe(second.privateKeyPem);
    expect(first.publicKeyPem).toBe(second.publicKeyPem);
  });
});