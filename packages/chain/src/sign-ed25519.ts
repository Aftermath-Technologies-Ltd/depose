// packages/chain/src/sign-ed25519.ts
//
// Ed25519 signing for DEPOSE evidence bundles.
//
// Key management story (BUILD_PLAN.md §6 Phase 2):
//   - Default: project-local Ed25519 keypair at ~/.depose/keys/signing.key
//   - Key stored with 0600 permissions, never logged
//   - Optional: sigstore keyless if SIGSTORE_OIDC=1 or CI with OIDC (deferred)
//
// Signature is over the canonical JSON bytes of the unsigned manifest.
// We sign the bytes directly, not a hex-encoded SHA-256, Ed25519
// already hashes internally (RFC 8032), and pre-hashing into hex
// added a cross-language seam (the Go verifier had to mirror the
// "sign the hex string" oddity). See B2 in update-plan.md.

import * as crypto from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { loadCatalog, saveCatalog, recordActive, findEntry } from './key-catalog.js';
import { fingerprintPublicKeyPem } from './key-fingerprint.js';

// ── Constants ─────────────────────────────────────────────────────────

const DEFAULT_KEYS_DIR = '.depose/keys';
const SIGNING_KEY_FILE = 'signing.key';
const PUBLIC_KEY_FILE = 'signing.pub';
const KEY_CATALOG_FILE = 'catalog.json';
const KEY_PERMISSIONS = 0o600;
const PUB_KEY_PERMISSIONS = 0o644;

// ── Types ─────────────────────────────────────────────────────────────

export interface Ed25519KeyPair {
  /** PEM-encoded private key */
  privateKeyPem: string;
  /** PEM-encoded public key */
  publicKeyPem: string;
}

export interface Ed25519SignatureResult {
  /** Base64-encoded signature */
  signatureBase64: string;
  /** PEM-encoded public key (for verification) */
  publicKeyPem: string;
  /** The scheme identifier */
  scheme: 'ed25519';
}

// ── Key generation ────────────────────────────────────────────────────

/**
 * Generate a new Ed25519 key pair.
 * Returns PEM-encoded private and public keys.
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    privateKeyPem: privateKey as string,
    publicKeyPem: publicKey as string,
  };
}

// ── Key storage ───────────────────────────────────────────────────────

/**
 * Get the default key directory path.
 */
export function getDefaultKeyDir(): string {
  return join(homedir(), DEFAULT_KEYS_DIR);
}

/**
 * Get the default signing key path.
 */
export function getDefaultSigningKeyPath(): string {
  return join(getDefaultKeyDir(), SIGNING_KEY_FILE);
}

/**
 * Get the default public key path.
 */
export function getDefaultPublicKeyPath(): string {
  return join(getDefaultKeyDir(), PUBLIC_KEY_FILE);
}

/**
 * Load or generate an Ed25519 key pair from the default location.
 * If no key exists, generates and saves a new one with 0600 permissions.
 */
export function loadOrGenerateKeyPair(keyDir?: string): Ed25519KeyPair {
  const dir = keyDir ?? getDefaultKeyDir();
  const privPath = join(dir, SIGNING_KEY_FILE);
  const pubPath = join(dir, PUBLIC_KEY_FILE);

  if (existsSync(privPath) && existsSync(pubPath)) {
    const privateKeyPem = readFileSync(privPath, 'utf-8');
    const publicKeyPem = readFileSync(pubPath, 'utf-8');
    // A key that has never been catalogued is one a recipient cannot pin
    // or check for revocation. Registering on load closes the gap for keys
    // that predate the catalog, using the key file's mtime rather than
    // "now" so the recorded date is not months off.
    ensureCatalogued(dir, publicKeyPem, {
      at: new Date(statSync(privPath).mtimeMs).toISOString(),
      source: 'inferred-from-mtime',
    });
    return { privateKeyPem, publicKeyPem };
  }

  // Generate new keypair
  const keyPair = generateEd25519KeyPair();

  // Save with restrictive permissions
  mkdirSync(dir, { recursive: true });
  writeFileSync(privPath, keyPair.privateKeyPem, 'utf-8');
  chmodSync(privPath, KEY_PERMISSIONS);
  writeFileSync(pubPath, keyPair.publicKeyPem, 'utf-8');
  chmodSync(pubPath, PUB_KEY_PERMISSIONS);

  // Catalogue at the point of generation, which is the only moment
  // issuedAt can be recorded rather than reconstructed.
  ensureCatalogued(dir, keyPair.publicKeyPem, {
    at: new Date().toISOString(),
    source: 'generated',
  });

  return keyPair;
}

/**
 * Add the key to the local catalog if it is not already there.
 *
 * Best-effort: a read-only or otherwise unwritable key directory must not
 * stop a bundle from being signed, so failures here are swallowed. The
 * catalog is producer-side bookkeeping, not part of the signature.
 */
function ensureCatalogued(
  dir: string,
  publicKeyPem: string,
  issued: { at: string; source: 'generated' | 'inferred-from-mtime' },
): void {
  try {
    const catalogPath = join(dir, KEY_CATALOG_FILE);
    const fingerprint = fingerprintPublicKeyPem(publicKeyPem);
    const catalog = loadCatalog(catalogPath);
    if (findEntry(catalog, fingerprint)) return;
    saveCatalog(catalogPath, recordActive(catalog, fingerprint, publicKeyPem, issued));
  } catch {
    // Signing proceeds regardless.
  }
}

// ── Signing ────────────────────────────────────────────────────────────

/**
 * Sign arbitrary bytes with an Ed25519 private key.
 *
 * Ed25519 (pure, ph=0) hashes its input internally per RFC 8032, so
 * we pass `null` as the algorithm and feed the raw message bytes.
 */
export function signEd25519(data: Buffer | string, privateKeyPem: string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
  const signature = crypto.sign(null, buf, {
    key: privateKeyPem,
    format: 'pem',
    type: 'pkcs8',
  });
  return signature.toString('base64');
}

/**
 * Verify an Ed25519 signature over arbitrary bytes.
 */
export function verifyEd25519(
  data: Buffer | string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, buf, {
      key: publicKeyPem,
      format: 'pem',
      type: 'spki',
    }, signature);
  } catch {
    return false;
  }
}

// ── Bundle signing ────────────────────────────────────────────────────

/**
 * Sign a DEPOSE manifest. The signature is over the canonical JSON
 * bytes of the unsigned form, no pre-hash, no hex encoding step.
 */
export function signManifest(
  manifestCanonicalJson: string,
  keyPair: Ed25519KeyPair
): Ed25519SignatureResult {
  const signatureBase64 = signEd25519(
    Buffer.from(manifestCanonicalJson, 'utf-8'),
    keyPair.privateKeyPem,
  );

  return {
    signatureBase64,
    publicKeyPem: keyPair.publicKeyPem,
    scheme: 'ed25519',
  };
}

/**
 * Verify a manifest signature directly over canonical JSON bytes.
 */
export function verifyManifestSignature(
  manifestCanonicalJson: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  return verifyEd25519(
    Buffer.from(manifestCanonicalJson, 'utf-8'),
    signatureBase64,
    publicKeyPem,
  );
}