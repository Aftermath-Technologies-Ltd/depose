// packages/chain/src/sign-ed25519.ts
//
// Ed25519 signing for DEPOSE evidence bundles.
//
// Key management story (BUILD_PLAN.md §6 Phase 2):
//   - Default: project-local Ed25519 keypair at ~/.depose/keys/signing.key
//   - Key stored with 0600 permissions, never logged
//   - Optional: sigstore keyless if SIGSTORE_OIDC=1 or CI with OIDC (deferred)
//
// Signature is over the SHA-256 of canonical-JSON-serialized manifest.json.

import * as crypto from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { sha256String } from '@depose/core';

// ── Constants ─────────────────────────────────────────────────────────

const DEFAULT_KEYS_DIR = '.depose/keys';
const SIGNING_KEY_FILE = 'signing.key';
const PUBLIC_KEY_FILE = 'signing.pub';
const KEY_PERMISSIONS = 0o600;

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
    return { privateKeyPem, publicKeyPem };
  }

  // Generate new keypair
  const keyPair = generateEd25519KeyPair();

  // Save with restrictive permissions
  mkdirSync(dir, { recursive: true });
  writeFileSync(privPath, keyPair.privateKeyPem, 'utf-8');
  chmodSync(privPath, KEY_PERMISSIONS);
  writeFileSync(pubPath, keyPair.publicKeyPem, 'utf-8');
  chmodSync(pubPath, KEY_PERMISSIONS);

  return keyPair;
}

// ── Signing ────────────────────────────────────────────────────────────

/**
 * Sign data with an Ed25519 private key.
 *
 * Ed25519 uses its own internal hashing (Ed25519 ph=0, no pre-hash).
 * We pass `null` as the algorithm to crypto.sign — the Ed25519 key type
 * handles hashing internally per RFC 8032.
 *
 * @param data - The data to sign (UTF-8 string)
 * @param privateKeyPem - PEM-encoded Ed25519 private key
 * @returns Base64-encoded signature
 */
export function signEd25519(data: string, privateKeyPem: string): string {
  const signature = crypto.sign(null, Buffer.from(data, 'utf-8'), {
    key: privateKeyPem,
    format: 'pem',
    type: 'pkcs8',
  });
  return signature.toString('base64');
}

/**
 * Verify data with an Ed25519 public key.
 *
 * @param data - The original data (UTF-8 string)
 * @param signatureBase64 - Base64-encoded signature
 * @param publicKeyPem - PEM-encoded Ed25519 public key
 * @returns True if signature is valid
 */
export function verifyEd25519(
  data: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  try {
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, Buffer.from(data, 'utf-8'), {
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
 * Sign the manifest for a DEPOSE bundle.
 *
 * The signature is computed over the SHA-256 of the canonical-JSON-serialized
 * manifest, as specified in BUILD_PLAN.md §4.3.
 *
 * @param manifestCanonicalJson - Canonical JSON of the manifest
 * @param keyPair - Ed25519 key pair
 * @returns Signature result for inclusion in the bundle
 */
export function signManifest(
  manifestCanonicalJson: string,
  keyPair: Ed25519KeyPair
): Ed25519SignatureResult {
  const manifestHash = sha256String(manifestCanonicalJson);
  const signatureBase64 = signEd25519(manifestHash, keyPair.privateKeyPem);

  return {
    signatureBase64,
    publicKeyPem: keyPair.publicKeyPem,
    scheme: 'ed25519',
  };
}

/**
 * Verify a manifest signature against a manifest.
 *
 * @param manifestCanonicalJson - Canonical JSON of the manifest
 * @param signatureBase64 - Base64-encoded signature
 * @param publicKeyPem - PEM-encoded Ed25519 public key
 * @returns True if signature is valid
 */
export function verifyManifestSignature(
  manifestCanonicalJson: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  const manifestHash = sha256String(manifestCanonicalJson);
  return verifyEd25519(manifestHash, signatureBase64, publicKeyPem);
}