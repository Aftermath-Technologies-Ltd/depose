// packages/chain/src/key-catalog.ts
//
// Producer-side key lifecycle catalog (rotation + revocation).
//
// What this is. A JSON file the producer maintains and publishes
// out-of-band (same trust channel they use for their fingerprint —
// .well-known page, signed git tag, attorney's printed handshake).
// Each entry records a producer key fingerprint and its status:
//
//   - active:   the key currently used for new signatures
//   - rotated:  retired voluntarily; bundles signed under it are
//               still cryptographically valid but should be treated
//               as historical
//   - revoked:  invalidated for cause (compromise suspected);
//               verifiers should reject bundles signed under it
//
// The catalog is the producer's public position on which of their
// keys are trustworthy *right now*. Recipients pin a catalog source
// (URL or local path) and pass it to the verifier via
// `depose-verify verify --revocation-list <path>`.
//
// Out of scope for this MVP. We do not yet sign the catalog with
// the current active key. The catalog is trusted at the same level
// as the fingerprint pin itself — both must reach the recipient
// over a channel they trust. Catalog signing is tracked in
// docs/key-management.md.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const KEY_CATALOG_SCHEMA_VERSION = 1;

export type KeyCatalogStatus = 'active' | 'rotated' | 'revoked';

export interface KeyCatalogEntry {
  /** SHA-256 hex of the SPKI-DER form of the public key. */
  fingerprint: string;
  status: KeyCatalogStatus;
  /** ISO 8601 timestamp the key was first written. */
  issuedAt: string;
  /** Present iff status === 'rotated'. */
  rotatedAt?: string;
  /** Present iff status === 'revoked'. */
  revokedAt?: string;
  /** Free-form reason; required when revoking. */
  reason?: string;
  /** PEM-encoded public key (kept for offline recipient verification). */
  publicKeyPem: string;
}

export interface KeyCatalog {
  schemaVersion: number;
  /** ISO 8601 timestamp the catalog was last written. */
  updatedAt: string;
  entries: KeyCatalogEntry[];
}

function emptyCatalog(): KeyCatalog {
  return {
    schemaVersion: KEY_CATALOG_SCHEMA_VERSION,
    updatedAt: new Date().toISOString(),
    entries: [],
  };
}

export function loadCatalog(path: string): KeyCatalog {
  if (!existsSync(path)) return emptyCatalog();
  const raw = readFileSync(path, 'utf-8');
  const parsed = JSON.parse(raw) as KeyCatalog;
  if (parsed.schemaVersion !== KEY_CATALOG_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported key-catalog schemaVersion ${parsed.schemaVersion}; ` +
        `this build supports ${KEY_CATALOG_SCHEMA_VERSION}.`,
    );
  }
  if (!Array.isArray(parsed.entries)) {
    throw new Error('Malformed key catalog: entries[] missing or not an array.');
  }
  return parsed;
}

export function saveCatalog(path: string, catalog: KeyCatalog): void {
  mkdirSync(dirname(path), { recursive: true });
  const out = { ...catalog, updatedAt: new Date().toISOString() };
  writeFileSync(path, JSON.stringify(out, null, 2) + '\n', 'utf-8');
}

export function findEntry(catalog: KeyCatalog, fingerprint: string): KeyCatalogEntry | undefined {
  return catalog.entries.find((e) => e.fingerprint.toLowerCase() === fingerprint.toLowerCase());
}

/**
 * Record a freshly-generated key as `active`. If another entry is
 * already `active`, leave it alone — the caller is responsible for
 * calling markRotated() on it first (this is what `depose key rotate`
 * does).
 */
export function recordActive(
  catalog: KeyCatalog,
  fingerprint: string,
  publicKeyPem: string,
): KeyCatalog {
  if (findEntry(catalog, fingerprint)) return catalog;
  const entry: KeyCatalogEntry = {
    fingerprint,
    status: 'active',
    issuedAt: new Date().toISOString(),
    publicKeyPem,
  };
  return { ...catalog, entries: [...catalog.entries, entry] };
}

export function markRotated(catalog: KeyCatalog, fingerprint: string): KeyCatalog {
  const entries = catalog.entries.map((e) => {
    if (e.fingerprint.toLowerCase() !== fingerprint.toLowerCase()) return e;
    if (e.status === 'revoked') return e; // revocation wins
    return { ...e, status: 'rotated' as const, rotatedAt: new Date().toISOString() };
  });
  return { ...catalog, entries };
}

export function markRevoked(catalog: KeyCatalog, fingerprint: string, reason: string): KeyCatalog {
  if (!reason || !reason.trim()) {
    throw new Error('Revocation requires a non-empty --reason explaining why.');
  }
  let found = false;
  const entries = catalog.entries.map((e) => {
    if (e.fingerprint.toLowerCase() !== fingerprint.toLowerCase()) return e;
    found = true;
    return {
      ...e,
      status: 'revoked' as const,
      revokedAt: new Date().toISOString(),
      reason,
    };
  });
  if (!found) {
    throw new Error(
      `Fingerprint ${fingerprint} not in catalog. Only keys that have been ` +
        `used to sign bundles (or recorded via recordActive) can be revoked.`,
    );
  }
  return { ...catalog, entries };
}

export function isRevoked(catalog: KeyCatalog, fingerprint: string): boolean {
  const entry = findEntry(catalog, fingerprint);
  return entry?.status === 'revoked';
}
