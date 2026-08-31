// packages/core/src/events/canonical-json.ts
//
// RFC 8785 JSON Canonicalization Scheme (JCS). See
// docs/canonical-json.md for the spec we follow. Conformance vectors
// in tests/conformance/canonical-json-vectors.json run against both
// this implementation and apps/verify/canonical/jcs.go, any
// divergence breaks cross-language signature verification.
//
// Node's JSON.stringify already produces the right number form, the
// JSON minimum escape set, and literal UTF-8 for non-ASCII printable
// characters. The only preprocessing we need is recursive object
// key sort (sortKeys).

import { createHash } from 'node:crypto';

// ── Canonical serializer ─────────────────────────────────────────────

/**
 * Serialize a JavaScript value to canonical (deterministic) JSON.
 * Objects are sorted by key; everything else is standard JSON.stringify.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value), null, 0);
}

/**
 * Deeply sort object keys lexicographically.
 * Arrays preserve order. Primitives pass through.
 */
export function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const key of keys) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  // Functions, symbols, etc., should not appear in payloads
  return value;
}

// ── SHA-256 hash ─────────────────────────────────────────────────────

/**
 * Compute SHA-256 hex digest of a JavaScript value.
 * Serializes to canonical JSON first, then hashes UTF-8 bytes.
 */
export function sha256(value: unknown): string {
  const canonical = canonicalJson(value);
  return createHash('sha256').update(canonical, 'utf-8').digest('hex');
}

/**
 * Compute SHA-256 hex digest of a UTF-8 string (without canonicalization).
 */
export function sha256String(input: string): string {
  return createHash('sha256').update(input, 'utf-8').digest('hex');
}

/**
 * Compute SHA-256 hex digest of raw bytes. Use this when integrity must
 * match a specific byte sequence (e.g. a file embedded in a bundle)
 * rather than a re-encoded UTF-8 string.
 */
export function sha256Bytes(input: Buffer | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}
