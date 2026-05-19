// packages/core/src/events/canonical-json.ts
//
// Deterministic JSON canonicalization (RFC 8785 JCS-like).
// Used for computing payloadHash and chainHash — every identical
// payload must produce identical byte output so SHA-256 is stable.
//
// Rules:
//   1. Sort object keys lexicographically (deep, recursive).
//   2. No whitespace (minified).
//   3. UTF-8 encoded.
//   4. Numbers serialized as-is (JSON.stringify behavior).
//   5. null, true, false as lowercase.
//   6. Arrays preserved (order matters).
//   7. Strings escaped per JSON spec (including unicode).

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
  // Functions, symbols, etc. — should not appear in payloads
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
