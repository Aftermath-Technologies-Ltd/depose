// packages/core/src/events/ids.ts
//
// ULID helpers for DEPOSE event and session identifiers.
// Minimal, dependency-free implementation.
// See: https://github.com/ulid/spec

// ── Constants ─────────────────────────────────────────────────────────

/** Crockford Base32 character set (excludes I, L, O, U to avoid ambiguity) */
const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ULID_LENGTH = 26;
const TS_BYTES = 6;
const RAND_BYTES = 10;
const TOTAL = TS_BYTES + RAND_BYTES;

const CRYPTO = typeof globalThis !== 'undefined' && (globalThis as Record<string, unknown>).crypto;

// ── Fixed seed (for tests) ───────────────────────────────────────────

let _fixedSeedMs = 0;
let _fixedSeedMono = 0;
let _usingFixed = false;

/** Set a fixed seed for deterministic ULID generation (for tests). */
export function setFixedUlidSeed(seedMs: number | bigint): void {
  _fixedSeedMs = Number(seedMs);
  _fixedSeedMono = 0;
  _usingFixed = true;
}

/** Clear the fixed seed, reverting to random ULID generation. */
export function clearFixedUlidSeed(): void {
  _usingFixed = false;
  _fixedSeedMs = 0;
  _fixedSeedMono = 0;
}

// ── Core ─────────────────────────────────────────────────────────────

/**
 * Generate a new ULID for the current time.
 *
 * The first 48 bits are the wall-clock millisecond timestamp and the
 * remaining 80 bits are CSPRNG random, per the ULID spec. This is what
 * makes ids lexicographically sortable by creation time, which the
 * capture store relies on: records are read in filename order and that
 * order has to be capture order.
 *
 * This previously randomized all 16 bytes, timestamp prefix included,
 * contradicting the documented layout in encodeUlid and making every
 * event id unsortable. Capture filenames decoded to times ranging from
 * 1970 to the year 10888.
 */
export function generateUlid(): string {
  const bytes = randomBytes(TOTAL);
  // Under a fixed seed, randomBytes() has already written the seeded
  // millisecond value into the timestamp bytes. Overwriting it with the
  // wall clock here would break round-trip determinism.
  if (!_usingFixed) {
    writeMsToBytes(bytes, Date.now());
  }
  return encodeUlid(bytes);
}

/** Generate a ULID that encodes the given timestamp (ms). */
export function ulidFromTime(timestampMs: number): string {
  const bytes = randomBytes(TOTAL);
  writeMsToBytes(bytes, timestampMs);
  return encodeUlid(bytes);
}

/** Check if a string is a valid ULID. */
export function isValidUlid(value: string): boolean {
  if (typeof value !== 'string' || value.length !== ULID_LENGTH) return false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]!;
    if (ENCODING.indexOf(ch) === -1) return false;
  }
  return true;
}

/** Extract the timestamp (ms) encoded in a ULID. */
export function ulidToTime(ulid: string): number {
  const bytes = decodeUlid(ulid);
  return msFromBytes(bytes);
}

// ── Internal ─────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const bytes = new Uint8Array(n);
  if (_usingFixed) {
    const ms = _fixedSeedMs + _fixedSeedMono;
    writeMsToBytes(bytes, ms);
    const counter = _fixedSeedMono * 1000;
    for (let i = 0; i < RAND_BYTES; i++) {
      bytes[TS_BYTES + i] = (counter >>> (8 * (RAND_BYTES - 1 - i))) & 0xff;
    }
    _fixedSeedMono++;
    return bytes;
  }
  // CSPRNG is mandatory in evidence paths; there is no Math.random
  // fallback. Node ≥20 always exposes globalThis.crypto; browsers
  // running on http: contexts (where crypto may be undefined) are
  // not supported producers and must error loudly rather than emit
  // a predictable ULID.
  if (!CRYPTO || typeof (CRYPTO as { getRandomValues?: unknown }).getRandomValues !== 'function') {
    throw new Error(
      'CSPRNG unavailable: globalThis.crypto.getRandomValues is missing. ' +
      'DEPOSE evidence IDs require a cryptographically secure RNG; ' +
      'refusing to silently weaken to Math.random.'
    );
  }
  return (CRYPTO as { getRandomValues: (arr: Uint8Array) => Uint8Array }).getRandomValues(bytes);
}

/**
 * Write a millisecond timestamp into the first 6 bytes (big-endian, 48 bits).
 *
 * Handles the 48-bit value correctly despite JS 32-bit bitwise limits by
 * splitting into a high 16-bit word and a low 32-bit word.
 */
function writeMsToBytes(bytes: Uint8Array, ms: number): void {
  const high = Math.floor(ms / 0x100000000);
  const low = ms >>> 0;
  bytes[0] = (high >>> 8) & 0xff;
  bytes[1] = high & 0xff;
  bytes[2] = (low >>> 24) & 0xff;
  bytes[3] = (low >>> 16) & 0xff;
  bytes[4] = (low >>> 8) & 0xff;
  bytes[5] = low & 0xff;
}

/** Read a millisecond timestamp from the first 6 bytes (big-endian, 48 bits). */
function msFromBytes(bytes: Uint8Array): number {
  const high = ((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0);
  const low = ((bytes[2] ?? 0) << 24) | ((bytes[3] ?? 0) << 16) | ((bytes[4] ?? 0) << 8) | (bytes[5] ?? 0);
  return high * 0x100000000 + (low >>> 0);
}

/**
 * Encode 16 bytes (128 bits) to a 26-character Crockford Base32 string.
 *
 * 128 bits produce exactly 25.6 five-bit groups. The 26th character
 * uses only its top 3 bits; the bottom 2 bits are zero-padded.
 *
 * Per ULID spec:
 *   Chars 0-9  encode the 48-bit timestamp
 *   Chars 10-25 encode the 80-bit random component
 */
function encodeUlid(bytes: Uint8Array): string {
  const out: string[] = new Array<string>(ULID_LENGTH);
  let bitPos = 0;

  for (let ci = 0; ci < ULID_LENGTH; ci++) {
    let val = 0;
    for (let b = 0; b < 5; b++) {
      const bp = bitPos + b;
      const byteIdx = bp >> 3;
      const bitIdx = 7 - (bp & 7);
      val = (val << 1) | ((bytes[byteIdx]! >>> bitIdx) & 1);
    }
    out[ci] = ENCODING[val & 0x1f] ?? '';
    bitPos += 5;
  }

  return out.join('');
}

/**
 * Decode a 26-character Crockford Base32 ULID string to 16 bytes.
 *
 * Each character contributes 5 bits (130 total). The first 128 bits
 * are the ULID value; the last 2 bits (bottom 2 bits of the 26th
 * character) are padding and are discarded.
 */
function decodeUlid(ulid: string): Uint8Array {
  const bytes = new Uint8Array(TOTAL);
  let curBit = 0;

  for (let ci = 0; ci < ULID_LENGTH; ci++) {
    const charVal = ENCODING.indexOf(ulid[ci]!);
    for (let b = 4; b >= 0; b--) {
      if (curBit >= 128) break;
      const bit = (charVal >> b) & 1;
      const byteIdx = curBit >> 3;
      const bitIdx = 7 - (curBit & 7);
      if (bit) {
        bytes[byteIdx] = bytes[byteIdx]! | (1 << bitIdx);
      }
      curBit++;
    }
  }

  return bytes;
}