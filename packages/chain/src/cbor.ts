// packages/chain/src/cbor.ts
//
// The subset of CBOR (RFC 8949) that COSE needs, encoded deterministically.
//
// Written here rather than taken from a package because the CLI ships one
// runtime dependency and a signed statement's bytes are on the trust
// boundary: a reader can check this file in one sitting against RFC 8949
// §3, which is not true of a general-purpose codec.
//
// Deterministic encoding follows RFC 8949 §4.2.1: the shortest form of
// every integer and length, and map keys sorted by their encoded bytes.
// Floats, indefinite lengths, and the other major types are deliberately
// absent; they cannot appear in the structures DEPOSE emits, and
// encodeCbor throws rather than guessing at them.

/** A value this encoder accepts. */
export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | CborTagged;

/** A tagged value (major type 6), used for the COSE_Sign1 tag. */
export interface CborTagged {
  tag: number;
  value: CborValue;
}

/**
 * Type guard for a tagged value.
 *
 * @param value - Any CBOR value.
 * @returns True when it is a `{tag, value}` pair.
 */
export function isCborTagged(value: CborValue): value is CborTagged {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    !(value instanceof Uint8Array) && !(value instanceof Map) && 'tag' in value;
}

/**
 * Encode a value as deterministic CBOR.
 *
 * @param value - The value to encode.
 * @returns The encoded bytes.
 * @throws TypeError when the value is of a kind this encoder does not
 *   cover (a float, a plain object, null, undefined, or a boolean); use a
 *   Map for CBOR maps and an integer or string for everything else.
 */
export function encodeCbor(value: CborValue): Uint8Array {
  const chunks: Uint8Array[] = [];
  write(value, chunks);
  return concat(chunks);
}

function write(value: CborValue, out: Uint8Array[]): void {
  if (typeof value === 'number' || typeof value === 'bigint') {
    writeInteger(value, out);
    return;
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    out.push(head(3, bytes.length));
    out.push(bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    out.push(head(2, value.length));
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    out.push(head(4, value.length));
    for (const item of value) write(item, out);
    return;
  }
  if (value instanceof Map) {
    writeMap(value, out);
    return;
  }
  if (isCborTagged(value)) {
    out.push(head(6, value.tag));
    write(value.value, out);
    return;
  }
  throw new TypeError(
    `encodeCbor received a value of type ${typeof value} it does not encode; ` +
      `use an integer, string, Uint8Array, array, Map, or {tag, value}`
  );
}

/** RFC 8949 §4.2.1: keys sorted by their encoded byte sequence. */
function writeMap(value: Map<CborValue, CborValue>, out: Uint8Array[]): void {
  const entries = Array.from(value.entries()).map(([k, v]) => ({
    key: encodeCbor(k),
    value: v,
  }));
  entries.sort((a, b) => compareBytes(a.key, b.key));
  out.push(head(5, entries.length));
  for (const entry of entries) {
    out.push(entry.key);
    write(entry.value, out);
  }
}

function writeInteger(value: number | bigint, out: Uint8Array[]): void {
  if (typeof value === 'number' && !Number.isInteger(value)) {
    throw new TypeError(`encodeCbor received the non-integer number ${value}; CBOR floats are not encoded here`);
  }
  const asBigint = typeof value === 'bigint' ? value : BigInt(value);
  if (asBigint >= 0n) {
    out.push(head(0, asBigint));
    return;
  }
  out.push(head(1, -asBigint - 1n));
}

/** Major type plus argument, in the shortest form RFC 8949 §4.2.1 allows. */
function head(major: number, argument: number | bigint): Uint8Array {
  const n = typeof argument === 'bigint' ? argument : BigInt(argument);
  const prefix = major << 5;
  if (n < 24n) return Uint8Array.from([prefix | Number(n)]);
  if (n < 0x100n) return Uint8Array.from([prefix | 24, Number(n)]);
  if (n < 0x10000n) return Uint8Array.from([prefix | 25, Number(n >> 8n) & 0xff, Number(n) & 0xff]);
  if (n < 0x100000000n) {
    return Uint8Array.from([
      prefix | 26,
      Number((n >> 24n) & 0xffn),
      Number((n >> 16n) & 0xffn),
      Number((n >> 8n) & 0xffn),
      Number(n & 0xffn),
    ]);
  }
  if (n < 0x10000000000000000n) {
    const bytes = [prefix | 27];
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      bytes.push(Number((n >> shift) & 0xffn));
    }
    return Uint8Array.from(bytes);
  }
  throw new TypeError(`encodeCbor cannot represent the argument ${n}; it exceeds 64 bits`);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
