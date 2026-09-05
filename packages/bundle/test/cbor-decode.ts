// packages/bundle/test/cbor-decode.ts
//
// A CBOR decoder for the tests only. The exporter has no reason to decode
// CBOR, so shipping a decoder in the package would be architecture for a
// case that does not exist; the conformance tests do need one, to read
// back a COSE_Sign1 and check its protected header against the SCITT
// requirements rather than against the bytes the encoder happened to emit.

/** A decoded CBOR value. */
export type Decoded =
  | number
  | bigint
  | string
  | Uint8Array
  | Decoded[]
  | Map<Decoded, Decoded>
  | { tag: number; value: Decoded };

/**
 * Decode one CBOR item.
 *
 * @param bytes - The encoded item, possibly with trailing data.
 * @returns The value and the number of bytes consumed.
 * @throws Error on a major type this decoder does not cover.
 */
export function decodeCbor(bytes: Uint8Array): { value: Decoded; length: number } {
  const initial = bytes[0]!;
  const major = initial >> 5;
  const minor = initial & 0x1f;
  const { argument, headerLength } = readArgument(bytes, minor);

  switch (major) {
    case 0:
      return { value: toNumber(argument), length: headerLength };
    case 1:
      return { value: toNumber(-argument - 1n), length: headerLength };
    case 2: {
      const length = Number(argument);
      return { value: bytes.subarray(headerLength, headerLength + length), length: headerLength + length };
    }
    case 3: {
      const length = Number(argument);
      const text = new TextDecoder().decode(bytes.subarray(headerLength, headerLength + length));
      return { value: text, length: headerLength + length };
    }
    case 4: {
      const items: Decoded[] = [];
      let offset = headerLength;
      for (let i = 0; i < Number(argument); i++) {
        const item = decodeCbor(bytes.subarray(offset));
        items.push(item.value);
        offset += item.length;
      }
      return { value: items, length: offset };
    }
    case 5: {
      const map = new Map<Decoded, Decoded>();
      let offset = headerLength;
      for (let i = 0; i < Number(argument); i++) {
        const key = decodeCbor(bytes.subarray(offset));
        offset += key.length;
        const value = decodeCbor(bytes.subarray(offset));
        offset += value.length;
        map.set(key.value, value.value);
      }
      return { value: map, length: offset };
    }
    case 6: {
      const inner = decodeCbor(bytes.subarray(headerLength));
      return { value: { tag: Number(argument), value: inner.value }, length: headerLength + inner.length };
    }
    default:
      throw new Error(`decodeCbor does not handle major type ${major}`);
  }
}

function readArgument(bytes: Uint8Array, minor: number): { argument: bigint; headerLength: number } {
  if (minor < 24) return { argument: BigInt(minor), headerLength: 1 };
  const widths: Record<number, number> = { 24: 1, 25: 2, 26: 4, 27: 8 };
  const width = widths[minor];
  if (width === undefined) {
    throw new Error(`decodeCbor does not handle the additional information ${minor}`);
  }
  let argument = 0n;
  for (let i = 0; i < width; i++) {
    argument = (argument << 8n) | BigInt(bytes[1 + i]!);
  }
  return { argument, headerLength: 1 + width };
}

function toNumber(value: bigint): number | bigint {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

/** The four members of a COSE_Sign1, unwrapped from its tag. */
export interface CoseSign1Parts {
  tag: number;
  protectedBytes: Uint8Array;
  protectedHeader: Map<Decoded, Decoded>;
  unprotected: Map<Decoded, Decoded>;
  payload: Uint8Array;
  signature: Uint8Array;
}

/**
 * Decode a tagged COSE_Sign1.
 *
 * @param bytes - The message.
 * @returns Its parts, with the protected header decoded as well as kept raw.
 */
export function decodeCoseSign1(bytes: Uint8Array): CoseSign1Parts {
  const { value } = decodeCbor(bytes);
  if (typeof value !== 'object' || value === null || !('tag' in value)) {
    throw new Error('not a tagged CBOR item');
  }
  const tagged = value as { tag: number; value: Decoded };
  const parts = tagged.value as Decoded[];
  const protectedBytes = parts[0] as Uint8Array;
  return {
    tag: tagged.tag,
    protectedBytes,
    protectedHeader: decodeCbor(protectedBytes).value as Map<Decoded, Decoded>,
    unprotected: parts[1] as Map<Decoded, Decoded>,
    payload: parts[2] as Uint8Array,
    signature: parts[3] as Uint8Array,
  };
}
