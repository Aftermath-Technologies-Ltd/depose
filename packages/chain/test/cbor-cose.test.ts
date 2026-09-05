// packages/chain/test/cbor-cose.test.ts
//
// The CBOR encoder is on the trust boundary: a SCITT Signed Statement's
// signature covers bytes this file produces, so it is checked against
// RFC 8949's own Appendix A vectors rather than against itself. The
// did:key vectors were computed with an independent base58
// implementation, for the same reason.

import { describe, it, expect } from 'vitest';
import { encodeCbor, type CborValue } from '../src/cbor.js';
import { base58btcEncode, didKeyFromEd25519Pem, bareDidKeyFromEd25519Pem } from '../src/did-key.js';
import {
  signCoseSign1,
  verifyCoseSign1,
  rawEd25519PublicKey,
  COSE_ALG_EDDSA,
  COSE_SIGN1_TAG,
} from '../src/cose-sign1.js';
import { generateEd25519KeyPair } from '../src/sign-ed25519.js';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe('encodeCbor against RFC 8949 Appendix A', () => {
  const vectors: Array<[CborValue, string]> = [
    [0, '00'],
    [1, '01'],
    [10, '0a'],
    [23, '17'],
    [24, '1818'],
    [100, '1864'],
    [1000, '1903e8'],
    [1000000, '1a000f4240'],
    [1000000000000n, '1b000000e8d4a51000'],
    [-1, '20'],
    [-10, '29'],
    [-100, '3863'],
    [-1000, '3903e7'],
    ['', '60'],
    ['a', '6161'],
    ['IETF', '6449455446'],
    ['"\\', '62225c'],
    [new Uint8Array([1, 2, 3, 4]), '4401020304'],
    [[], '80'],
    [[1, 2, 3], '83010203'],
    [new Map(), 'a0'],
    [
      new Map<CborValue, CborValue>([
        [1, 2],
        [3, 4],
      ]),
      'a201020304',
    ],
    [['a', new Map<CborValue, CborValue>([['b', 'c']])], '826161a161626163'],
  ];

  it.each(vectors)('encodes %o', (value, expected) => {
    expect(hex(encodeCbor(value))).toBe(expected);
  });

  it('encodes the COSE EdDSA algorithm identifier as a negative integer', () => {
    expect(hex(encodeCbor(COSE_ALG_EDDSA))).toBe('27');
  });
});

describe('deterministic encoding rules', () => {
  it('sorts map keys by their encoded bytes, not by insertion order', () => {
    const inOrder = new Map<CborValue, CborValue>([
      [1, 'a'],
      [3, 'b'],
      [15, 'c'],
    ]);
    const shuffled = new Map<CborValue, CborValue>([
      [15, 'c'],
      [1, 'a'],
      [3, 'b'],
    ]);
    expect(hex(encodeCbor(shuffled))).toBe(hex(encodeCbor(inOrder)));
    expect(hex(encodeCbor(inOrder))).toBe('a3016161036162' + '0f6163');
  });

  it('uses the shortest form of every argument', () => {
    expect(hex(encodeCbor(23))).toHaveLength(2);
    expect(hex(encodeCbor(24))).toHaveLength(4);
    expect(hex(encodeCbor(255))).toBe('18ff');
    expect(hex(encodeCbor(256))).toBe('190100');
  });

  it('refuses a value it cannot encode rather than guessing', () => {
    expect(() => encodeCbor(1.5 as unknown as CborValue)).toThrow(/non-integer/);
    expect(() => encodeCbor(true as unknown as CborValue)).toThrow(/does not encode/);
    expect(() => encodeCbor({ a: 1 } as unknown as CborValue)).toThrow(/does not encode/);
  });

  it('encodes a tagged value with the tag preceding its content', () => {
    expect(hex(encodeCbor({ tag: COSE_SIGN1_TAG, value: [] }))).toBe('d280');
  });
});

describe('base58btc and did:key', () => {
  // Computed with an independent base58 implementation over the
  // multicodec-prefixed key bytes (0xed 0x01 followed by the 32 bytes).
  const vectors: Array<[Uint8Array, string]> = [
    [new Uint8Array(32), 'did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP'],
    [new Uint8Array(32).fill(0xff), 'did:key:z6MkwgaR63138bEEgad7uk993KMX54vBA6KTB4sFhCPnSB2e'],
    [Uint8Array.from(Array.from({ length: 32 }, (_, i) => i)), 'did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c'],
  ];

  it.each(vectors)('derives the identifier for a known key', (raw, expected) => {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw)]);
    const pem = `-----BEGIN PUBLIC KEY-----\n${spki.toString('base64')}\n-----END PUBLIC KEY-----\n`;
    expect(didKeyFromEd25519Pem(pem)).toBe(expected);
  });

  it('keeps one leading "1" per leading zero byte', () => {
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe('112');
    expect(base58btcEncode(new Uint8Array([0]))).toBe('1');
  });

  it('drops only the did: scheme for the bare form the receipt profile wants', () => {
    const keyPair = generateEd25519KeyPair();
    const did = didKeyFromEd25519Pem(keyPair.publicKeyPem);
    expect(bareDidKeyFromEd25519Pem(keyPair.publicKeyPem)).toBe(did.slice('did:'.length));
    expect(bareDidKeyFromEd25519Pem(keyPair.publicKeyPem).startsWith('key:z6Mk')).toBe(true);
  });

  it('extracts the 32 raw key bytes from an SPKI PEM', () => {
    const keyPair = generateEd25519KeyPair();
    expect(rawEd25519PublicKey(keyPair.publicKeyPem)).toHaveLength(32);
  });
});

describe('COSE_Sign1', () => {
  it('round-trips a signature over the Sig_structure', () => {
    const keyPair = generateEd25519KeyPair();
    const protectedHeader = new Map<CborValue, CborValue>([[1, COSE_ALG_EDDSA]]);
    const payload = new Uint8Array([1, 2, 3]);
    const message = signCoseSign1({ protectedHeader, payload }, keyPair);

    expect(message[0]).toBe(0xd2); // tag 18
    const protectedBytes = encodeCbor(protectedHeader);
    const signature = message.subarray(message.length - 64);
    expect(verifyCoseSign1(protectedBytes, payload, signature, keyPair.publicKeyPem)).toBe(true);
  });

  it('a payload that changed no longer verifies', () => {
    const keyPair = generateEd25519KeyPair();
    const protectedHeader = new Map<CborValue, CborValue>([[1, COSE_ALG_EDDSA]]);
    const message = signCoseSign1({ protectedHeader, payload: new Uint8Array([1, 2, 3]) }, keyPair);
    const signature = message.subarray(message.length - 64);

    expect(
      verifyCoseSign1(encodeCbor(protectedHeader), new Uint8Array([1, 2, 4]), signature, keyPair.publicKeyPem)
    ).toBe(false);
  });

  it('a protected header that changed no longer verifies', () => {
    const keyPair = generateEd25519KeyPair();
    const payload = new Uint8Array([1, 2, 3]);
    const message = signCoseSign1({ protectedHeader: new Map<CborValue, CborValue>([[1, COSE_ALG_EDDSA]]), payload }, keyPair);
    const signature = message.subarray(message.length - 64);
    const rewritten = encodeCbor(new Map<CborValue, CborValue>([[1, -7]]));

    expect(verifyCoseSign1(rewritten, payload, signature, keyPair.publicKeyPem)).toBe(false);
  });

  it('signs the same message identically every time', () => {
    const keyPair = generateEd25519KeyPair();
    const input = { protectedHeader: new Map<CborValue, CborValue>([[1, COSE_ALG_EDDSA]]), payload: new Uint8Array([9]) };
    expect(hex(signCoseSign1(input, keyPair))).toBe(hex(signCoseSign1(input, keyPair)));
  });
});
