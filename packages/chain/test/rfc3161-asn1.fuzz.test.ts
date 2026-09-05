// packages/chain/test/rfc3161-asn1.fuzz.test.ts
//
// Mutation fuzz loop for the hand-rolled DER parser behind RFC 3161
// validation. The producer feeds it bytes a TSA (or a network attacker)
// chose, so the contract is: every input either parses or throws
// TsrValidationError, in bounded time, with no other exception type and
// no hang. Seeds are the real FreeTSA and DigiCert tokens the Go
// verifier also uses. The PRNG is seeded so a failure reproduces.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { findTstInfoBytes, parseTstInfoFields } from '../src/rfc3161-asn1.js';
import { parseDerElement, getChildren } from '../src/asn1-der.js';
import { validateTsr } from '../src/timestamp-rfc3161.js';
import { TsrValidationError } from '../src/rfc3161-types.js';

const testdata = join(__dirname, '../../../apps/verify/timestamp/testdata');
const seeds = ['freetsa-token.tsr', 'digicert-token.tsr'].map((f) => readFileSync(join(testdata, f)));

const ITERATIONS = Number(process.env.DEPOSE_FUZZ_ITERATIONS ?? 4000);

/** xorshift32, deterministic across runs. */
function makeRng(seed: number): () => number {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 0x100000000;
  };
}

function mutate(seed: Buffer, rng: () => number): Buffer {
  const out = Buffer.from(seed);
  const strategy = Math.floor(rng() * 6);
  const at = () => Math.floor(rng() * out.length);
  switch (strategy) {
    case 0: {
      const flips = 1 + Math.floor(rng() * 8);
      for (let i = 0; i < flips; i++) out[at()] ^= 1 << Math.floor(rng() * 8);
      return out;
    }
    case 1:
      return out.subarray(0, at());
    case 2: {
      const pos = at();
      const junk = Buffer.alloc(1 + Math.floor(rng() * 16), Math.floor(rng() * 256));
      return Buffer.concat([out.subarray(0, pos), junk, out.subarray(pos)]);
    }
    case 3: {
      // Corrupt a length byte to a long-form length that overruns.
      const pos = at();
      out[pos] = 0x84;
      out[pos + 1] = 0xff;
      out[pos + 2] = 0xff;
      out[pos + 3] = 0xff;
      out[pos + 4] = 0xff;
      return out;
    }
    case 4: {
      // Indefinite length marker.
      out[at()] = 0x80;
      return out;
    }
    default: {
      const pos = at();
      return Buffer.concat([out.subarray(0, pos), out.subarray(pos), out.subarray(pos)]);
    }
  }
}

function assertBounded(fn: () => void): void {
  const started = Date.now();
  try {
    fn();
  } catch (err) {
    if (!(err instanceof TsrValidationError)) {
      throw new Error(`parser threw ${err instanceof Error ? err.constructor.name : typeof err}: ${String(err)}`, { cause: err });
    }
  }
  const elapsed = Date.now() - started;
  if (elapsed > 2000) {
    throw new Error(`parser took ${elapsed}ms on one input; a DER parser must be linear in input size`);
  }
}

describe('rfc3161 DER parser under mutation', () => {
  it('parses the seeds unmodified', () => {
    for (const seed of seeds) {
      const tstInfo = findTstInfoBytes(seed);
      const fields = parseTstInfoFields(tstInfo);
      expect(fields.genTime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(fields.messageImprint.hashedMessage.length).toBe(32);
    }
  });

  it(`throws only TsrValidationError and stays bounded over ${ITERATIONS} mutations`, () => {
    const rng = makeRng(0x5eed);
    const nonce = Buffer.from('0102030405060708', 'hex');
    const hash = '0'.repeat(64);
    for (let i = 0; i < ITERATIONS; i++) {
      const input = mutate(seeds[i % seeds.length]!, rng);
      assertBounded(() => {
        const elem = parseDerElement(input, 0);
        if (elem) getChildren(input, elem);
      });
      assertBounded(() => {
        const tstInfo = findTstInfoBytes(input);
        parseTstInfoFields(tstInfo);
      });
      assertBounded(() => {
        validateTsr(input, nonce, hash);
      });
    }
  });

  it('rejects an element whose long-form length overruns the buffer', () => {
    const overrun = Buffer.from([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x00]);
    expect(parseDerElement(overrun, 0)).toBeNull();
  });

  it('never yields a child that extends past its parent', () => {
    // Parent claims 4 bytes; child claims 10.
    const buf = Buffer.from([0x30, 0x04, 0x04, 0x0a, 0x00, 0x00]);
    const parent = parseDerElement(buf, 0)!;
    expect(getChildren(buf, parent)).toEqual([]);
  });
});
