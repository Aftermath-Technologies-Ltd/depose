// Conformance suite for RFC 8785 JSON Canonicalization Scheme.
//
// Both this file and apps/verify/canonical/jcs_test.go run the same
// vectors from tests/conformance/canonical-json-vectors.json. Any
// divergence between the two languages means a signature signed by
// the TypeScript producer will not verify in the Go verifier (or
// vice versa) — that breaks the entire cross-language trust path.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson } from '../src/events/canonical-json.js';

interface Vector {
  name: string;
  input: unknown;
  expected: string;
}

interface VectorFile {
  description: string;
  vectors: Vector[];
}

const vectorPath = join(__dirname, '../../../tests/conformance/canonical-json-vectors.json');
const file: VectorFile = JSON.parse(readFileSync(vectorPath, 'utf-8'));

describe('canonical JSON conformance (RFC 8785 JCS)', () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    const got = canonicalJson(vector.input);
    expect(got).toBe(vector.expected);
  });
});
