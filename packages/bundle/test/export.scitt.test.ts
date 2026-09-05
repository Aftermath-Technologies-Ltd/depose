// packages/bundle/test/export.scitt.test.ts
//
// The SCITT Signed Statement, checked against what
// draft-ietf-scitt-architecture requires of a statement and what
// draft-mih-scitt-agent-action-capsule-04 requires of the capsule inside
// it. Decoding the message back rather than comparing to the encoder's
// own output is the point: the assertions are about the wire form.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson } from '@depose/core';
import { verifyCoseSign1, rawEd25519PublicKey, didKeyFromEd25519Pem } from '@depose/chain';
import {
  buildCapsule,
  capsuleId,
  exportScittStatement,
  CAPSULE_CONTENT_TYPE,
  type LoadedBundle,
} from '../src/index.js';
import { decodeCoseSign1, type Decoded } from './cbor-decode.js';
import { EXPORT_EXAMPLES, EXPORT_TEST_KEY, sealExample } from './export-fixture.js';

const outputRoot = join(__dirname, 'test-output-export-scitt');
const bundles = new Map<string, LoadedBundle>();

beforeAll(async () => {
  rmSync(outputRoot, { recursive: true, force: true });
  mkdirSync(outputRoot, { recursive: true });
  for (const example of EXPORT_EXAMPLES) {
    bundles.set(example, await sealExample(example, outputRoot));
  }
});

afterAll(() => {
  rmSync(outputRoot, { recursive: true, force: true });
});

describe.each(EXPORT_EXAMPLES)('SCITT signed statement for %s', (example) => {
  it('is a tagged COSE_Sign1 whose signature verifies over the Sig_structure', () => {
    const bytes = exportScittStatement(bundles.get(example)!, EXPORT_TEST_KEY);
    const parts = decodeCoseSign1(bytes);

    expect(parts.tag).toBe(18);
    expect(parts.unprotected.size).toBe(0);
    expect(
      verifyCoseSign1(parts.protectedBytes, parts.payload, parts.signature, EXPORT_TEST_KEY.publicKeyPem)
    ).toBe(true);
  });

  it('carries CWT_Claims with iss and sub, which is what SCITT requires', () => {
    const parts = decodeCoseSign1(exportScittStatement(bundles.get(example)!, EXPORT_TEST_KEY));
    const claims = parts.protectedHeader.get(15) as Map<Decoded, Decoded>;

    expect(claims).toBeInstanceOf(Map);
    expect(claims.get(1)).toBe(didKeyFromEd25519Pem(EXPORT_TEST_KEY.publicKeyPem));
    expect(claims.get(2)).toBe(`depose:bundle:${bundles.get(example)!.manifest.bundleId}`);
  });

  it('declares the capsule media type and the signer key', () => {
    const parts = decodeCoseSign1(exportScittStatement(bundles.get(example)!, EXPORT_TEST_KEY));
    expect(parts.protectedHeader.get(1)).toBe(-8);
    expect(parts.protectedHeader.get(3)).toBe(CAPSULE_CONTENT_TYPE);
    expect(Buffer.from(parts.protectedHeader.get(4) as Uint8Array)).toEqual(
      Buffer.from(rawEd25519PublicKey(EXPORT_TEST_KEY.publicKeyPem))
    );
  });

  it('carries a capsule whose id recomputes from its own JCS bytes', () => {
    const parts = decodeCoseSign1(exportScittStatement(bundles.get(example)!, EXPORT_TEST_KEY));
    const capsule = JSON.parse(Buffer.from(parts.payload).toString('utf-8'));

    expect(capsule.canonicalization_id).toBe('jcs');
    expect(capsule.format_version).toBe('4');
    expect(capsule.capsule_id).toMatch(/^[0-9a-f]{64}$/);
    expect(capsuleId(capsule)).toBe(capsule.capsule_id);
    expect(Buffer.from(parts.payload).toString('utf-8')).toBe(canonicalJson(capsule));
  });

  it('never claims a confirmed effect without a response digest', () => {
    const capsule = buildCapsule(bundles.get(example)!);
    if (capsule.effect.status === 'confirmed') {
      expect(capsule.effect.response_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
    expect(capsule.assurance.effect_mode).toBe('confirmed');
    expect(capsule.assurance.attestation_mode).toBe('anchored');
  });

  it('reports the destructive rule as non-blocking, because nothing was blocked', () => {
    const capsule = buildCapsule(bundles.get(example)!);
    const rule = capsule.constraints.find((c) => c.id === 'destructive_ruleset')!;
    expect(rule.result).toBe('fail');
    expect(rule.blocking).toBe(false);
    expect(rule.evidence_digest).toBe(`sha256:${bundles.get(example)!.manifest.rulesetHash}`);
  });

  it('references the events file and the Merkle root by digest', () => {
    const capsule = buildCapsule(bundles.get(example)!);
    const manifest = bundles.get(example)!.manifest;
    expect(capsule.references).toContainEqual({
      type: 'depose:events_jsonl',
      digest: `sha256:${manifest.eventsJsonlSha256}`,
    });
    expect(capsule.references).toContainEqual({
      type: 'depose:merkle_root',
      digest: `sha256:${manifest.merkleRoot}`,
    });
  });

  it('refuses to sign a statement over a dev-unsigned bundle', () => {
    const bundle = bundles.get(example)!;
    const unsigned = { ...bundle, manifest: { ...bundle.manifest, producer: { ...bundle.manifest.producer, mode: 'dev-unsigned' as const } } };
    expect(() => exportScittStatement(unsigned, EXPORT_TEST_KEY)).toThrow(/carries none of its own/);
  });
});
