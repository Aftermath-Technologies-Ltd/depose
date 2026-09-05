// packages/bundle/test/export.conformance.test.ts
//
// Every export is checked against what the draft it targets requires, not
// against what the exporter happens to emit. The golden test next door
// pins the bytes; this one pins the meaning.
//
//   draft-sharif-agent-audit-trail-00
//   draft-marques-asqav-compliance-receipts-08
//
// The SCITT statement has its own file, export.scitt.test.ts.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { verify, createPublicKey } from 'node:crypto';
import { canonicalJson, sha256String } from '@depose/core';

import {
  aatRecords,
  asqavReceipts,
  GENESIS_PREVIOUS_HASH,
  type AatRecord,
  type AsqavReceipt,
  type LoadedBundle,
} from '../src/index.js';
import { EXPORT_EXAMPLES, EXPORT_TEST_KEY, sealExample } from './export-fixture.js';

const outputRoot = join(__dirname, 'test-output-export-conformance');
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

const AAT_ACTION_TYPES = ['tool_call', 'tool_response', 'decision', 'delegation', 'escalation', 'error', 'lifecycle'];
const AAT_OUTCOMES = ['success', 'failure', 'timeout', 'denied', 'escalated'];
const AAT_TRUST_LEVELS = ['L0', 'L1', 'L2', 'L3', 'L4'];
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe.each(EXPORT_EXAMPLES)('AAT export of %s', (example) => {
  let records: AatRecord[];
  beforeAll(() => {
    records = aatRecords(bundles.get(example)!);
  });

  it('emits one record per sealed event', () => {
    expect(records).toHaveLength(bundles.get(example)!.events.length);
  });

  it('fills every mandatory field on every record', () => {
    for (const record of records) {
      for (const field of [
        'record_id',
        'timestamp',
        'agent_id',
        'agent_version',
        'session_id',
        'action_type',
        'action_detail',
        'outcome',
        'trust_level',
      ] as const) {
        expect(record[field], `${field} on ${record.record_id}`).toBeDefined();
      }
      // parent_record_id and prev_hash are mandatory but nullable.
      expect('parent_record_id' in record).toBe(true);
      expect('prev_hash' in record).toBe(true);
    }
  });

  it('keeps every enumerated field inside its vocabulary', () => {
    for (const record of records) {
      expect(AAT_ACTION_TYPES).toContain(record.action_type);
      expect(AAT_OUTCOMES).toContain(record.outcome);
      expect(AAT_TRUST_LEVELS).toContain(record.trust_level);
    }
  });

  it('emits RFC 9562 UUIDs with the correct variant bits', () => {
    for (const record of records) {
      expect(record.record_id).toMatch(UUID_SHAPE);
      expect(record.session_id).toMatch(UUID_SHAPE);
      if (record.parent_record_id !== null) {
        expect(record.parent_record_id).toMatch(UUID_SHAPE);
      }
    }
  });

  it('uses the same derived id for the same event everywhere it appears', () => {
    const byId = new Map(records.map((r) => [r.record_id, r]));
    for (const record of records) {
      if (record.parent_record_id === null) continue;
      expect(byId.has(record.parent_record_id)).toBe(true);
    }
  });

  it('starts the chain with a null prev_hash and links every later record', () => {
    expect(records[0]!.prev_hash).toBeNull();
    for (let i = 1; i < records.length; i++) {
      expect(records[i]!.prev_hash).toBe(sha256String(canonicalJson(records[i - 1]!)));
    }
  });

  it('reports a coverage gap as a failure, never as a success', () => {
    const bundle = bundles.get(example)!;
    const gapIndices = bundle.events
      .map((event, index) => (event.type === 'gap' ? index : -1))
      .filter((index) => index >= 0);
    expect(gapIndices.length).toBeGreaterThan(0);
    for (const index of gapIndices) {
      expect(records[index]!.outcome).toBe('failure');
      expect(records[index]!.action_detail['event']).toBe('coverage_gap');
    }
  });

  it('carries the DEPOSE event id so a reader can get back to the bundle', () => {
    const bundle = bundles.get(example)!;
    records.forEach((record, index) => {
      expect(record.action_detail['depose_event_id']).toBe(bundle.events[index]!.id);
    });
  });
});

describe.each(EXPORT_EXAMPLES)('ASQAV receipts for %s', (example) => {
  let receipts: AsqavReceipt[];
  beforeAll(() => {
    receipts = asqavReceipts(bundles.get(example)!, EXPORT_TEST_KEY);
  });

  it('emits at least one receipt and only for actions', () => {
    expect(receipts.length).toBeGreaterThan(0);
    for (const receipt of receipts) {
      expect(receipt.payload.type).toBe('protectmcp:decision');
    }
  });

  it('has the three required envelope members', () => {
    for (const receipt of receipts) {
      expect(receipt.payload).toBeDefined();
      expect(receipt.signature).toBeDefined();
      expect(Array.isArray(receipt.anchors)).toBe(true);
    }
  });

  it('fills every field the profile makes REQUIRED', () => {
    for (const { payload } of receipts) {
      expect(payload.issued_at).toMatch(/Z$/);
      expect(payload.issuer_id.startsWith('key:z')).toBe(true);
      expect(payload.payload_digest.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(payload.payload_digest.size).toBeGreaterThan(0);
      expect(payload.action_ref).toMatch(/^[0-9a-f]{64}$/);
      expect(payload.iteration_id.length).toBeGreaterThan(0);
      expect(payload.previousReceiptHash).toMatch(/^[0-9a-f]{64}$/);
      expect(payload.policy_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(payload.tool_name.length).toBeGreaterThan(0);
    }
  });

  it('records observation, because DEPOSE never gated anything', () => {
    for (const { payload } of receipts) {
      expect(payload.decision).toBe('observation');
      // reason is REQUIRED only for deny and rate_limit, and asserting one
      // here would claim an enforcement outcome that did not happen.
      expect('reason' in payload).toBe(false);
    }
  });

  it('chains each payload to its predecessor, starting from the genesis value', () => {
    expect(receipts[0]!.payload.previousReceiptHash).toBe(GENESIS_PREVIOUS_HASH);
    for (let i = 1; i < receipts.length; i++) {
      expect(receipts[i]!.payload.previousReceiptHash).toBe(sha256String(canonicalJson(receipts[i - 1]!.payload)));
    }
  });

  it('signs the canonical payload with the key that sealed the bundle', () => {
    const publicKey = createPublicKey(EXPORT_TEST_KEY.publicKeyPem);
    for (const receipt of receipts) {
      expect(receipt.signature.alg).toBe('EdDSA');
      expect(receipt.signature.kid).toBe(receipt.payload.issuer_id);
      const ok = verify(
        null,
        Buffer.from(canonicalJson(receipt.payload), 'utf-8'),
        publicKey,
        Buffer.from(receipt.signature.sig, 'base64')
      );
      expect(ok).toBe(true);
    }
  });

  it('a rewritten payload no longer verifies', () => {
    const receipt = receipts[0]!;
    const tampered = { ...receipt.payload, tool_name: 'something-else' };
    const ok = verify(
      null,
      Buffer.from(canonicalJson(tampered), 'utf-8'),
      createPublicKey(EXPORT_TEST_KEY.publicKeyPem),
      Buffer.from(receipt.signature.sig, 'base64')
    );
    expect(ok).toBe(false);
  });

  it('carries the RFC 3161 token out of band of anchors, with anchors left empty', () => {
    for (const receipt of receipts) {
      // The bundle's token commits to the manifest, not to this envelope,
      // so it cannot be presented as an anchor over this envelope.
      expect(receipt.anchors).toEqual([]);
      expect(receipt.payload.rfc3161_timestamp).toBe(
        bundles.get(example)!.manifest.timestamps[0]!.tokenBase64
      );
    }
  });

  it('reports a coverage gap through unsigned_gap', () => {
    const gaps = receipts.filter((r) => r.payload.tool_name.startsWith('depose:gap:'));
    expect(gaps.length).toBeGreaterThan(0);
    for (const gap of gaps) {
      expect(gap.payload.unsigned_gap?.count).toBe(1);
    }
  });
});
