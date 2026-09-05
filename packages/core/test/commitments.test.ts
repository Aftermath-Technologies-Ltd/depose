// packages/core/test/commitments.test.ts
//
// Salted field commitments: the committed form is what gets sealed, the
// openings must reproduce it, and a wrong salt or value must not.
// Shared vectors: tests/conformance/commitment-vectors.json (also run by
// the Go verifier).

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  computeCommitment,
  commitEventFields,
  commitEvents,
  openCommitment,
  restoreEvent,
  isCommitmentPlaceholder,
  parseDisclosableSpec,
  parseEventLine,
  sha256,
  DEFAULT_DISCLOSABLE,
  type CommitmentOpening,
  type Event,
} from '../src/index.js';

interface VectorFile {
  vectors: Array<{ name: string; path: string; value: unknown; salt: string; expected: string }>;
  eventVector: {
    plaintextPayload: unknown;
    disclosable: string[];
    salts: string[];
    committedPayload: unknown;
    committedPayloadHash: string;
    openings: CommitmentOpening[];
  };
}

const file = JSON.parse(
  readFileSync(join(__dirname, '../../../tests/conformance/commitment-vectors.json'), 'utf-8')
) as VectorFile;

function intent(command: string): Event {
  return parseEventLine(JSON.stringify({
    id: '01JCONF0000000000000000001', wallTs: '2025-05-18T15:30:05.000Z', monoNs: '1', sessionId: 's',
    agentId: 'claude-code', parentEventId: null, type: 'tool_call_intent',
    payload: { toolName: 'Bash', toolInput: { command }, toolUseId: 'tu_1' }, payloadHash: '0'.repeat(64),
  }));
}

describe('computeCommitment', () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))('%s', (_name, v) => {
    expect(computeCommitment(v.salt, v.path, v.value)).toBe(v.expected);
  });

  it('changes with the salt, the path, and the value', () => {
    const base = computeCommitment('00'.repeat(32), '/a', 'x');
    expect(computeCommitment('01'.repeat(32), '/a', 'x')).not.toBe(base);
    expect(computeCommitment('00'.repeat(32), '/b', 'x')).not.toBe(base);
    expect(computeCommitment('00'.repeat(32), '/a', 'y')).not.toBe(base);
  });
});

describe('commitEventFields', () => {
  it('reproduces the event vector: placeholders, openings, and payloadHash over the committed form', () => {
    const v = file.eventVector;
    let i = 0;
    const { event, openings } = commitEventFields(intent('rm -rf /data/training'), v.disclosable, () => v.salts[i++]!);
    expect(event.payload).toEqual(v.committedPayload);
    expect(event.payloadHash).toBe(v.committedPayloadHash);
    expect(event.payloadHash).toBe(sha256(event.payload));
    expect(openings).toEqual(v.openings);
  });

  it('never commits the tool name and leaves non-disclosable events untouched', () => {
    const { event } = commitEventFields(intent('ls'), [...DEFAULT_DISCLOSABLE], () => '00'.repeat(32));
    expect((event.payload as { toolName: string }).toolName).toBe('Bash');
    expect(isCommitmentPlaceholder((event.payload as { toolInput: unknown }).toolInput)).toBe(true);
    const prompt = parseEventLine(JSON.stringify({ ...intent('x'), monoNs: '1', type: 'prompt', payload: { text: 'hi' } }));
    expect(commitEventFields(prompt, [...DEFAULT_DISCLOSABLE], () => '00'.repeat(32)).openings).toEqual([]);
  });

  it('rejects disclosable entries that would commit identity fields', () => {
    expect(() => parseDisclosableSpec('tool_call_intent.toolName')).toThrow(/never committed/);
    expect(() => parseDisclosableSpec('toolInput')).toThrow(/<eventType>.<payloadField>/);
    expect(() => parseDisclosableSpec('a.b.c')).toThrow(/<eventType>.<payloadField>/);
  });
});

describe('openCommitment and restoreEvent', () => {
  const salts = ['c1'.repeat(32), 'c2'.repeat(32)];
  let i = 0;
  const { events, openings } = commitEvents([intent('terraform destroy')], [...DEFAULT_DISCLOSABLE], () => salts[i++]!);
  const sealed = events[0]!;

  it('opens with the recorded salt and value', () => {
    expect(openCommitment(sealed.payload, openings[0]!)).toBe(true);
  });

  it('rejects a wrong salt, a wrong value, and a wrong path', () => {
    expect(openCommitment(sealed.payload, { ...openings[0]!, salt: 'ff'.repeat(32) })).toBe(false);
    expect(openCommitment(sealed.payload, { ...openings[0]!, value: { command: 'terraform plan' } })).toBe(false);
    expect(openCommitment(sealed.payload, { ...openings[0]!, path: '/toolName' })).toBe(false);
  });

  it('restores the plaintext value for display without touching the sealed hash', () => {
    const restored = restoreEvent(sealed, openings);
    expect((restored.payload as { toolInput: unknown }).toolInput).toEqual({ command: 'terraform destroy' });
    expect(restored.payloadHash).toBe(sealed.payloadHash);
  });
});
