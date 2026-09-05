// packages/core/src/events/commitments.ts
//
// Salted field commitments, SD-JWT style. A disclosable payload field is
// replaced in the sealed event by
//
//   { "$commitment": sha256( jcs( [salt, path, value] ) ) }
//
// and the (salt, path, value) opening is kept in commitments.json next
// to events.jsonl. The chain, the Merkle tree, and the signature cover
// the committed form, so a later disclosure can reveal some fields and
// withhold others without touching the seal: a withheld field's
// commitment reveals nothing (32 random bytes of salt), and a revealed
// field verifies against the sealed event by recomputing the hash.
//
// Only top-level payload fields are committable. The path is a JSON
// pointer into the payload ("/toolInput"). Spec:
// docs/bundle-format.md#field-commitments.

import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical-json.js';
import type { Event } from './schema.js';

/** Key of the placeholder object that stands in for a committed value. */
export const COMMITMENT_KEY = '$commitment';

/** How a commitment is computed; recorded in commitments.json for readers. */
export const COMMITMENT_ALGORITHM = 'sha256(jcs([salt, path, value]))';

/** One field's opening: enough to recompute and check its commitment. */
export interface CommitmentOpening {
  eventId: string;
  /** JSON pointer into the payload, e.g. "/toolInput". */
  path: string;
  /** 32 random bytes, lowercase hex. */
  salt: string;
  value: unknown;
}

/** Shape of commitments.json. */
export interface CommitmentsFile {
  schemaVersion: 1;
  algorithm: typeof COMMITMENT_ALGORITHM;
  openings: CommitmentOpening[];
}

/** Placeholder left in the payload where a committed value was. */
export interface CommitmentPlaceholder {
  [COMMITMENT_KEY]: string;
}

/**
 * Compute a field commitment.
 *
 * @param salt - Lowercase hex salt.
 * @param path - JSON pointer into the payload.
 * @param value - The original value.
 * @returns Lowercase hex SHA-256 over the JCS form of [salt, path, value].
 */
export function computeCommitment(salt: string, path: string, value: unknown): string {
  return createHash('sha256').update(canonicalJson([salt, path, value]), 'utf-8').digest('hex');
}

/**
 * Whether a value is a commitment placeholder.
 *
 * @param value - Any payload value.
 * @returns True for an object whose only key is `$commitment` holding a 64-hex string.
 */
export function isCommitmentPlaceholder(value: unknown): value is CommitmentPlaceholder {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  const hash = (value as Record<string, unknown>)[COMMITMENT_KEY];
  return keys.length === 1 && typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash);
}

/**
 * Parse a disclosable spec entry `<eventType>.<payloadField>`.
 *
 * @param spec - One entry from the ruleset's `disclosable` list.
 * @returns The event type and the field's JSON pointer.
 * @throws Error when the entry is malformed or names a field that is never disclosable.
 */
export function parseDisclosableSpec(spec: string): { eventType: string; path: string } {
  const dot = spec.indexOf('.');
  if (dot <= 0 || dot === spec.length - 1 || spec.indexOf('.', dot + 1) !== -1) {
    throw new Error(
      `disclosable entry "${spec}" must be <eventType>.<payloadField> naming one top-level payload field`
    );
  }
  const field = spec.slice(dot + 1);
  if (field === 'toolName' || field === 'kind' || field === 'reason') {
    throw new Error(`disclosable entry "${spec}": ${field} identifies what happened and is never committed`);
  }
  return { eventType: spec.slice(0, dot), path: `/${field}` };
}

/**
 * Replace every disclosable field of one event with its commitment.
 *
 * @param event - A plaintext event.
 * @param disclosable - Ruleset `disclosable` entries.
 * @param salt - Salt generator (32 random bytes as hex).
 * @returns The committed event (payloadHash recomputed) and its openings.
 */
export function commitEventFields(
  event: Event,
  disclosable: string[],
  salt: () => string
): { event: Event; openings: CommitmentOpening[] } {
  const openings: CommitmentOpening[] = [];
  const payload = event.payload as unknown as Record<string, unknown> | null;
  if (typeof payload !== 'object' || payload === null) return { event, openings };

  const committed: Record<string, unknown> = { ...payload };
  for (const spec of disclosable) {
    const { eventType, path } = parseDisclosableSpec(spec);
    if (eventType !== event.type) continue;
    const field = path.slice(1);
    if (!(field in committed) || committed[field] === undefined) continue;
    if (isCommitmentPlaceholder(committed[field])) continue;
    const value = committed[field];
    const fieldSalt = salt();
    committed[field] = { [COMMITMENT_KEY]: computeCommitment(fieldSalt, path, value) };
    openings.push({ eventId: event.id, path, salt: fieldSalt, value });
  }
  if (openings.length === 0) return { event, openings };

  const payloadHash = createHash('sha256').update(canonicalJson(committed), 'utf-8').digest('hex');
  return { event: { ...event, payload: committed, payloadHash } as Event, openings };
}

/**
 * Commit the disclosable fields of every event.
 *
 * @param events - Plaintext events in their final order.
 * @param disclosable - Ruleset `disclosable` entries.
 * @param salt - Salt generator.
 * @returns Committed events in the same order, and all openings.
 */
export function commitEvents(
  events: Event[],
  disclosable: string[],
  salt: () => string
): { events: Event[]; openings: CommitmentOpening[] } {
  const out: Event[] = [];
  const openings: CommitmentOpening[] = [];
  for (const event of events) {
    const committed = commitEventFields(event, disclosable, salt);
    out.push(committed.event);
    openings.push(...committed.openings);
  }
  return { events: out, openings };
}

/**
 * Check one opening against the placeholder in a committed payload.
 *
 * @param payload - The sealed event's payload.
 * @param opening - The claimed opening.
 * @returns True when the payload holds a placeholder at the path whose hash matches.
 */
export function openCommitment(payload: unknown, opening: CommitmentOpening): boolean {
  if (typeof payload !== 'object' || payload === null) return false;
  const field = opening.path.startsWith('/') ? opening.path.slice(1) : '';
  if (field === '' || field.includes('/')) return false;
  const placeholder = (payload as Record<string, unknown>)[field];
  if (!isCommitmentPlaceholder(placeholder)) return false;
  return placeholder[COMMITMENT_KEY] === computeCommitment(opening.salt, opening.path, opening.value);
}

/**
 * Put revealed values back into a committed event for display.
 *
 * @param event - A sealed event with placeholders.
 * @param openings - Openings for this event (others are ignored).
 * @returns The event with every opened placeholder replaced by its value.
 *          payloadHash is left as sealed; the result is for reading, not hashing.
 */
export function restoreEvent(event: Event, openings: CommitmentOpening[]): Event {
  const payload = event.payload as unknown as Record<string, unknown> | null;
  if (typeof payload !== 'object' || payload === null) return event;
  const restored: Record<string, unknown> = { ...payload };
  for (const opening of openings) {
    if (opening.eventId !== event.id) continue;
    if (!openCommitment(payload, opening)) continue;
    restored[opening.path.slice(1)] = opening.value;
  }
  return { ...event, payload: restored } as Event;
}
