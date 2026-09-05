// packages/core/src/events/event-io.ts
//
// Wire form of an Event. monoNs is a bigint in memory (a monotonic
// nanosecond clock passes 2^53 after 104 days of uptime, and JSON
// numbers past that silently lose precision) and a decimal string on
// the wire, so the TypeScript producer and the Go verifier see the same
// digits. Everything that writes or reads an events.jsonl line goes
// through this module. See docs/bundle-format.md#event-schema.

import type { Event, EventBase } from './schema.js';

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * JSON.stringify replacer that writes bigint values as decimal strings.
 *
 * @param _key - Property name (unused).
 * @param value - Property value.
 * @returns The value, with bigints converted to strings.
 */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

/**
 * Serialize one event to its events.jsonl line (no trailing newline).
 *
 * @param event - The event.
 * @returns Compact JSON with monoNs as a decimal string.
 */
export function serializeEvent(event: Event): string {
  return JSON.stringify(event, bigintReplacer);
}

/**
 * Parse an events.jsonl line back into an Event.
 *
 * monoNs must be a decimal string (schema 3) or a safe integer (schema 2
 * bundles); anything else is rejected rather than coerced.
 *
 * @param line - One JSON object.
 * @returns The event with monoNs as a bigint.
 * @throws Error when the line is not JSON, or monoNs is malformed.
 */
export function parseEventLine(line: string): Event {
  const raw = JSON.parse(line) as Record<string, unknown>;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('event line is not a JSON object; each events.jsonl line must be one Event');
  }
  return { ...raw, monoNs: parseMonoNs(raw.monoNs, String(raw.id ?? '?')) } as Event;
}

/**
 * Convert a wire-form monoNs to a bigint.
 *
 * @param value - A decimal string, or a safe non-negative integer from a v2 file.
 * @param eventId - For the error message.
 * @returns The value as a bigint.
 * @throws Error when the value is not a non-negative integer in either form.
 */
export function parseMonoNs(value: unknown, eventId: string): bigint {
  if (typeof value === 'string' && DECIMAL.test(value)) {
    return BigInt(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  throw new Error(
    `event ${eventId} has monoNs ${JSON.stringify(value)}; it must be a non-negative decimal integer string`
  );
}

/**
 * Sort comparator by (wallTs, monoNs), the timeline order.
 *
 * @param a - First event.
 * @param b - Second event.
 * @returns Negative, zero, or positive.
 */
export function compareByTime(a: EventBase, b: EventBase): number {
  const tsCmp = a.wallTs.localeCompare(b.wallTs);
  if (tsCmp !== 0) return tsCmp;
  return a.monoNs < b.monoNs ? -1 : a.monoNs > b.monoNs ? 1 : 0;
}
