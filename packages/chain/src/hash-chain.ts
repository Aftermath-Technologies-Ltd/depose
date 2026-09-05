// packages/chain/src/hash-chain.ts
//
// IRONROOT-style hash chain for DEPOSE evidence integrity.
//
// Chain construction (docs/bundle-format.md#hash-chain):
//
//   chainHash[0]   = SHA-256( zero32 || payloadHash[0] || eventMetadata[0] )
//   chainHash[i]   = SHA-256( chainHash[i-1] || payloadHash[i] || eventMetadata[i] )
//   rootHash       = chainHash[N-1]
//
// eventMetadata is canonical-JSON of:
//   { id, wallTs, monoNs, sessionId, agentId, parentEventId, type, payloadHash }
//
// Note: payloadHash is included both as standalone input and inside metadata.
// That is intentional and matches IRONROOT, do not "deduplicate" it.

import { createHash } from 'node:crypto';
import { canonicalJson, type Event, type EventBase } from '@depose/core';

// ── Constants ─────────────────────────────────────────────────────────

/** 32 zero bytes used as the chain's initialization vector */
const ZERO_32 = Buffer.alloc(32, 0);

// ── Event metadata ────────────────────────────────────────────────────

/**
 * Extract the metadata fields used in chain hash computation.
 * Per docs/bundle-format.md#hash-chain: { id, wallTs, monoNs, sessionId, agentId,
 * parentEventId, type, payloadHash }.
 * payloadHash is intentionally included in both standalone and metadata inputs.
 */
export function extractEventMetadata(event: EventBase): Record<string, unknown> {
  return {
    id: event.id,
    wallTs: event.wallTs,
    monoNs: event.monoNs,
    sessionId: event.sessionId,
    agentId: event.agentId,
    parentEventId: event.parentEventId,
    type: event.type,
    payloadHash: event.payloadHash,
  };
}

// ── Chain computation ─────────────────────────────────────────────────

/**
 * The chain is defined over events in ascending id order and the
 * verifier replays the file in the order written, so an unsorted input
 * would seal a chain the verifier can never reproduce. Fail here instead.
 */
function assertSortedById(events: Event[]): void {
  for (let i = 1; i < events.length; i++) {
    if (events[i]!.id < events[i - 1]!.id) {
      throw new Error(
        `events are not sorted by id at index ${i} (${events[i]!.id} follows ${events[i - 1]!.id}); ` +
        `sort by id before building the chain`
      );
    }
  }
}

/**
 * Compute a single chain hash for event at index i, given the previous
 * chain hash (or zero32 for i=0).
 *
 * chainHash[i] = SHA-256( chainHash[i-1] || payloadHash[i] || eventMetadata[i] )
 */
export function computeChainHash(
  prevChainHash: Buffer,
  payloadHash: string,
  eventMetadata: Record<string, unknown>
): Buffer {
  const metadataCanonical = canonicalJson(eventMetadata);
  const hash = createHash('sha256');
  hash.update(prevChainHash);
  // payloadHash is a hex string; we use it as UTF-8 bytes (not decoded from hex)
  // to maintain determinism independent of hex-decode ambiguity
  hash.update(payloadHash, 'utf-8');
  hash.update(metadataCanonical, 'utf-8');
  return hash.digest();
}

/**
 * Build the full hash chain over a sorted list of events.
 *
 * Events MUST be sorted by id (ULID) before calling this function.
 * Returns a new array of events with chainHash populated, plus the rootHash.
 *
 * @param events - Events sorted by id (ULID time-sort)
 * @returns Chained events and root hash
 * @throws Error when the events are not in ascending id order
 */
export function buildHashChain(events: Event[]): {
  chainedEvents: Event[];
  rootHash: string;
} {
  if (events.length === 0) {
    return { chainedEvents: [], rootHash: '' };
  }
  assertSortedById(events);

  const chainedEvents: Event[] = [];
  let prevHash: Buffer = ZERO_32;

  for (const event of events) {
    const metadata = extractEventMetadata(event);
    const chainHashBuf = computeChainHash(prevHash, event.payloadHash, metadata);
    const chainHashHex = chainHashBuf.toString('hex');

    chainedEvents.push({
      ...event,
      chainHash: chainHashHex,
    });

    prevHash = chainHashBuf;
  }

  const rootHash = prevHash.toString('hex');
  return { chainedEvents, rootHash };
}

/**
 * Verify a hash chain over a list of events.
 * Returns true if the chain is valid and the computed rootHash matches
 * the expected rootHash.
 *
 * @param events - Events with chainHash already populated, sorted by id
 * @param expectedRootHash - The expected terminal chain hash
 * @returns Verification result with check details
 */
export function verifyHashChain(
  events: Event[],
  expectedRootHash: string
): {
  valid: boolean;
  computedRootHash: string;
  failedAtIndex: number | null;
  failureDetail: string | null;
} {
  if (events.length === 0) {
    return {
      valid: expectedRootHash === '',
      computedRootHash: '',
      failedAtIndex: null,
      failureDetail: expectedRootHash !== '' ? 'expected rootHash on empty chain' : null,
    };
  }

  let prevHash: Buffer = ZERO_32;

  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    const metadata = extractEventMetadata(event);
    const computedHash = computeChainHash(prevHash, event.payloadHash, metadata);
    const computedHex = computedHash.toString('hex');

    if (computedHex !== event.chainHash) {
      return {
        valid: false,
        computedRootHash: '',
        failedAtIndex: i,
        failureDetail: `chain hash mismatch at event[${i}] (id=${event.id}): expected ${event.chainHash}, computed ${computedHex}`,
      };
    }

    prevHash = computedHash;
  }

  const computedRootHash = prevHash.toString('hex');
  const valid = computedRootHash === expectedRootHash;

  return {
    valid,
    computedRootHash,
    failedAtIndex: null,
    failureDetail: valid ? null : `rootHash mismatch: expected ${expectedRootHash}, computed ${computedRootHash}`,
  };
}