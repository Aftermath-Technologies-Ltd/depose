// packages/bundle/src/writer-seal.ts
//
// The sealing computation: commit disclosable fields, build the linear
// chain, build the Merkle tree over the chain hashes, and produce the
// exact events.jsonl bytes. Pure over its inputs; the writer puts the
// results on disk.

import type { Event } from '@depose/core';
import { commitEvents, generateSalt, serializeEvent, sha256Bytes, type CommitmentOpening } from '@depose/core';
import { buildHashChain, leafHash, merkleRoot, type Ed25519KeyPair } from '@depose/chain';

export interface SealOptions {
  /** Present when a chain is to be built (always in signed mode). */
  keyPair?: Ed25519KeyPair;
  /** Replace disclosable fields with salted commitments. */
  commitFields: boolean;
  /** Ruleset `disclosable` entries. */
  disclosable: string[];
}

export interface SealResult {
  /** Events as written to events.jsonl: committed, chained, in id order. */
  sealedEvents: Event[];
  /** Terminal chain hash, '' when no chain was built. */
  rootHash: string;
  /** RFC 6962 tree head over the chain hashes, '' when no chain was built. */
  merkleRoot: string;
  /** The literal bytes of events.jsonl. */
  eventsJsonlBytes: Buffer;
  /** SHA-256 of eventsJsonlBytes. */
  eventsJsonlSha256: string;
  /** Openings for every committed field, in event then path order. */
  openings: CommitmentOpening[];
}

/**
 * Seal a sorted event list.
 *
 * @param sortedEvents - Plaintext events in ascending id order.
 * @param options - Key, commitment mode, disclosable fields.
 * @returns The sealed events and everything the manifest pins about them.
 */
export function sealEvents(sortedEvents: Event[], options: SealOptions): SealResult {
  const committed = options.commitFields
    ? commitEvents(sortedEvents, options.disclosable, generateSalt)
    : { events: sortedEvents, openings: [] };

  let rootHash = '';
  let merkle = '';
  let sealedEvents = committed.events;
  if (options.keyPair) {
    const chain = buildHashChain(committed.events);
    sealedEvents = chain.chainedEvents;
    rootHash = chain.rootHash;
    merkle = merkleRoot(sealedEvents.map((e) => leafHash(Buffer.from(e.chainHash!, 'hex')))).toString('hex');
  }

  const eventsJsonlBytes = Buffer.from(
    sealedEvents.map((e) => serializeEvent(e)).join('\n') + '\n',
    'utf-8'
  );
  return {
    sealedEvents,
    rootHash,
    merkleRoot: merkle,
    eventsJsonlBytes,
    eventsJsonlSha256: sha256Bytes(eventsJsonlBytes),
    openings: committed.openings,
  };
}
