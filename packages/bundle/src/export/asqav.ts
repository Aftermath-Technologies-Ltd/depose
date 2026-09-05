// packages/bundle/src/export/asqav.ts
//
// Export to draft-marques-asqav-compliance-receipts, a compliance profile
// of the signed action receipt format for AI agents.
//
// One receipt per tool call. Each is an envelope of
// {payload, signature, anchors}: the payload is canonicalized with JCS
// (RFC 8785), signed with the bundle's Ed25519 key, and chained through
// previousReceiptHash = hex(SHA-256(JCS(predecessor.payload))).
//
// Two mappings need saying out loud, and both are in
// docs/export-mapping.md:
//
//   decision: "observation". DEPOSE observes and never gates. The
//   profile's decision vocabulary has a value for exactly that, and
//   emitting "allow" would claim an enforcement decision nobody made.
//
//   The RFC 3161 token goes in rfc3161_timestamp, not in anchors. An
//   anchor's scope is SHA-256(JCS({payload, signature})); the DEPOSE
//   token commits to the bundle manifest instead. Putting it in anchors
//   would be a false claim about what the TSA saw, so anchors is emitted
//   empty and the mapping doc says a conforming anchor needs a re-anchor
//   this exporter deliberately does not perform.

import { canonicalJson, sha256String, type Event } from '@depose/core';
import { bareDidKeyFromEd25519Pem } from '@depose/chain';
import { sign, createPrivateKey } from 'node:crypto';
import type { LoadedBundle } from './read-bundle.js';
import { receiptPayload, type AsqavPayload } from './asqav-map.js';
import type { Ed25519KeyPair } from '@depose/chain';

/** The signature member of a receipt envelope. */
export interface AsqavSignature {
  alg: 'EdDSA';
  kid: string;
  sig: string;
}

/** One receipt envelope. */
export interface AsqavReceipt {
  payload: AsqavPayload;
  signature: AsqavSignature;
  anchors: Array<{ type: string; value: string; status?: string }>;
}

/** The genesis value for previousReceiptHash: no predecessor exists. */
export const GENESIS_PREVIOUS_HASH = '0'.repeat(64);

/**
 * Convert a sealed bundle to a stream of ASQAV compliance receipts.
 *
 * Pure given the same bundle and key: Ed25519 signatures are
 * deterministic, so the bytes are stable.
 *
 * @param bundle - The loaded bundle.
 * @param keyPair - The key that sealed the bundle, used to sign each receipt.
 * @returns JSON Lines, one receipt envelope per line.
 */
export function exportAsqavReceipts(bundle: LoadedBundle, keyPair: Ed25519KeyPair): string {
  return asqavReceipts(bundle, keyPair).map((receipt) => JSON.stringify(receipt)).join('\n') + '\n';
}

/**
 * The receipt envelopes for a bundle, before serialization.
 *
 * @param bundle - The loaded bundle.
 * @param keyPair - The key that sealed the bundle.
 * @returns One receipt per receiptable event, chained in order.
 */
export function asqavReceipts(bundle: LoadedBundle, keyPair: Ed25519KeyPair): AsqavReceipt[] {
  const issuerId = bareDidKeyFromEd25519Pem(keyPair.publicKeyPem);
  const policyDigest = `sha256:${sha256String(bundle.rulesetBytes?.toString('utf-8') ?? '')}`;
  const anchorToken = bundle.manifest.timestamps?.[0]?.tokenBase64;

  const receipts: AsqavReceipt[] = [];
  let previous = GENESIS_PREVIOUS_HASH;
  for (const event of bundle.events) {
    if (!isReceiptable(event)) continue;
    const payload = receiptPayload(event, {
      issuerId,
      policyDigest,
      previousReceiptHash: previous,
      iterationId: bundle.manifest.session.sessionId,
      rfc3161Timestamp: anchorToken,
    });
    receipts.push({ payload, signature: signPayload(payload, issuerId, keyPair), anchors: [] });
    previous = sha256String(canonicalJson(payload));
  }
  return receipts;
}

/**
 * Whether an event produces a receipt.
 *
 * A receipt records an action an agent took, so conversation turns and
 * bookkeeping events are not receiptable. Gaps are: a compliance reader
 * needs to see the holes, and the profile carries them in `unsigned_gap`.
 *
 * @param event - The event to test.
 * @returns True when the event becomes a receipt.
 */
export function isReceiptable(event: Event): boolean {
  switch (event.type) {
    case 'tool_call_intent':
    case 'tool_call_executed':
    case 'tool_call_effect':
    case 'shell_command_pre':
    case 'process_spawn':
    case 'gap':
      return true;
    default:
      return false;
  }
}

function signPayload(payload: AsqavPayload, issuerId: string, keyPair: Ed25519KeyPair): AsqavSignature {
  const bytes = Buffer.from(canonicalJson(payload), 'utf-8');
  const signature = sign(null, bytes, createPrivateKey(keyPair.privateKeyPem));
  return { alg: 'EdDSA', kid: issuerId, sig: signature.toString('base64') };
}
