// packages/bundle/src/export/asqav-map.ts
//
// The DEPOSE-to-ASQAV payload mapping. See asqav.ts for the envelope and
// docs/export-mapping.md for the fields that have no home here.

import { canonicalJson, sha256String, type Event } from '@depose/core';

/** A receipt payload, in the shape the profile constrains. */
export interface AsqavPayload {
  type: 'protectmcp:decision';
  issued_at: string;
  issuer_id: string;
  payload_digest: { hash: string; size: number };
  action_ref: string;
  iteration_id: string;
  previousReceiptHash: string;
  decision: 'observation';
  tool_name: string;
  policy_digest: string;
  /**
   * Present only on gap receipts. The profile's field for periods the
   * issuer knows it did not cover.
   */
  unsigned_gap?: { count: number; from: string; to: string };
  /**
   * The bundle's RFC 3161 token. Deliberately not in `anchors`: its scope
   * is the DEPOSE manifest, not this envelope. See asqav.ts.
   */
  rfc3161_timestamp?: string;
}

/** Everything a payload needs beyond the event itself. */
export interface ReceiptContext {
  issuerId: string;
  policyDigest: string;
  previousReceiptHash: string;
  iterationId: string;
  rfc3161Timestamp?: string;
}

/**
 * Build the receipt payload for one event.
 *
 * `payload_digest` and `action_ref` both commit to the DEPOSE event: the
 * digest to the canonical event payload, action_ref to the canonical
 * action (tool name plus the event's own payload hash). A recipient with
 * the bundle can recompute both; a recipient with only the receipt can
 * check the chain and the signature.
 *
 * @param event - The event this receipt records.
 * @param ctx - Issuer, policy digest, chain predecessor, and session.
 * @returns The payload, ready to canonicalize and sign.
 */
export function receiptPayload(event: Event, ctx: ReceiptContext): AsqavPayload {
  const canonical = canonicalJson(event.payload);
  const payload: AsqavPayload = {
    type: 'protectmcp:decision',
    issued_at: event.wallTs,
    issuer_id: ctx.issuerId,
    payload_digest: { hash: `sha256:${event.payloadHash}`, size: Buffer.byteLength(canonical, 'utf-8') },
    action_ref: sha256String(canonicalJson({ tool: toolName(event), payloadHash: event.payloadHash })),
    iteration_id: ctx.iterationId,
    previousReceiptHash: ctx.previousReceiptHash,
    // DEPOSE observes; it does not allow, deny, or rate limit. The
    // profile's vocabulary has a value for exactly that.
    decision: 'observation',
    tool_name: toolName(event),
    policy_digest: ctx.policyDigest,
  };
  if (event.type === 'gap') {
    payload.unsigned_gap = { count: 1, from: event.wallTs, to: event.wallTs };
  }
  if (ctx.rfc3161Timestamp) {
    payload.rfc3161_timestamp = ctx.rfc3161Timestamp;
  }
  return payload;
}

/**
 * The tool a receipt is about.
 *
 * `tool_name` is REQUIRED by the profile, so an event with no tool of its
 * own reports the DEPOSE event type prefixed with `depose:`, which is
 * honest about where the value came from.
 *
 * @param event - The event.
 * @returns The tool name.
 */
export function toolName(event: Event): string {
  switch (event.type) {
    case 'tool_call_intent':
    case 'tool_call_executed':
    case 'tool_call_effect':
      return (event.payload as { toolName: string }).toolName;
    case 'shell_command_pre':
      return (event.payload as { argv: string[] }).argv[0] ?? 'shell';
    case 'process_spawn':
      return (event.payload as { argv: string[]; exe: string }).argv[0] ?? (event.payload as { exe: string }).exe;
    case 'gap':
      return `depose:gap:${(event.payload as { reason: string }).reason}`;
    default:
      return `depose:${event.type}`;
  }
}
