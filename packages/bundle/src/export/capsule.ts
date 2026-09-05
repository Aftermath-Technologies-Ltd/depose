// packages/bundle/src/export/capsule.ts
//
// Export to a SCITT Signed Statement (draft-ietf-scitt-architecture)
// carrying an Agent Action Capsule (draft-mih-scitt-agent-action-capsule),
// ready to register with a transparency service.
//
// The capsule is the whole bundle as one action: the agent ran a session,
// the session had an effect, and the effect is bound by the signed Merkle
// root and chain head rather than by a promise. Per-event capsules would
// duplicate the AAT export without adding a registrable claim.
//
// Two profile conflicts are resolved here and stated in
// docs/export-mapping.md:
//
//   The capsule draft's own Producer Envelope is a COSE_Sign1 with
//   exactly three protected entries (alg, content_type, kid), an
//   empty unprotected map, and the raw capsule-id as payload. That is not
//   a conforming SCITT Signed Statement, which REQUIRES CWT_Claims in the
//   protected header. Registration with a transparency service is the
//   stated purpose, so DEPOSE emits the SCITT-conforming form: CWT_Claims
//   with iss and sub, content_type application/agent-action-capsule+json,
//   and the capsule JSON as the attached payload.
//
//   A dev-unsigned bundle is refused. Signing a statement over evidence
//   that carries no signature of its own would put a producer's name on
//   an unsigned claim.

import { canonicalJson, sha256String, type Event } from '@depose/core';
import {
  signCoseSign1,
  rawEd25519PublicKey,
  didKeyFromEd25519Pem,
  COSE_HEADER,
  CWT_CLAIM,
  COSE_ALG_EDDSA,
  type CborValue,
  type Ed25519KeyPair,
} from '@depose/chain';
import type { LoadedBundle } from './read-bundle.js';

/** Media type of the capsule payload. */
export const CAPSULE_CONTENT_TYPE = 'application/agent-action-capsule+json';

/** The profile version this exporter targets. */
export const CAPSULE_SPEC_VERSION = 'draft-mih-scitt-agent-action-capsule-04';

/** Serialization suite for the capsule. */
export const CAPSULE_FORMAT_VERSION = '4';

/** One Agent Action Capsule. */
export interface Capsule {
  spec_version: string;
  format_version: string;
  canonicalization_id: 'jcs';
  capsule_id: string;
  action_id: string;
  action_type: 'fyi' | 'decide';
  operator: string;
  developer: string;
  timestamp: string;
  effect: {
    type: string;
    status: 'planned' | 'dispatched' | 'confirmed' | 'failed' | 'reverted';
    irreversibility_class: string;
    response_digest?: string;
    effect_attestation?: string;
  };
  assurance: {
    attestation_mode: 'self_attested' | 'anchored';
    effect_mode: 'not_applicable' | 'dispatched_unconfirmed' | 'confirmed';
    ledger_mode: 'standalone' | 'chained' | 'anchored';
  };
  constraints: Array<{
    id: string;
    result: 'pass' | 'fail' | 'n/a';
    severity: string;
    blocking: boolean;
    evidence_digest?: string;
  }>;
  references: Array<{ type: string; digest: string }>;
}

/**
 * Build the capsule for a bundle, without signing it.
 *
 * @param bundle - The loaded bundle.
 * @returns The capsule, with capsule_id already computed.
 */
export function buildCapsule(bundle: LoadedBundle): Capsule {
  const m = bundle.manifest;
  const anchored = (m.timestamps ?? []).length > 0;
  const destructive = m.counts.destructiveOperations;
  const gaps = m.counts.gaps;

  const capsule: Capsule = {
    spec_version: CAPSULE_SPEC_VERSION,
    format_version: CAPSULE_FORMAT_VERSION,
    canonicalization_id: 'jcs',
    capsule_id: '',
    action_id: m.bundleId,
    // The capsule records what happened, not a decision anyone made:
    // DEPOSE never gates, so there is no disposition to report and
    // action_type "decide" would require one.
    action_type: 'fyi',
    operator: m.session.sessionId,
    developer: `${m.session.agentId}@${m.producer.version}`,
    timestamp: m.producedAt,
    effect: {
      type: destructive > 0 ? 'destructive_operation' : 'agent_session',
      // The bundle records outcomes that were observed, so the effect is
      // confirmed and response_digest is the signed chain head. A bundle
      // with no chain has nothing to confirm against.
      status: m.rootHash === '' ? 'dispatched' : 'confirmed',
      irreversibility_class: destructive > 0 ? 'one_way_consequential' : 'two_way',
      ...(m.rootHash === ''
        ? { effect_attestation: 'runtime_claimed' }
        : { response_digest: `sha256:${m.rootHash}`, effect_attestation: 'gate_executed' }),
    },
    assurance: {
      attestation_mode: anchored ? 'anchored' : 'self_attested',
      effect_mode: m.rootHash === '' ? 'dispatched_unconfirmed' : 'confirmed',
      ledger_mode: anchored ? 'anchored' : 'chained',
    },
    constraints: constraintRecords(bundle, destructive, gaps),
    references: references(bundle),
  };

  capsule.capsule_id = capsuleId(capsule);
  return capsule;
}

/**
 * The capsule id: SHA-256 of JCS over the capsule with capsule_id removed.
 *
 * @param capsule - The capsule, with or without capsule_id populated.
 * @returns 64 lowercase hex characters.
 */
export function capsuleId(capsule: Capsule): string {
  const { capsule_id: _omitted, ...rest } = capsule;
  return sha256String(canonicalJson(rest));
}

/**
 * Wrap a bundle's capsule in a SCITT Signed Statement.
 *
 * @param bundle - The loaded bundle.
 * @param keyPair - The key that sealed the bundle.
 * @returns The tagged COSE_Sign1 bytes.
 * @throws Error when the bundle is dev-unsigned.
 */
export function exportScittStatement(bundle: LoadedBundle, keyPair: Ed25519KeyPair): Uint8Array {
  if (bundle.manifest.producer.mode !== 'signed') {
    throw new Error(
      `${bundle.path} is a ${bundle.manifest.producer.mode} bundle and cannot become a SCITT Signed Statement; ` +
        `a statement puts a signature on a claim about the bundle, and the bundle carries none of its own. ` +
        `Seal it with depose record in signed mode first.`
    );
  }
  const capsule = buildCapsule(bundle);
  const payload = Buffer.from(canonicalJson(capsule), 'utf-8');

  const cwtClaims = new Map<CborValue, CborValue>([
    [CWT_CLAIM.iss, didKeyFromEd25519Pem(keyPair.publicKeyPem)],
    [CWT_CLAIM.sub, `depose:bundle:${bundle.manifest.bundleId}`],
  ]);
  const protectedHeader = new Map<CborValue, CborValue>([
    [COSE_HEADER.alg, COSE_ALG_EDDSA],
    [COSE_HEADER.contentType, CAPSULE_CONTENT_TYPE],
    [COSE_HEADER.kid, rawEd25519PublicKey(keyPair.publicKeyPem)],
    [COSE_HEADER.cwtClaims, cwtClaims],
  ]);

  return signCoseSign1({ protectedHeader, payload: new Uint8Array(payload) }, keyPair);
}

/**
 * The deterministic checks the bundle ran, as Constraint Records.
 *
 * Content is bound by digest only, which is the profile's rule: the
 * ruleset that produced a verdict is referenced, never inlined.
 */
function constraintRecords(bundle: LoadedBundle, destructive: number, gaps: number): Capsule['constraints'] {
  const records: Capsule['constraints'] = [
    {
      id: 'destructive_ruleset',
      result: destructive > 0 ? 'fail' : 'pass',
      severity: destructive > 0 ? 'high' : 'info',
      // DEPOSE observes. A rule firing records a finding; it never gated
      // the command, and saying otherwise would be the one claim in this
      // export a reader could act on wrongly.
      blocking: false,
      evidence_digest: `sha256:${bundle.manifest.rulesetHash}`,
    },
    {
      id: 'coverage_gaps',
      result: gaps > 0 ? 'fail' : 'pass',
      severity: gaps > 0 ? 'medium' : 'info',
      blocking: false,
    },
  ];
  const lost = bundle.events.filter(isLostOutcome).length;
  if (lost > 0) {
    records.push({ id: 'intent_without_effect', result: 'fail', severity: 'high', blocking: false });
  }
  return records;
}

function isLostOutcome(event: Event): boolean {
  return event.type === 'gap' && (event.payload as { reason: string }).reason === 'intent_without_effect';
}

/** Typed digests a holder of the bundle can resolve. */
function references(bundle: LoadedBundle): Capsule['references'] {
  const m = bundle.manifest;
  const refs: Capsule['references'] = [
    { type: 'depose:events_jsonl', digest: `sha256:${m.eventsJsonlSha256}` },
    { type: 'depose:destructive_ruleset', digest: `sha256:${m.rulesetHash}` },
  ];
  if (m.merkleRoot !== '') {
    refs.push({ type: 'depose:merkle_root', digest: `sha256:${m.merkleRoot}` });
  }
  return refs;
}
