// packages/bundle/src/manifest.ts
//
// Manifest schema and builder for .depo bundles.
//
// The manifest is the entrypoint of a .depo bundle (see BUILD_PLAN.md §4.3
// and §5). It contains:
//   - Bundle metadata (schema version, ID, producer info, session info)
//   - Integrity data (rootHash, signatures, timestamps)
//   - Counts (events, destructive ops, gaps, artifacts)
//   - Ruleset hash (for reproducibility)
//
// See BUILD_PLAN.md §4.3 for the full schema.

import { canonicalJson, sha256String } from '@depose/core';
import type { Event } from '@depose/core';
import { buildDestructiveOpsIndex, type DestructiveRule } from '@depose/core';

// ── Manifest types (verbatim from BUILD_PLAN.md §4.3) ────────────────

/**
 * Bundle production mode.
 *
 * - `signed`: production / evidence. Requires a non-empty rootHash,
 *   at least one Ed25519 signature, and at least one RFC 3161
 *   timestamp. This is the only mode acceptable as evidence.
 * - `dev-unsigned`: developer / pipeline-testing. signatures and
 *   timestamps must be empty. The bundle's directory is named
 *   `incident-unsigned-<id>` and verify.txt + narrative.md carry a
 *   "NOT EVIDENCE" banner.
 *
 * The verifier consumes this field as a declared contract: it
 * enforces the invariants for each mode and refuses to print a plain
 * "PASS" for a `dev-unsigned` bundle.
 */
export type BundleMode = 'signed' | 'dev-unsigned';

export interface Manifest {
  schemaVersion: 1;
  bundleId: string;
  producedAt: string;
  producer: {
    tool: 'depose';
    version: string;
    mode: BundleMode;
    /**
     * SHA-256 of the producer's signing key (SPKI DER), as lowercase
     * hex. Set only when mode === 'signed'. Recipients pin this to
     * an out-of-band-published fingerprint (e.g. a .well-known
     * page, an attorney's printed handshake, a published catalog)
     * and the verifier rejects the bundle when --expected-key-
     * fingerprint disagrees. See docs/key-management.md.
     */
    keyFingerprint?: string;
    host: {
      os: string;
      arch: string;
      kernel: string;
    };
  };
  session: {
    agentId: string;
    sessionId: string;
    startedAt: string;
    endedAt: string;
  };
  rootHash: string;
  signatures: SignatureBlock[];
  timestamps: Rfc3161Token[];
  rekor?: RekorEntry[];
  counts: {
    events: number;
    destructiveOperations: number;
    gaps: number;
    artifactsPre: number;
    artifactsPost: number;
  };
  rulesetHash: string;
}

export interface SignatureBlock {
  scheme: 'ed25519' | 'sigstore-fulcio';
  signature: string;
  publicKey?: string;
  fulcioCert?: string;
  signedFields: 'manifest.json';
}

export interface Rfc3161Token {
  tsa: string;
  timestamp: string;
  tokenBase64: string;
}

export interface RekorEntry {
  uuid: string;
  body: string;
  integratedTime: number;
}

// ── Manifest builder ─────────────────────────────────────────────────

/**
 * Build a manifest from a list of events and destructive rules.
 *
 * This is the Phase 1 (unsigned) manifest builder. Signatures and
 * timestamps are empty (populated in Phase 2).
 *
 * @param events - Sorted list of events
 * @param rules - Destructive ruleset
 * @param options - Manifest options
 */
export function buildManifest(
  events: Event[],
  rules: DestructiveRule[],
  options: {
    bundleId: string;
    producedAt: string;
    version: string;
    mode: BundleMode;
    sessionId: string;
    agentId: string;
    sessionStartedAt: string;
    sessionEndedAt: string;
    rulesetHash: string;
    rootHash: string;
    keyFingerprint?: string;
  }
): Manifest {
  const destructiveOps = buildDestructiveOpsIndex(events, rules);
  const gaps = events.filter((e) => e.type === 'gap');
  const fileChanges = events.filter((e) => e.type === 'file_diff');

  return {
    schemaVersion: 1,
    bundleId: options.bundleId,
    producedAt: options.producedAt,
    producer: {
      tool: 'depose',
      version: options.version,
      mode: options.mode,
      ...(options.keyFingerprint ? { keyFingerprint: options.keyFingerprint } : {}),
      host: {
        os: process.platform,
        arch: process.arch,
        kernel: process.version,
      },
    },
    session: {
      agentId: options.agentId,
      sessionId: options.sessionId,
      startedAt: options.sessionStartedAt,
      endedAt: options.sessionEndedAt,
    },
    rootHash: options.rootHash,
    signatures: [],
    timestamps: [],
    counts: {
      events: events.length,
      destructiveOperations: destructiveOps.length,
      gaps: gaps.length,
      artifactsPre: fileChanges.length,
      artifactsPost: fileChanges.length,
    },
    rulesetHash: options.rulesetHash,
  };
}

/**
 * Serialize a manifest to canonical (deterministic) JSON string.
 */
export function serializeManifest(manifest: Manifest): string {
  return canonicalJson(manifest);
}

/**
 * Serialize a manifest for signing — excludes signatures and timestamps
 * to avoid the self-referential signature problem.
 *
 * The signature is computed over SHA-256(canonical JSON of the manifest
 * with signatures=[] and timestamps=[]). When verifying, the verifier
 * must reconstruct the same unsigned manifest to compute the expected hash.
 */
export function serializeManifestForSigning(manifest: Manifest): string {
  const unsigned: Manifest = {
    ...manifest,
    signatures: [],
    timestamps: [],
  };
  return canonicalJson(unsigned);
}

/**
 * Compute the SHA-256 hash of a manifest's unsigned form (for signing/verifying).
 */
export function hashManifestForSigning(manifest: Manifest): string {
  return sha256String(serializeManifestForSigning(manifest));
}

/**
 * Compute the SHA-256 hash of a manifest (for signing).
 * @deprecated Use hashManifestForSigning for signature verification
 */
export function hashManifest(manifest: Manifest): string {
  return sha256String(serializeManifest(manifest));
}
