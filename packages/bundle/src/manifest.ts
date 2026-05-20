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
import { platform, arch, release } from 'node:os';

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
  /**
   * Schema version of the manifest format.
   * Version 2 adds `producer.host.nodeVersion` (replacing the misnamed `kernel`
   * that held the Node.js version), a proper `producer.host.kernel` from
   * `os.release()`, and `session.host` for session-capture environment metadata.
   *
   * **Deprecation note:** v1 manifests (schemaVersion=1) used `producer.host.kernel`
   * to store the Node.js process version (e.g. "v20.19.0") rather than the OS
   * kernel release. Verifiers MUST continue to accept schemaVersion=1; the field
   * should be interpreted as `nodeVersion` when the manifest declares
   * schemaVersion=1.
   */
  schemaVersion: 2;
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
      /** Node.js runtime version (e.g. "v20.19.0") */
      nodeVersion: string;
      /** OS kernel release from os.release() (e.g. "23.4.0") */
      kernel: string;
    };
  };
  session: {
    agentId: string;
    sessionId: string;
    startedAt: string;
    endedAt: string;
    /**
     * Session host metadata — the environment where the agent session actually
     * ran. Fields are nullable because they may be unavailable during
     * reconstruction (e.g. when building from JSONL alone). producer.host
     * always records the bundling machine; session.host records the original
     * capture environment when known.
     */
    host: {
      os: string | null;
      arch: string | null;
      nodeVersion: string | null;
      kernel: string | null;
    } | null;
  };
  rootHash: string;
  /**
   * SHA-256 (lowercase hex) of the literal UTF-8 bytes of events.jsonl
   * as embedded in this bundle. The verifier re-reads events.jsonl
   * and compares — adding events, removing events, re-ordering lines,
   * or any whitespace-level change inside the file fails verification
   * even when the chain-replay path would otherwise survive.
   *
   * Belt-and-suspenders for the IRONROOT chain: the chain authenticates
   * per-event content via payloadHash + metadata, but cannot detect
   * line-level reordering of events that already have a self-consistent
   * chain (e.g. a parallel chain forged with the producer's key). This
   * hash pins the exact bytes the verifier must see.
   *
   * Empty string is allowed for dev-unsigned bundles produced before
   * this field existed; the verifier accepts empty in dev-unsigned mode
   * but requires a non-empty value in signed mode.
   */
  eventsJsonlSha256: string;
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
    eventsJsonlSha256: string;
    keyFingerprint?: string;
  }
): Manifest {
  const destructiveOps = buildDestructiveOpsIndex(events, rules);
  const gaps = events.filter((e) => e.type === 'gap');
  const fileChanges = events.filter((e) => e.type === 'file_diff');

  return {
    schemaVersion: 2 as const,
    bundleId: options.bundleId,
    producedAt: options.producedAt,
    producer: {
      tool: 'depose',
      version: options.version,
      mode: options.mode,
      ...(options.keyFingerprint ? { keyFingerprint: options.keyFingerprint } : {}),
      host: {
        os: platform(),
        arch: arch(),
        nodeVersion: process.version,
        kernel: release(),
      },
    },
    session: {
      agentId: options.agentId,
      sessionId: options.sessionId,
      startedAt: options.sessionStartedAt,
      endedAt: options.sessionEndedAt,
      host: null,
    },
    rootHash: options.rootHash,
    eventsJsonlSha256: options.eventsJsonlSha256,
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
