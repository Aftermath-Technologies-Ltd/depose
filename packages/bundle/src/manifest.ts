// packages/bundle/src/manifest.ts
//
// Manifest schema and builder for .depo bundles.
//
// The manifest is the entrypoint of a .depo bundle. It contains:
//   - Bundle metadata (schema version, ID, producer info, session info)
//   - Integrity data (rootHash, files map, signatures, timestamps)
//   - Counts (events, destructive ops, gaps, artifacts)
//   - Ruleset hash (for reproducibility)
//
// See docs/bundle-format.md#manifest-schema for the normative schema.

import type { Event } from '@depose/core';
import { buildDestructiveOpsIndex, type DestructiveRule } from '@depose/core';
import { platform, arch, release } from 'node:os';
import type { FilesMap } from './files-map.js';

// ── Manifest types ───────────────────────────────────────────────────

/** Schema version this producer writes. */
export const MANIFEST_SCHEMA_VERSION = 3;

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
   *
   * Version 3 adds the signed `files` map covering every file in the
   * bundle tree. Version 2 added `producer.host.nodeVersion`, a proper
   * `producer.host.kernel`, and `session.host`. The verifier accepts
   * [2, 3]; a v2 bundle has no files map and the verifier reports that
   * as a downgrade rather than a failure.
   */
  schemaVersion: 3;
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
     * Session host metadata, the environment where the agent session actually
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
   * RFC 6962 Merkle tree head over the per-event chain hashes (lowercase
   * hex), or '' when no chain was built. Signed and timestamped alongside
   * rootHash; disclosure proofs verify against it. See
   * docs/bundle-format.md#merkle-tree.
   */
  merkleRoot: string;
  /**
   * SHA-256 (lowercase hex) of the literal UTF-8 bytes of events.jsonl
   * as embedded in this bundle. The verifier re-reads events.jsonl
   * and compares, adding events, removing events, re-ordering lines,
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
  /**
   * Every file in the bundle tree except manifest.json,
   * attestations/signatures.json, and attestations/rfc3161-timestamps/*,
   * keyed by relative path. Signed. See docs/bundle-format.md#files-map.
   */
  files: FilesMap;
  signatures: SignatureBlock[];
  timestamps: Rfc3161Token[];
  /**
   * Whether the seal is anchored to a timestamp authority.
   *
   *   anchored  at least one RFC 3161 token covers this manifest
   *   pending   no TSA could be reached at seal time; the bundle is
   *             signed and undated, and `depose anchor` can add the
   *             token later
   *
   * Outside the signed form, alongside `signatures` and `timestamps`,
   * for the same reason: its value is only known after the manifest has
   * been signed, and `depose anchor` updates it without invalidating the
   * seal. It is a label, not evidence. The verifier derives the real
   * state from `timestamps` and from attestations/anchor.json, both of
   * which authenticate themselves, and reports a manifest whose label
   * disagrees with them.
   * See docs/bundle-format.md#anchoring.
   */
  anchorStatus?: 'anchored' | 'pending';
  rekor?: RekorEntry[];
  counts: {
    events: number;
    destructiveOperations: number;
    gaps: number;
    artifactsPre: number;
    artifactsPost: number;
    /**
     * Capture records merged into this bundle, and records present in the
     * producer's capture store that were not attributable to this session
     * and were therefore left out.
     *
     * Both live in signed material on purpose. "We held capture data and
     * deliberately did not use it" is a claim a recipient must be able to
     * check against the signature, not one that sits only in the narrative
     * (which is excluded from the root hash).
     *
     * Optional: bundles produced before these fields existed omit them,
     * and the Go verifier decodes a missing value as zero.
     */
    capturesAttributed?: number;
    capturesExcluded?: number;
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
 * Signatures and timestamps start empty; the writer fills them after
 * the files map is final.
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
    merkleRoot: string;
    eventsJsonlSha256: string;
    files?: FilesMap;
    keyFingerprint?: string;
    capturesAttributed?: number;
    capturesExcluded?: number;
  }
): Manifest {
  const destructiveOps = buildDestructiveOpsIndex(events, rules);
  const gaps = events.filter((e) => e.type === 'gap');
  const fileChanges = events.filter((e) => e.type === 'file_diff');

  return {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
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
    merkleRoot: options.merkleRoot,
    eventsJsonlSha256: options.eventsJsonlSha256,
    files: options.files ?? {},
    signatures: [],
    timestamps: [],
    counts: {
      events: events.length,
      destructiveOperations: destructiveOps.length,
      gaps: gaps.length,
      artifactsPre: fileChanges.length,
      artifactsPost: fileChanges.length,
      capturesAttributed: options.capturesAttributed ?? 0,
      capturesExcluded: options.capturesExcluded ?? 0,
    },
    rulesetHash: options.rulesetHash,
  };
}
