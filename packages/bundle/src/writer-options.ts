// packages/bundle/src/writer-options.ts
//
// What writeBundle takes and what it gives back. Separate from the writer
// itself because the option contract is what a caller reads, and it runs
// longer than the code that consumes it.

import type { Event, DestructiveRule } from '@depose/core';
import type { Ed25519KeyPair, Rfc3161Token as ChainRfc3161Token } from '@depose/chain';
import type { TsaEndpoint } from '@depose/chain';
import type { BundleMode, Manifest } from './manifest.js';

export interface BundleWriterOptions {
  /** Session ID (ULID), used as bundle directory name */
  sessionId: string;
  /** Agent ID (e.g., 'claude-code') */
  agentId: string;
  /** Bundle version (semver) */
  version: string;
  /** Production timestamp (ISO 8601 UTC) */
  producedAt: string;
  /** Session start timestamp (ISO 8601 UTC) */
  sessionStartedAt: string;
  /** Session end timestamp (ISO 8601 UTC) */
  sessionEndedAt: string;
  /** Destructive ruleset (for counting destructive ops) */
  rules: DestructiveRule[];
  /** Original ruleset bytes, written verbatim into the bundle and
   *  hashed into manifest.rulesetHash. The verifier re-reads the
   *  embedded file and re-hashes it to enforce ruleset integrity. */
  rulesetBytes: Buffer;
  /** Output directory (where the .depo directory is written) */
  outputDir: string;
  /**
   * Bundle production mode (see BundleMode docstring).
   *
   * `signed`, production. Requires keyPair. Builds chain, signs,
   *   requests RFC 3161 timestamps. The bundle is named
   *   `incident-<id>` and is the only mode acceptable as evidence.
   * `dev-unsigned`, pipeline testing. signatures/timestamps are
   *   empty. The bundle is named `incident-unsigned-<id>` and
   *   verify.txt + narrative carry a "NOT EVIDENCE" banner. The
   *   chain is built only if keyPair is provided (this preserves
   *   roundtrip tests without an active TSA dependency).
   */
  mode: BundleMode;
  /** Ed25519 key pair. Required for `signed`. Optional for
   *  `dev-unsigned` (used only to build the chain; the signature
   *  itself is not emitted). */
  keyPair?: Ed25519KeyPair;
  /** Test-only hatch: pre-baked RFC 3161 tokens to embed instead of
   *  calling a real TSA. Used by signed-mode tests that cannot reach
   *  a live TSA. Never set by CLI commands. */
  injectedTimestamps?: ChainRfc3161Token[];
  /**
   * Timestamp authorities to try, in the order given before shuffling.
   * Defaults to the built-in list. Configured in the ruleset so the
   * choice of witness travels with the rules.
   */
  tsaEndpoints?: TsaEndpoint[];
  /**
   * Fail rather than seal when no authority answers. Off by default: a
   * signature made now with an anchor added later is better evidence
   * than no bundle, and the verifier reports the difference.
   */
  requireAnchor?: boolean;
  /**
   * The agent log grammar this session was reconstructed from, when the
   * agent has more than one. Recorded in the signed manifest.
   */
  sourceFormat?: string;
  /** Path to the original JSONL source file. When provided, the
   *  file is copied into raw/claude-code/<filename>.jsonl in the
   *  bundle, along with any shell-history.txt or git-reflog.txt
   *  sibling. */
  sourceJsonlPath?: string;
  /**
   * Capture-store accounting, recorded in the signed manifest so a
   * recipient can see that capture data existed and how much of it was
   * deliberately left out as unattributable to this session.
   */
  capturesAttributed?: number;
  capturesExcluded?: number;
  /**
   * Capture store the attributed records came from. When set, the records
   * that actually entered this bundle are copied into raw/captures/.
   */
  captureSourceDir?: string;
  /**
   * Replace disclosable payload fields with salted commitments before
   * sealing, keeping the openings in commitments.json. On by default;
   * this is what makes `depose disclose` possible. See
   * docs/bundle-format.md#field-commitments.
   */
  commitFields?: boolean;
  /** Ruleset `disclosable` entries. Defaults to DEFAULT_DISCLOSABLE. */
  disclosable?: string[];
}

// ── Bundle output ────────────────────────────────────────────────────

export interface BundleOutput {
  /** Path to the written .depo directory */
  depopPath: string;
  /** The manifest that was written */
  manifest: Manifest;
  /** Events written to events.jsonl: committed, with chainHash populated */
  events: Event[];
  /** Warnings (non-fatal issues during bundle creation) */
  warnings: string[];
}

