// packages/chain/src/rekor.ts
//
// Optional Rekor transparency log integration for DEPOSE evidence bundles.
//
// Optional Rekor submission.
//
// Rekor provides a public, append-only transparency log that records
// when a signature was created. This provides:
//   - Non-repudiation: the entry existed at a specific time
//   - Discoverability: anyone can verify the entry exists in the log
//   - Durability: the log is distributed and mirrored
//
// Current status: scaffold only. Full implementation is deferred until
// after Ed25519 + RFC 3161 are validated end-to-end.

// ── Types ─────────────────────────────────────────────────────────────

export interface RekorEntry {
  /** UUID of the Rekor entry */
  uuid: string;
  /** Base64-encoded body */
  body: string;
  /** Unix timestamp of when the entry was integrated */
  integratedTime: number;
}

export interface RekorOptions {
  /** Rekor API URL (default: https://rekor.sigstore.dev) */
  rekorUrl?: string;
  /** Request timeout in milliseconds (default: 15000) */
  timeoutMs?: number;
}

// ── Submission (stub) ─────────────────────────────────────────────────

/**
 * Submit a signature to the Rekor transparency log.
 *
 * NOT YET IMPLEMENTED. Requires:
 *   - Rekor API client
 *   - Proper rekord format (sha256 hash + signature + public key)
 *
 * @returns Rekor entry with UUID, body, and integrated time
 */
export async function submitToRekor(
  _signatureBase64: string,
  _publicKeyPem: string,
  _dataHashHex: string,
  _options?: RekorOptions
): Promise<RekorEntry> {
  // Rekor submission is optional per the build plan.
  // Return empty result indicating it was skipped.
  throw new Error(
    'Rekor transparency log submission is not yet implemented. ' +
    'This is an optional feature that will be added in a future release.'
  );
}

// ── Verification (stub) ──────────────────────────────────────────────

/**
 * Verify a Rekor inclusion proof.
 *
 * NOT YET IMPLEMENTED.
 *
 * @returns True if the entry is valid and included in the log
 */
export async function verifyRekorInclusion(
  _entry: RekorEntry
): Promise<boolean> {
  throw new Error(
    'Rekor inclusion proof verification is not yet implemented.'
  );
}