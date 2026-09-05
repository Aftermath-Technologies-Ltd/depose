// packages/chain/src/sign-sigstore.ts
//
// Sigstore keyless signing for DEPOSE evidence bundles (optional).
//
//
// This module provides the interface for Sigstore keyless signing
// when SIGSTORE_OIDC=1 is set or a CI environment with OIDC is detected.
//
// Current status: scaffold only. Full implementation deferred until
// Ed25519 path is validated end-to-end.

// ── Types ─────────────────────────────────────────────────────────────

export interface SigstoreSignatureResult {
  /** Base64-encoded signature */
  signatureBase64: string;
  /** Fulcio-issued X.509 certificate (PEM) */
  fulcioCert: string;
  /** The scheme identifier */
  scheme: 'sigstore-fulcio';
}

export interface SigstoreOptions {
  /** OIDC identity token (from CI or browser flow) */
  identityToken?: string;
  /** Fulcio URL (default: https://fulcil.sigstore.dev) */
  fulcioUrl?: string;
  /** Rekor URL (default: https://rekor.sigstore.dev) */
  rekorUrl?: string;
}

// ── Detection ─────────────────────────────────────────────────────────

/**
 * Detect whether Sigstore keyless signing should be attempted.
 * Returns true if:
 *   - SIGSTORE_OIDC=1 is set, OR
 *   - A CI environment with OIDC is detected (GitHub Actions, GitLab CI)
 */
export function shouldUseSigstore(): boolean {
  if (process.env.SIGSTORE_OIDC === '1') {
    return true;
  }
  // GitHub Actions provides OIDC via ACTIONS_ID_TOKEN_REQUEST_URL
  if (process.env.GITHUB_ACTIONS === 'true' && process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    return true;
  }
  return false;
}

// ── Signing (stub) ────────────────────────────────────────────────────

/**
 * Sign the manifest using Sigstore keyless signing.
 *
 * NOT YET IMPLEMENTED. Requires:
 *   - OIDC identity acquisition
 *   - Fulcio certificate issuance
 *   - Cosign/sigstore client library or CLI
 *
 * Signatures from this function should NOT be used in production.
 * Returns a placeholder indicating the feature is available but unimplemented.
 */
export async function signManifestSigstore(
  _manifestCanonicalJson: string,
  _options?: SigstoreOptions
): Promise<SigstoreSignatureResult> {
  throw new Error(
    'Sigstore keyless signing is not yet implemented. ' +
    'Use Ed25519 signing (default) for now. ' +
    'Sigstore support will be added in a future release.'
  );
}

// ── Verification (stub) ──────────────────────────────────────────────

/**
 * Verify a Sigstore keyless signature.
 *
 * NOT YET IMPLEMENTED.
 */
export async function verifyManifestSigstore(
  _manifestCanonicalJson: string,
  _signatureBase64: string,
  _fulcioCert: string
): Promise<boolean> {
  throw new Error(
    'Sigstore keyless verification is not yet implemented. ' +
    'Use the depose-verify Go binary for full verification.'
  );
}