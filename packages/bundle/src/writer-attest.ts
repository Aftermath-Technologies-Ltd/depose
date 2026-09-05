// packages/bundle/src/writer-attest.ts
//
// Step 4 of the writer: sign the manifest, then ask a timestamp
// authority to date the signature.
//
// The two halves fail differently on purpose. No key is a programming
// error and throws. No timestamp authority is a fact about the network,
// and it leaves the bundle sealed pending an anchor rather than
// unproduced, unless the producer asked for the opposite with
// requireAnchor. See docs/bundle-format.md#anchoring.

import { signManifest as signManifestEd25519, tryTimestamps } from '@depose/chain';
import type { Ed25519KeyPair, Rfc3161Token as ChainRfc3161Token, TsaEndpoint } from '@depose/chain';
import { serializeManifestForSigning } from './manifest-io.js';
import type { BundleMode, Manifest, Rfc3161Token, SignatureBlock } from './manifest.js';

/** What attestManifest needs from the writer. */
export interface AttestOptions {
  mode: BundleMode;
  keyPair?: Ed25519KeyPair;
  injectedTimestamps?: ChainRfc3161Token[];
  tsaEndpoints?: TsaEndpoint[];
  requireAnchor: boolean;
  /** Named in the pending-anchor warning so the next command is copyable. */
  bundleDir: string;
  /** Appended to in place. */
  warnings: string[];
}

/** The attestation blocks, already written onto the manifest. */
export interface AttestResult {
  signatures: SignatureBlock[];
  timestamps: Rfc3161Token[];
}

/**
 * Sign the manifest and anchor the signature.
 *
 * Mutates `manifest.signatures`, `manifest.timestamps`, and
 * `manifest.anchorStatus`; all three are outside the signing form, so
 * setting them after signing does not invalidate the signature.
 *
 * @param manifest - The manifest, with the files map already in place.
 * @param options - Mode, key, endpoints, and where to put warnings.
 * @returns The signature and timestamp blocks.
 * @throws Error when signed mode has no key, or when requireAnchor is set
 *   and no authority answers.
 */
export async function attestManifest(manifest: Manifest, options: AttestOptions): Promise<AttestResult> {
  const signatures: SignatureBlock[] = [];
  const timestamps: Rfc3161Token[] = [];
  if (options.mode === 'signed') {
    const sigResult = signManifestEd25519(serializeManifestForSigning(manifest), options.keyPair!);
    signatures.push({
      scheme: 'ed25519',
      signature: sigResult.signatureBase64,
      publicKey: sigResult.publicKeyPem,
      signedFields: 'manifest.json',
    });
    manifest.signatures = signatures;

    // A TSA that cannot be reached no longer costs the producer the whole
    // bundle. The signature is made now and binds the content; the
    // anchor, when `depose anchor` gets it, commits to these same
    // manifest bytes.
    const attempt = options.injectedTimestamps && options.injectedTimestamps.length > 0
      ? { tokens: options.injectedTimestamps, errors: [] }
      : await tryTimestamps(serializeManifestForSigning(manifest), { tsaEndpoints: options.tsaEndpoints });
    for (const token of attempt.tokens) {
      timestamps.push({ tsa: token.tsa, timestamp: token.timestamp, tokenBase64: token.tokenBase64 });
    }
    if (timestamps.length === 0) {
      if (options.requireAnchor) {
        throw new Error(
          `Failed to obtain RFC 3161 timestamp and --require-anchor was set, so no bundle was produced.\n` +
            `${attempt.errors.join('\n')}\n` +
            `Drop --require-anchor to seal now and run depose anchor when the network is back.`
        );
      }
      options.warnings.push(
        `Sealed pending anchor: no timestamp authority answered. The signature is made and the ` +
          `content is bound; run "depose anchor ${options.bundleDir}" to date it. ` +
          `Authorities tried: ${attempt.errors.join('; ')}`
      );
    }
    manifest.timestamps = timestamps;
    manifest.anchorStatus = timestamps.length > 0 ? 'anchored' : 'pending';
  } else {
    options.warnings.push('Bundle is dev-unsigned. signatures=[], timestamps=[]. NOT EVIDENCE.');
  }

  return { signatures, timestamps };
}
