// packages/bundle/src/manifest-io.ts
//
// Turning a manifest into bytes. Two forms exist and the difference
// matters: the full canonical JSON that goes on disk, and the signing
// form, which strips the three fields written after the signature is
// made (signatures, timestamps, anchorStatus). The verifier rebuilds the
// signing form the same way, in apps/verify/manifest.StripSignatureFields.

import { canonicalJson, sha256String } from '@depose/core';
import type { Manifest } from './manifest.js';

/**
 * Serialize a manifest to canonical (deterministic) JSON string.
 */
export function serializeManifest(manifest: Manifest): string {
  return canonicalJson(manifest);
}

/**
 * Serialize a manifest for signing, excludes signatures and timestamps
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
  // anchorStatus is decided after signing and can change when the bundle
  // is anchored later, so it is stripped exactly like signatures and
  // timestamps. See the Manifest.anchorStatus docstring.
  delete unsigned.anchorStatus;
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
