// packages/bundle/src/anchor.ts
//
// Anchoring a bundle that was sealed while the network was down.
//
// The old writer threw when every TSA failed, so a laptop on a plane
// produced nothing at all. A signature made now and a timestamp obtained
// later is strictly better evidence than no bundle: the signature binds
// the content, and the anchor, when it arrives, still commits to the
// same manifest bytes the seal signed.
//
// `depose anchor` never touches manifest.json. The manifest is
// byte-identical before and after, so the original signature verifies
// exactly as it did. The anchor lives in attestations/anchor.json, which
// carries its own countersignature by the same key, so a third party
// cannot bolt a token onto someone else's bundle and have it read as the
// producer's own act.
//
// See docs/bundle-format.md#anchoring.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson, sha256String } from '@depose/core';
import {
  tryTimestamps,
  signEd25519,
  verifyEd25519,
  fingerprintPublicKeyPem,
  type Ed25519KeyPair,
  type TsaEndpoint,
} from '@depose/chain';
import { serializeManifestForSigning } from './manifest-io.js';
import type { Manifest, Rfc3161Token } from './manifest.js';

/** Path of the anchor document, relative to the bundle root. */
export const ANCHOR_PATH = 'attestations/anchor.json';

/** Directory holding the token files, relative to the bundle root. */
export const ANCHOR_TIMESTAMP_DIR = 'attestations/rfc3161-timestamps';

/** Schema version of the anchor document. */
export const ANCHOR_SCHEMA_VERSION = 1;

/** One anchor token, plus where its bytes live in the tree. */
export interface AnchorToken extends Rfc3161Token {
  /** Bundle-relative path of the .tsr file holding these bytes. */
  file: string;
}

/** The anchor document, without its countersignature. */
export interface AnchorClaim {
  schemaVersion: number;
  bundleId: string;
  /** When the anchor was obtained, from the producer's clock. */
  anchoredAt: string;
  /**
   * SHA-256 of the manifest's signing form, which is what the tokens
   * commit to. A verifier recomputes it and refuses an anchor that
   * belongs to a different bundle.
   */
  manifestSha256: string;
  timestamps: AnchorToken[];
}

/** The countersignature binding the claim to the sealing key. */
export interface AnchorCountersignature {
  scheme: 'ed25519';
  signature: string;
  publicKey: string;
  signedFields: typeof ANCHOR_PATH;
}

/** The full anchor document as written to disk. */
export interface AnchorDocument extends AnchorClaim {
  countersignature: AnchorCountersignature;
}

/** What an anchoring run did. */
export interface AnchorResult {
  /** The document written, or the one already present when nothing was needed. */
  document: AnchorDocument;
  /** True when this run obtained the tokens; false when they were already there. */
  obtained: boolean;
  /** One line per TSA that failed. */
  errors: string[];
}

/** Options for {@link anchorBundle}. */
export interface AnchorOptions {
  /** The key that sealed the bundle. */
  keyPair: Ed25519KeyPair;
  /** Authorities to try; defaults to the built-in list. */
  tsaEndpoints?: TsaEndpoint[];
  /** Clock, injectable so a fixture reproduces. */
  now?: () => Date;
  /** Tokens to use instead of calling a TSA. Tests only. */
  injectedTimestamps?: Rfc3161Token[];
  /** Add an anchor even when the bundle already has one. */
  force?: boolean;
}

/**
 * Obtain an RFC 3161 anchor for an already-sealed bundle and record it.
 *
 * @param bundleDir - The sealed bundle.
 * @param options - The sealing key, the authorities, and injectables.
 * @returns The anchor document and any TSA errors.
 * @throws Error when the bundle is unreadable, was sealed by a different
 *   key, is already anchored, or no authority could be reached.
 */
export async function anchorBundle(bundleDir: string, options: AnchorOptions): Promise<AnchorResult> {
  const manifestPath = join(bundleDir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    throw new Error(`${bundleDir} has no manifest.json; point anchor at a sealed bundle directory`);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Manifest;
  assertAnchorable(bundleDir, manifest, options);

  const anchorPath = join(bundleDir, ANCHOR_PATH);
  if (existsSync(anchorPath) && options.force !== true) {
    const existing = JSON.parse(readFileSync(anchorPath, 'utf-8')) as AnchorDocument;
    return { document: existing, obtained: false, errors: [] };
  }

  const signingForm = serializeManifestForSigning(manifest);
  const attempt = options.injectedTimestamps?.length
    ? { tokens: options.injectedTimestamps, errors: [] }
    : await tryTimestamps(signingForm, { tsaEndpoints: options.tsaEndpoints });

  if (attempt.tokens.length === 0) {
    throw new Error(
      `No timestamp authority could be reached, so ${bundleDir} is still unanchored.\n` +
        `${attempt.errors.join('\n')}\n` +
        `The bundle's signature is unaffected; run depose anchor again when the network is back.`
    );
  }

  mkdirSync(join(bundleDir, ANCHOR_TIMESTAMP_DIR), { recursive: true });
  const timestamps: AnchorToken[] = attempt.tokens.map((token, index) => {
    const file = `${ANCHOR_TIMESTAMP_DIR}/anchor-${index}.tsr`;
    writeFileSync(join(bundleDir, file), Buffer.from(token.tokenBase64, 'base64'));
    return { ...token, file };
  });

  const claim: AnchorClaim = {
    schemaVersion: ANCHOR_SCHEMA_VERSION,
    bundleId: manifest.bundleId,
    anchoredAt: (options.now?.() ?? new Date()).toISOString(),
    manifestSha256: sha256String(signingForm),
    timestamps,
  };
  const document: AnchorDocument = { ...claim, countersignature: countersign(claim, options.keyPair) };
  writeFileSync(anchorPath, JSON.stringify(document, null, 2) + '\n', 'utf-8');

  return { document, obtained: true, errors: attempt.errors };
}

/**
 * Sign an anchor claim with the sealing key.
 *
 * @param claim - The claim, without its countersignature.
 * @param keyPair - The sealing key.
 * @returns The countersignature block.
 */
export function countersign(claim: AnchorClaim, keyPair: Ed25519KeyPair): AnchorCountersignature {
  return {
    scheme: 'ed25519',
    signature: signEd25519(canonicalJson(claim), keyPair.privateKeyPem),
    publicKey: keyPair.publicKeyPem,
    signedFields: ANCHOR_PATH,
  };
}

/**
 * Check an anchor document's countersignature.
 *
 * @param document - The document read from disk.
 * @returns True when the countersignature covers the claim as written.
 */
export function verifyAnchorCountersignature(document: AnchorDocument): boolean {
  const { countersignature, ...claim } = document;
  return verifyEd25519(canonicalJson(claim), countersignature.signature, countersignature.publicKey);
}

function assertAnchorable(bundleDir: string, manifest: Manifest, options: AnchorOptions): void {
  if (manifest.producer.mode !== 'signed') {
    throw new Error(
      `${bundleDir} is a ${manifest.producer.mode} bundle. An anchor dates a signature, and this bundle has none.`
    );
  }
  if (manifest.timestamps.length > 0 && options.force !== true) {
    throw new Error(
      `${bundleDir} was already anchored at seal time (${manifest.timestamps[0]!.timestamp}). ` +
        `Pass force to add another anchor.`
    );
  }
  const sealed = manifest.producer.keyFingerprint;
  const local = fingerprintPublicKeyPem(options.keyPair.publicKeyPem);
  if (sealed && sealed !== local) {
    throw new Error(
      `${bundleDir} was sealed by key ${sealed.slice(0, 16)}... and the key given is ${local.slice(0, 16)}.... ` +
        `An anchor is countersigned by the producer, so it has to be the sealing key.`
    );
  }
}
