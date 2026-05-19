// packages/cli/src/commands/key.ts
//
// `depose key fingerprint` — print the SHA-256 fingerprint of the
// producer's signing key.
//
// The fingerprint is what recipients pin against. The producer
// publishes it out-of-band (a .well-known page, an attorney's
// printed handshake, a key catalog). The verifier rejects a bundle
// whose embedded `producer.keyFingerprint` doesn't match the
// `--expected-key-fingerprint` the recipient was given.
//
// See docs/key-management.md.

import { existsSync, readFileSync } from 'node:fs';
import { fingerprintPublicKeyPem, formatFingerprintSshStyle, getDefaultPublicKeyPath, loadOrGenerateKeyPair } from '@depose/chain';

export interface KeyCommandArgs {
  'key-dir'?: string;
  /** Print in ssh-style (SHA256:<base64>) instead of hex */
  ssh?: boolean;
  [key: string]: string | boolean | string[] | undefined;
}

export async function handleKeyFingerprint(args: KeyCommandArgs): Promise<void> {
  const keyDir = args['key-dir'] as string | undefined;

  // If the public key already exists at the default location, read
  // it directly so we don't accidentally trigger key *generation*
  // just to inspect the fingerprint.
  const pubPath = keyDir ? `${keyDir}/signing.pub` : getDefaultPublicKeyPath();
  let publicKeyPem: string;
  if (existsSync(pubPath)) {
    publicKeyPem = readFileSync(pubPath, 'utf-8');
  } else {
    const keyPair = loadOrGenerateKeyPair(keyDir);
    publicKeyPem = keyPair.publicKeyPem;
  }

  const hex = fingerprintPublicKeyPem(publicKeyPem);
  if (args.ssh) {
    console.log(formatFingerprintSshStyle(hex));
  } else {
    console.log(hex);
  }
}
