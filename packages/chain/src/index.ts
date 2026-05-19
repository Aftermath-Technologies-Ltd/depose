// packages/chain/src/index.ts
//
// Chain package — hash chain, signing, RFC 3161, sigstore, Rekor.
// Named exports only (BUILD_PLAN.md §3.1).

// Hash chain (IRONROOT construction)
export {
  buildHashChain,
  verifyHashChain,
  computeChainHash,
  extractEventMetadata,
} from './hash-chain.js';

// Ed25519 signing
export {
  generateEd25519KeyPair,
  loadOrGenerateKeyPair,
  signEd25519,
  verifyEd25519,
  signManifest,
  verifyManifestSignature,
  getDefaultKeyDir,
  getDefaultSigningKeyPath,
  getDefaultPublicKeyPath,
  type Ed25519KeyPair,
  type Ed25519SignatureResult,
} from './sign-ed25519.js';

// Key fingerprint helpers
export {
  fingerprintPublicKeyPem,
  formatFingerprintSshStyle,
} from './key-fingerprint.js';

// RFC 3161 timestamping
export {
  requestTimestamps,
  buildTimeStampReq,
  extractTimestampFromTsr,
  verifyTimestamp,
  DEFAULT_TSA_ENDPOINTS,
  type TsaEndpoint,
  type Rfc3161Token,
  type TimestampOptions,
} from './timestamp-rfc3161.js';

// Sigstore keyless (stub — deferred per build plan)
export {
  shouldUseSigstore,
  type SigstoreSignatureResult,
  type SigstoreOptions,
} from './sign-sigstore.js';

// Rekor transparency log (stub — optional per build plan)
export {
  type RekorEntry,
  type RekorOptions,
} from './rekor.js';