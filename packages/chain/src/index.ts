// packages/chain/src/index.ts
//
// Chain package, hash chain, signing, RFC 3161, sigstore, Rekor.
// Named exports only.

// Hash chain (IRONROOT construction)
export {
  buildHashChain,
  verifyHashChain,
  computeChainHash,
  extractEventMetadata,
} from './hash-chain.js';

// RFC 6962 Merkle tree over chain hashes
export {
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  rootFromInclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from './merkle.js';

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

// Deterministic CBOR and COSE_Sign1, for SCITT Signed Statements
export {
  encodeCbor,
  isCborTagged,
  type CborValue,
  type CborTagged,
} from './cbor.js';

export {
  signCoseSign1,
  verifyCoseSign1,
  rawEd25519PublicKey,
  COSE_HEADER,
  CWT_CLAIM,
  COSE_ALG_EDDSA,
  COSE_SIGN1_TAG,
  type CoseSign1Input,
} from './cose-sign1.js';

// did:key identifiers for the Ed25519 signer
export {
  base58btcEncode,
  didKeyFromEd25519Pem,
  bareDidKeyFromEd25519Pem,
} from './did-key.js';

// Key fingerprint helpers
export {
  fingerprintPublicKeyPem,
  formatFingerprintSshStyle,
} from './key-fingerprint.js';

// RFC 3161 timestamping. Producer-side validation (F-04 remediation)
// now does proper ASN.1 DER parsing, nonce verification, and
// messageImprint hash verification. Cryptographic signature + cert-
// chain verification still lives in the Go verifier
// (apps/verify/timestamp/rfc3161.go).
export {
  requestTimestamps,
  buildTimeStampReq,
  validateTsr,
  TsrValidationError,
  DEFAULT_TSA_ENDPOINTS,
  type TsaEndpoint,
  type Rfc3161Token,
  type TimestampOptions,
  type TimeStampReqResult,
  type TsrValidationResult,
} from './timestamp-rfc3161.js';

// Sigstore keyless (scaffold, not yet implemented, Ed25519 + RFC 3161 is
// the only signing path today)
export {
  shouldUseSigstore,
  type SigstoreSignatureResult,
  type SigstoreOptions,
} from './sign-sigstore.js';

// Rekor transparency log (scaffold, not yet implemented)
export {
  type RekorEntry,
  type RekorOptions,
} from './rekor.js';

// Key lifecycle catalog (rotation + revocation MVP)
export {
  KEY_CATALOG_SCHEMA_VERSION,
  loadCatalog,
  saveCatalog,
  findEntry,
  recordActive,
  markRotated,
  markRevoked,
  isRevoked,
  type KeyCatalog,
  type KeyCatalogEntry,
  type KeyCatalogStatus,
} from './key-catalog.js';