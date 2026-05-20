// Single source of truth for the verifier download URL.
//
// Anything that points an evidence recipient at where to get
// `depose-verify` MUST import this constant. A CI grep in
// `.github/workflows/ci.yml` blocks merges if the URL appears
// anywhere else in the codebase.
export const VERIFIER_DOWNLOAD_URL =
  'https://github.com/Aftermath-Technologies-Ltd/depose/releases/latest';

// GitHub repository slug used by tooling (release scripts, etc.).
//
// Build-time injection: the preferred approach is to set the environment
// variable DEPOSE_REPO_SLUG before running the build/tsc step; this value
// is resolved at import time and baked into the bundle.  The hardcoded
// default below acts as a fallback so the project still compiles without
// the env-var.
//
// Upgrade path: when the repository moves to a different org/name, future
// releases will write new bundles with identity URLs that reference the new
// slug.  Old bundles continue to verify correctly because each verifier
// release validates against the manifest URL recorded inside the bundle at
// the time it was produced — no global rewrite is needed.
const _repoSlug = process.env.DEPOSE_REPO_SLUG ?? 'Aftermath-Technologies-Ltd/depose';
export const GITHUB_REPO_SLUG = _repoSlug;
