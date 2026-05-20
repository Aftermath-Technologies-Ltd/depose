// Single source of truth for the verifier download URL.
//
// Anything that points an evidence recipient at where to get
// `depose-verify` MUST import this constant. A CI grep in
// `.github/workflows/ci.yml` blocks merges if the URL appears
// anywhere else in the codebase.
//
// Build-time injection: DEPOSE_RELEASE_TAG (e.g. "v0.1.0") pins the
// URL to a specific release. When unset (dev / pre-tag builds), the
// URL falls back to `releases/latest`. The release workflow MUST set
// DEPOSE_RELEASE_TAG=${GITHUB_REF_NAME} before running `pnpm build`
// so that bundles produced from a tagged release point recipients
// at the verifier that matched that release — not at "whatever is
// latest tomorrow."

// GitHub repository slug used by tooling (release scripts, etc.).
//
// Build-time injection: DEPOSE_REPO_SLUG override at build time;
// otherwise the hardcoded default applies.
//
// Upgrade path: when the repository moves to a different org/name, future
// releases will write new bundles with identity URLs that reference the new
// slug.  Old bundles continue to verify correctly because each verifier
// release validates against the manifest URL recorded inside the bundle at
// the time it was produced — no global rewrite is needed.
const _repoSlug = process.env.DEPOSE_REPO_SLUG ?? 'Aftermath-Technologies-Ltd/depose';
export const GITHUB_REPO_SLUG = _repoSlug;

const _releaseTag = process.env.DEPOSE_RELEASE_TAG ?? '';
/** Release tag this build was produced against (e.g. "v0.1.0"), or "" if unpinned. */
export const DEPOSE_RELEASE_TAG = _releaseTag;

export const VERIFIER_DOWNLOAD_URL = _releaseTag
  ? `https://github.com/${_repoSlug}/releases/tag/${_releaseTag}`
  : `https://github.com/${_repoSlug}/releases/latest`;
