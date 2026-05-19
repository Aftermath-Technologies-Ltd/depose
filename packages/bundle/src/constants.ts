// Single source of truth for the verifier download URL.
//
// Anything that points an evidence recipient at where to get
// `depose-verify` MUST import this constant. A CI grep in
// `.github/workflows/ci.yml` blocks merges if the URL appears
// anywhere else in the codebase.
export const VERIFIER_DOWNLOAD_URL =
  'https://github.com/Aftermath-Technologies-Ltd/depose/releases/latest';

// GitHub repository slug used by tooling (release scripts, etc.).
export const GITHUB_REPO_SLUG = 'Aftermath-Technologies-Ltd/depose';
