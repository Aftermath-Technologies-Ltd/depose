// packages/cli/src/version.ts
//
// Single source of truth for the CLI version string.
//
// Not read from package.json at runtime: the shipped CLI is an esbuild
// single-file bundle under dist-bundle/, where no package.json is
// guaranteed to sit next to the entrypoint. A constant is resolved at
// build time and cannot fail in the field.
//
// packages/cli/test/version.test.ts asserts this matches package.json, so
// the two cannot drift silently.

/** Version reported by `depose --version` and written to manifest.producer.version. */
export const CLI_VERSION = '0.1.0';
