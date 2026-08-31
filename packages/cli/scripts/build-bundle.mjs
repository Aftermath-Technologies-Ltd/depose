#!/usr/bin/env node
// packages/cli/scripts/build-bundle.mjs
//
// Bundle the depose CLI and depose-hook entrypoints into single,
// self-contained CommonJS files using esbuild. The resulting bundles
// inline all @depose/* workspace dependencies, so the published
// tarball does not depend on any private workspace packages and
// `npm install -g <tarball>` works without registry lookups.

import { build } from 'esbuild';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, '..');
const outDir = resolve(pkgRoot, 'dist-bundle');

mkdirSync(outDir, { recursive: true });

const SHEBANG = '#!/usr/bin/env node\n';

// ESM bundles produced by esbuild can pull in CJS-only deps (commander,
// yaml, etc.). esbuild emits `__require` calls to load them, but bare
// ESM does not provide a `require` binding. Inject one at the top of
// the bundle via createRequire so those CJS deps resolve correctly.
const ESM_BANNER = [
  '#!/usr/bin/env node',
  `import { createRequire as __depose_cr } from 'node:module';`,
  `import { fileURLToPath as __depose_furl } from 'node:url';`,
  `import { dirname as __depose_dn } from 'node:path';`,
  `const require = __depose_cr(import.meta.url);`,
  `const __filename = __depose_furl(import.meta.url);`,
  `const __dirname = __depose_dn(__filename);`,
].join('\n');
void SHEBANG;

async function bundle(entry, outFile) {
  await build({
    entryPoints: [resolve(pkgRoot, entry)],
    outfile: resolve(outDir, outFile),
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'esm',
    minify: false,
    sourcemap: false,
    legalComments: 'none',
    external: [],
    banner: { js: ESM_BANNER },
  });
  chmodSync(resolve(outDir, outFile), 0o755);
}

// Generate a small entry wrapper that invokes main(). Bundling the
// compiled main.js directly only inlines the exports; nothing calls
// main, so the bundle would be a no-op.
const cliEntry = resolve(outDir, '_cli-entry.mjs');
writeFileSync(
  cliEntry,
  `import { main } from '../dist/commands/main.js';\n` +
    `main(process.argv.slice(2));\n`,
);

// The hook entry is a tiny wrapper around @depose/capture-claude;
// inline it via a small generated entrypoint so esbuild can see
// the import and pull capture-claude into the bundle.
const hookEntry = resolve(outDir, '_hook-entry.mjs');
writeFileSync(
  hookEntry,
  `import { runHookCli } from '@depose/capture-claude';\n` +
    `const sub = process.argv[2];\n` +
    `if (sub === 'pretooluse') {\n` +
    `  runHookCli().catch(() => process.exit(0));\n` +
    `} else {\n` +
    `  process.stderr.write(\`depose-hook: unknown subcommand "\${sub || ''}"\\n\`);\n` +
    `  process.stderr.write('Usage: depose-hook pretooluse\\n');\n` +
    `  process.exit(0);\n` +
    `}\n`,
);
await bundle('dist-bundle/_hook-entry.mjs', 'depose-hook.mjs');

// Build the main CLI bundle from the generated entry.
await bundle('dist-bundle/_cli-entry.mjs', 'depose.mjs');

// Clean up the generated entries.
import('node:fs').then((fs) => {
  fs.rmSync(hookEntry);
  fs.rmSync(cliEntry);
});

console.log('Bundled CLI to', outDir);
