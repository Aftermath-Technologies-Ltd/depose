// vitest.config.ts
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Workspace packages resolve to their TypeScript source, not to dist/. Their
// package.json entries point at dist/, so without this the suite imported
// whatever the last `tsc --build` left behind: on a fresh checkout half the
// test files failed to load, and after a source edit without a rebuild they
// tested stale output.
const workspacePackages = ['bundle', 'capture-claude', 'chain', 'core', 'narrative'];

export default defineConfig({
  resolve: {
    alias: workspacePackages.map((name) => ({
      find: new RegExp(`^@depose/${name}$`),
      replacement: fileURLToPath(new URL(`./packages/${name}/src/index.ts`, import.meta.url)),
    })),
  },
  test: {
    globals: false,
    include: ['packages/*/test/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    // Pins HOME and DEPOSE_CAPTURE_DIR to a temp dir before the module
    // graph loads, so no suite reads the developer's real capture store.
    setupFiles: ['tests/setup/isolate-env.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['packages/*/src/**/*.ts'],
      exclude: [
        'packages/*/src/index.ts',
        '**/*.d.ts',
      ],
    },
  },
});
