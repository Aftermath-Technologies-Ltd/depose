// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
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
