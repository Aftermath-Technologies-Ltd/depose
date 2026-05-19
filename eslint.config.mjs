// ESLint v9 flat config for the depose monorepo.
//
// D5: consolidates the legacy .eslintrc.cjs into this file. Severity
// for unused imports/vars/types is 'error', not 'warn', so dead
// imports cannot accumulate. CI runs `pnpm lint --max-warnings 0`.
import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  // Global ignore — files NOT linted at all. Flat config treats a
  // config object with only `ignores` as the global ignore list.
  { ignores: ['**/dist/**', '**/node_modules/**', '**/*.d.ts', '**/*.tsbuildinfo'] },

  // Apply eslint:recommended only to JS files. TypeScript files use
  // typescript-eslint's recommended set, which is layered below.
  // Keeping js:recommended off of .ts files is what lets us disable
  // the runtime-level `no-undef` (TypeScript's own checker subsumes
  // it with full type awareness).
  { ...js.configs.recommended, files: ['**/*.js', '**/*.mjs', '**/*.cjs'] },
  {
    files: ['packages/**/*.ts'],
    ignores: ['**/dist/**', '**/node_modules/**', '**/*.d.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        // Node 20+ runtime globals — flat config doesn't enable
        // env: node automatically.
        process: 'readonly',
        Buffer: 'readonly',
        console: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        globalThis: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        require: 'readonly',
        module: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setImmediate: 'readonly',
        clearImmediate: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-require-imports': 'error',
      // ESLint base rule disables — handled by the TS variants
      // above; leaving both on would double-report. no-undef is
      // disabled because TypeScript's own checker catches undefined
      // identifiers with full type awareness; the ESLint version
      // sees a TS file as plain JS and flags every Node global.
      'no-unused-vars': 'off',
      'no-undef': 'off',
    },
  },
];
