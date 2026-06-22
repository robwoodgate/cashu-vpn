import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Flat config (ESLint 9). Lints TypeScript only, matching the previous
// `--ext .ts` scope — build output and the manual .mjs scripts stay out.
export default tseslint.config(
  { ignores: ['dist/', 'node_modules/'] },
  {
    files: ['**/*.ts'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  {
    // Browser-only client bundle (esbuild). Allow DOM globals.
    files: ['src/client.ts'],
    languageOptions: { globals: { ...globals.browser } },
  },
);
