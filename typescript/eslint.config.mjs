import solanaConfig from '@solana/eslint-config-solana';

export default [
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/*.tsbuildinfo', '**/__tests__/**'],
  },
  ...solanaConfig,
  {
    languageOptions: {
      parserOptions: {
        tsconfigRootDir: import.meta.dirname,
      },
    },

    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
];
