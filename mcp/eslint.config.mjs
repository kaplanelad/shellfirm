import js from '@eslint/js';
import globals from 'globals';
import tsEslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import vitestPlugin from 'eslint-plugin-vitest';

export default [
  // Base JS recommended rules
  js.configs.recommended,

  // TypeScript files
  {
    files: ['**/*.ts', '**/*.tsx'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      globals: { ...globals.node },
    },
    plugins: {
      '@typescript-eslint': tsEslint,
    },
    rules: {
      // Allow console usage for MCP logging
      'no-console': 'off',
      // Use TS rule instead; disable base rule in TS files
      'no-unused-vars': 'off',
      // Some TS type names (like NodeJS.Timeout) shouldn't trigger no-undef
      'no-undef': 'off',
      // Allow empty catch blocks (we intentionally silence errors in some areas)
      'no-empty': ['error', { allowEmptyCatch: true }],
      // Keep TS basic hygiene
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },

  // JavaScript and ESM config files
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      'no-console': 'off',
    },
  },
  {
    files: ['**/*.test.ts', '**/*.spec.ts'],
    plugins: {
      vitest: vitestPlugin,
    },
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
      },
      globals: { ...globals.node, ...globals.browser, ...vitestPlugin.environments.env.globals },
    },
    rules: {
      // Add test-specific rules if needed later
    },
  },
  // File-specific overrides
  {
    files: ['src/shellfirm-wasm.ts'],
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
      'no-empty': 'off',
    },
  },
  // Type declaration files shouldn't flag unused variables in signatures
  {
    files: ['**/*.d.ts'],
    rules: {
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
  {
    ignores: [
      'node_modules/**',
      'dist/**',
    ],
  },
];


