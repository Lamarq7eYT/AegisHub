import js from '@eslint/js';
import security from 'eslint-plugin-security';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';

export default [
  js.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**'],
    languageOptions: {
      parser: tsParser,
      globals: {
        console: 'readonly',
        document: 'readonly',
        fetch: 'readonly',
        process: 'readonly',
        setTimeout: 'readonly',
        window: 'readonly'
      },
      parserOptions: {
        sourceType: 'module'
      }
    },
    plugins: {
      '@typescript-eslint': tseslint,
      security
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      ...security.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'error'
    }
  }
];
