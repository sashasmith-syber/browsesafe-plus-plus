import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      globals: {
        // Chrome Extension APIs
        chrome: 'readonly',
        // Service Worker globals
        self: 'readonly',
        caches: 'readonly',
        fetch: 'readonly',
        // DOM globals (for content scripts)
        document: 'readonly',
        window: 'readonly',
        // Node.js globals (for tests)
        require: 'readonly',
        module: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        process: 'readonly',
        Buffer: 'readonly'
      },
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
      }
    },
    rules: {
      // Security rules
      'no-inner-html': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      
      // Code quality
      'no-console': 'warn',
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': 'error',
      'strict': ['error', 'global'],
      
      // Best practices
      'no-unused-vars': 'warn',
      'no-undef': 'error',
      'no-empty': 'warn',
      'no-multiple-empty-lines': ['warn', { max: 1 }],
      'no-trailing-spaces': 'warn',
      'quotes': ['warn', 'single'],
      'semi': ['warn', 'always']
    },
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/.git/**'
    ]
  }
];
