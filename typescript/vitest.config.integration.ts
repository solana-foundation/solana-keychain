import { defineConfig } from 'vitest/config';

import NoAllSkippedReporter from './packages/test-utils/src/no-all-skipped-reporter.js';

// Load root .env before tests run (Node 20+ built-in, no package needed)
try { process.loadEnvFile(new URL('../.env', import.meta.url).pathname); } catch { /* no .env, skip */ }

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['**/src/**/*.integration.test.ts'],
        exclude: ['**/node_modules/**', '**/dist/**'],
        testTimeout: 30000, // 30 second timeout for integration tests
        fileParallelism: false, // Disable for CI
        maxWorkers: 1, // Disable for CI
        reporters: process.env.CI ? ['default', new NoAllSkippedReporter()] : ['default'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            exclude: ['**/node_modules/**', '**/dist/**', '**/*.test.ts', '**/*.integration.test.ts'],
        },
    },
});
