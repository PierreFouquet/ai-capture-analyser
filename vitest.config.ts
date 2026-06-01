import { defineConfig } from 'vitest/config';

// Worker logic runs under the default `node` environment. Browser-facing
// modules (frontend) opt into jsdom per-file with a
// `// @vitest-environment jsdom` pragma at the top of the test.
export default defineConfig({
    test: {
        environment: 'node',
        include: ['test/**/*.test.{js,ts}'],
        coverage: {
            provider: 'v8',
            // Only instrument actual source, not assets/configs/tests.
            include: ['src/**/*.ts', 'public/**/*.js'],
            reporter: ['text', 'html'],
        },
    },
});
