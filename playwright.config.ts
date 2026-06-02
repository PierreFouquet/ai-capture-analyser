import { defineConfig, devices } from '@playwright/test';

// Real-browser end-to-end tests. These complement (do not replace) the fast
// Vitest + jsdom unit/integration suite under test/*.test.{js,ts}. They run the
// actual frontend served statically, with the /api/* backend mocked per-test.
const PORT = Number(process.env.E2E_PORT) || 4321;

export default defineConfig({
    testDir: './test/e2e',
    testMatch: '**/*.spec.ts',
    // Keep the unit suite (test/**/*.test.*) out of Playwright's matcher.
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    reporter: 'list',
    use: {
        baseURL: `http://localhost:${PORT}`,
        trace: 'on-first-retry',
    },
    projects: [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    ],
    webServer: {
        command: 'node test/e2e/static-server.mjs',
        url: `http://localhost:${PORT}`,
        reuseExistingServer: !process.env.CI,
        timeout: 30_000,
    },
});
