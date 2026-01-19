import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright + Burp Security Test Harness Configuration
 *
 * Routes all traffic through Burp proxy for capture and analysis.
 * Burp should be running on localhost:8080 before starting tests.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // Sequential for easier Burp analysis
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1, // Single worker for cleaner traffic capture
  reporter: [
    ['html', { outputFolder: 'test-results' }],
    ['json', { outputFile: 'test-results/results.json' }],
    ['list']
  ],

  use: {
    // Route through Burp proxy
    proxy: {
      server: 'http://127.0.0.1:8080',
    },

    // Ignore SSL errors (Burp's certificate)
    ignoreHTTPSErrors: true,

    // Capture screenshots and traces for analysis
    screenshot: 'on',
    trace: 'on',
    video: 'on',

    // Extended timeouts for proxy overhead
    actionTimeout: 30000,
    navigationTimeout: 60000,

    // Custom headers to identify test traffic in Burp
    extraHTTPHeaders: {
      'X-Security-Test': 'playwright-burp-harness',
      'X-Test-Run': new Date().toISOString(),
    },
  },

  projects: [
    {
      name: 'api-tests',
      testMatch: /api-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        baseURL: 'https://prod-api.sleepiq.sleepnumber.com',
      },
    },
    {
      name: 'web-portal-tests',
      testMatch: /web-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        baseURL: 'https://sleepiq.sleepnumber.com',
      },
    },
    {
      name: 'auth-tests',
      testMatch: /auth-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
      },
    },
    {
      name: 'idor-tests',
      testMatch: /idor-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        baseURL: 'https://prod-api.sleepiq.sleepnumber.com',
      },
    },
    {
      name: 'error-disclosure-tests',
      testMatch: /error-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
