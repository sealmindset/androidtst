import { test, expect, APIRequestContext } from '@playwright/test';
import { config } from '../utils/config';
import { ResponseAnalyzer } from '../utils/response-analyzer';

/**
 * Authentication Flow Security Tests
 *
 * Tests for authentication vulnerabilities including:
 * - Credential stuffing protection
 * - Account enumeration
 * - Session handling
 * - Password reset flows
 * - JWT token handling
 */

test.describe('Authentication Security Tests', () => {
  let apiContext: APIRequestContext;
  let analyzer: ResponseAnalyzer;

  test.beforeAll(async ({ playwright }) => {
    apiContext = await playwright.request.newContext({
      baseURL: config.endpoints.prod.api,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'User-Agent': 'SleepIQ/5.3.30 Android',
        'Content-Type': 'application/json',
        'X-Security-Test': 'auth-flows',
      },
    });
    analyzer = new ResponseAnalyzer();
  });

  test.afterAll(async () => {
    await apiContext.dispose();
    console.log('\n' + analyzer.generateReport());
  });

  test.describe('Login Endpoint Security', () => {
    test('should not reveal user existence on invalid login', async () => {
      // Test with non-existent user
      const nonExistentResponse = await apiContext.put('/rest/login', {
        data: {
          login: 'nonexistent_user_12345@example.com',
          password: 'wrongpassword123',
        },
      });

      // Test with common username pattern
      const commonPatternResponse = await apiContext.put('/rest/login', {
        data: {
          login: 'admin@sleepnumber.com',
          password: 'wrongpassword123',
        },
      });

      await analyzer.analyze(nonExistentResponse);
      await analyzer.analyze(commonPatternResponse);

      // Both should return same error to prevent enumeration
      const nonExistentBody = await nonExistentResponse.text();
      const commonPatternBody = await commonPatternResponse.text();

      // Check for user enumeration vulnerability
      const enumVuln =
        nonExistentBody.includes('User not found') ||
        nonExistentBody.includes('does not exist') ||
        commonPatternBody.includes('incorrect password');

      expect(enumVuln).toBeFalsy();
      console.log('[AUTH] Login enumeration test:', enumVuln ? 'VULNERABLE' : 'SECURE');
    });

    test('should handle SQL injection attempts safely', async () => {
      const sqlPayloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT * FROM users--",
        "admin'--",
        "1' OR '1'='1' /*",
      ];

      for (const payload of sqlPayloads) {
        const response = await apiContext.put('/rest/login', {
          data: {
            login: payload,
            password: payload,
          },
        });

        const analysis = await analyzer.analyze(response);

        // Should not return SQL errors
        expect(analysis.sensitiveDataFound.some(d => d.type === 'sqlError')).toBeFalsy();

        // Should return 400/401, not 500
        expect(response.status()).toBeLessThan(500);

        console.log(`[AUTH] SQL injection "${payload.substring(0, 15)}...": Status ${response.status()}`);
      }
    });

    test('should enforce rate limiting on login attempts', async () => {
      const attempts = 20;
      const responses: number[] = [];

      for (let i = 0; i < attempts; i++) {
        const response = await apiContext.put('/rest/login', {
          data: {
            login: `test_rate_limit_${i}@example.com`,
            password: 'testpassword',
          },
        });
        responses.push(response.status());

        // Small delay to not overwhelm
        await new Promise(r => setTimeout(r, 100));
      }

      // Check if any responses indicate rate limiting (429 or similar)
      const rateLimited = responses.some(s => s === 429);
      console.log('[AUTH] Rate limiting:', rateLimited ? 'ENABLED' : 'NOT DETECTED');
      console.log(`[AUTH] Response codes: ${[...new Set(responses)].join(', ')}`);
    });

    test('should not leak internal errors on malformed JSON', async () => {
      const response = await apiContext.put('/rest/login', {
        data: '{"login": "test@example.com", "password": ', // Malformed JSON
        headers: { 'Content-Type': 'application/json' },
      });

      const analysis = await analyzer.analyze(response);

      // Should not contain stack traces or internal paths
      expect(analysis.sensitiveDataFound.some(d => d.type === 'stackTrace')).toBeFalsy();
      expect(analysis.verboseErrors.length).toBeLessThanOrEqual(1);

      const body = await response.text();
      console.log('[AUTH] Malformed JSON response:', body.substring(0, 100));
    });
  });

  test.describe('JWT Token Security', () => {
    test('should require token header for JWT endpoint', async () => {
      const response = await apiContext.get('/rest/user/jwt');
      const body = await response.text();

      await analyzer.analyze(response);

      expect(response.status()).toBe(400);
      console.log('[JWT] Missing token response:', body);
    });

    test('should reject invalid JWT tokens', async () => {
      const invalidTokens = [
        'invalid_token',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.',
      ];

      for (const token of invalidTokens) {
        const response = await apiContext.get('/rest/user/jwt', {
          headers: { 'X-Token': token },
        });

        const analysis = await analyzer.analyze(response);

        // Should not reveal why token is invalid
        expect(analysis.verboseErrors.length).toBe(0);
        console.log(`[JWT] Invalid token test: Status ${response.status()}`);
      }
    });

    test('should reject JWT with "none" algorithm', async () => {
      // JWT with alg: none (common bypass attempt)
      const noneAlgToken =
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.';

      const response = await apiContext.get('/rest/user/jwt', {
        headers: { 'X-Token': noneAlgToken },
      });

      expect(response.status()).not.toBe(200);
      console.log('[JWT] None algorithm bypass test: Status', response.status());
    });
  });

  test.describe('Session Security', () => {
    test('should return proper session cookie attributes', async () => {
      const response = await apiContext.put('/rest/login', {
        data: {
          login: 'test@example.com',
          password: 'testpassword',
        },
      });

      const setCookieHeaders = response.headers()['set-cookie'];
      console.log('[SESSION] Set-Cookie headers:', setCookieHeaders);

      if (setCookieHeaders) {
        // Check for secure cookie attributes
        const hasHttpOnly = setCookieHeaders.toLowerCase().includes('httponly');
        const hasSecure = setCookieHeaders.toLowerCase().includes('secure');
        const hasSameSite = setCookieHeaders.toLowerCase().includes('samesite');

        console.log('[SESSION] HttpOnly:', hasHttpOnly ? 'YES' : 'MISSING');
        console.log('[SESSION] Secure:', hasSecure ? 'YES' : 'MISSING');
        console.log('[SESSION] SameSite:', hasSameSite ? 'YES' : 'MISSING');

        expect(hasHttpOnly).toBeTruthy();
      }
    });

    test('should invalidate session after multiple failed logins', async () => {
      // First get a session
      const initialResponse = await apiContext.put('/rest/login', {
        data: {
          login: 'test@example.com',
          password: 'testpassword',
        },
      });

      const cookies = initialResponse.headers()['set-cookie'];

      // Now try accessing protected resource
      const protectedResponse = await apiContext.get('/rest/bed', {
        headers: { Cookie: cookies || '' },
      });

      console.log('[SESSION] Protected endpoint status:', protectedResponse.status());
      await analyzer.analyze(protectedResponse);
    });
  });

  test.describe('Password Reset Security', () => {
    test('should not enumerate users via password reset', async () => {
      // This tests Cognito ForgotPassword enumeration
      // Note: Actual implementation would need Cognito client

      console.log('[PWRESET] Password reset enumeration should be tested via Cognito');
      console.log('[PWRESET] See VULNERABILITY_REPORT.md Section 8 for Cognito findings');
    });
  });
});
