import { test, expect, APIRequestContext } from '@playwright/test';
import { config } from '../utils/config';
import { ResponseAnalyzer } from '../utils/response-analyzer';

/**
 * Error Disclosure Security Tests
 *
 * Tests for information disclosure through error messages including:
 * - Verbose error messages revealing internal paths
 * - Stack traces in responses
 * - Database error messages
 * - Internal API structure exposure
 * - Header-based information disclosure
 */

test.describe('Error Disclosure Security Tests', () => {
  let apiContext: APIRequestContext;
  let analyzer: ResponseAnalyzer;

  test.beforeAll(async ({ playwright }) => {
    apiContext = await playwright.request.newContext({
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'User-Agent': 'SleepIQ/5.3.30 Android',
        'X-Security-Test': 'error-disclosure',
      },
    });
    analyzer = new ResponseAnalyzer();
  });

  test.afterAll(async () => {
    await apiContext.dispose();
    console.log('\n' + analyzer.generateReport());
  });

  test.describe('Legacy BAM Endpoint Disclosure', () => {
    const bamBase = config.endpoints.prod.bam;

    test('should not leak internal structure via getSoftware.jsp', async () => {
      const testPayloads = [
        { deviceId: '12345' },
        { deviceId: '00000000-0000-0000-0000-000000000001' },
        { deviceId: "' OR '1'='1" },
        { deviceId: '../../../etc/passwd' },
      ];

      for (const payload of testPayloads) {
        const url = `${bamBase}/bam/device/getSoftware.jsp?deviceId=${encodeURIComponent(payload.deviceId)}`;
        const response = await apiContext.get(url);
        const analysis = await analyzer.analyze(response);
        const body = await response.text();

        console.log(`\n[BAM] getSoftware.jsp with deviceId="${payload.deviceId}":`);
        console.log(`[BAM] Status: ${response.status()}`);

        // Check for internal structure leak
        const leaksStructure =
          body.includes('RequestSoftwareMessage') ||
          body.includes('requestId=') ||
          body.includes('deviceId2=') ||
          body.includes('accountNumberStr=');

        if (leaksStructure) {
          console.log('[BAM] WARNING: Internal API structure leaked!');
          console.log(`[BAM] Response: ${body.substring(0, 500)}`);
        }

        // Check for sensitive patterns
        if (analysis.sensitiveDataFound.length > 0) {
          console.log('[BAM] Sensitive data found:', analysis.sensitiveDataFound.map(d => d.type).join(', '));
        }
      }
    });

    test('should not expose server time without authentication', async () => {
      const response = await apiContext.get(`${bamBase}/bam/device/getTime.jsp`);
      const body = await response.text();

      console.log(`\n[BAM] getTime.jsp response: ${body}`);
      console.log(`[BAM] Status: ${response.status()}`);

      // This endpoint returns time without auth - document as finding
      if (response.status() === 200 && body.includes('timeMS=')) {
        console.log('[BAM] FINDING: Server time exposed without authentication');
      }
    });

    test('should not leak config structure via getConfig.jsp', async () => {
      const endpoints = [
        `${bamBase}/bam/device/getConfig.jsp`,
        `${bamBase}/bam/device/getConfig.jsp?deviceId=test`,
        `${bamBase}/bam/device/getConfig.jsp?deviceId=1&accountId=1`,
      ];

      for (const url of endpoints) {
        const response = await apiContext.get(url);
        const analysis = await analyzer.analyze(response);
        const body = await response.text();

        console.log(`\n[BAM] getConfig.jsp test:`);
        console.log(`[BAM] URL: ${url}`);
        console.log(`[BAM] Status: ${response.status()}`);
        console.log(`[BAM] Response: ${body.substring(0, 300)}`);

        if (analysis.verboseErrors.length > 0) {
          console.log('[BAM] Verbose errors detected');
        }
      }
    });
  });

  test.describe('REST API Error Disclosure', () => {
    const apiBase = config.endpoints.prod.api;

    test('should return generic errors for invalid endpoints', async () => {
      const invalidEndpoints = [
        '/rest/nonexistent',
        '/rest/admin',
        '/rest/debug',
        '/rest/internal/status',
        '/rest/../../../etc/passwd',
        '/rest/sleeper/../../admin',
      ];

      for (const endpoint of invalidEndpoints) {
        const response = await apiContext.get(`${apiBase}${endpoint}`);
        const analysis = await analyzer.analyze(response);
        const body = await response.text();

        console.log(`\n[API] Invalid endpoint: ${endpoint}`);
        console.log(`[API] Status: ${response.status()}`);

        // Check for path traversal reflection
        if (body.includes('..') || body.includes('etc/passwd')) {
          console.log('[API] WARNING: Path traversal reflected in response!');
        }

        // Check for verbose errors
        if (analysis.verboseErrors.length > 0) {
          console.log('[API] Verbose error:', analysis.verboseErrors[0].substring(0, 100));
        }
      }
    });

    test('should not leak structure on malformed requests', async () => {
      const malformedRequests = [
        {
          method: 'PUT',
          url: `${apiBase}/rest/login`,
          data: 'not-valid-json',
          contentType: 'application/json',
        },
        {
          method: 'PUT',
          url: `${apiBase}/rest/login`,
          data: '{"incomplete": ',
          contentType: 'application/json',
        },
        {
          method: 'PUT',
          url: `${apiBase}/rest/login`,
          data: '<xml>test</xml>',
          contentType: 'application/xml',
        },
        {
          method: 'GET',
          url: `${apiBase}/rest/bed/null/status`,
          data: null,
          contentType: 'application/json',
        },
      ];

      for (const req of malformedRequests) {
        const response = await apiContext.fetch(req.url, {
          method: req.method,
          data: req.data || undefined,
          headers: { 'Content-Type': req.contentType },
        });

        const analysis = await analyzer.analyze(response);
        const body = await response.text();

        console.log(`\n[API] Malformed request test:`);
        console.log(`[API] ${req.method} ${req.url}`);
        console.log(`[API] Status: ${response.status()}`);

        // Check for stack traces
        if (analysis.sensitiveDataFound.some(d => d.type === 'stackTrace')) {
          console.log('[API] CRITICAL: Stack trace in response!');
        }

        // Check for Java exceptions
        if (analysis.sensitiveDataFound.some(d => d.type === 'javaException')) {
          console.log('[API] WARNING: Java exception exposed:', body.substring(0, 200));
        }
      }
    });

    test('should not expose internal paths in errors', async () => {
      // Test endpoints that might reveal internal paths
      const response = await apiContext.get(`${apiBase}/rest/bed/invalid-id/status`);
      const body = await response.text();

      const internalPathPatterns = [
        /\/home\//,
        /\/var\//,
        /\/opt\//,
        /\/usr\//,
        /C:\\Users/,
        /\.java:\d+/,
        /com\.sleepnumber\./,
        /com\.selectcomfort\./,
      ];

      console.log('\n[API] Internal path disclosure test:');
      for (const pattern of internalPathPatterns) {
        if (pattern.test(body)) {
          console.log(`[API] FOUND: ${pattern.toString()}`);
        }
      }
    });
  });

  test.describe('ECIM Error Disclosure', () => {
    const ecimBase = config.endpoints.prod.ecim;

    test('should not leak AWS internals in error responses', async () => {
      const ecimEndpoints = [
        '/health',
        '/admin',
        '/internal',
        '/api/users',
        '/metrics',
        '/graphql',
        '/nonexistent',
      ];

      for (const endpoint of ecimEndpoints) {
        const response = await apiContext.get(`${ecimBase}${endpoint}`);
        const headers = response.headers();
        const analysis = await analyzer.analyze(response);

        console.log(`\n[ECIM] Endpoint: ${endpoint}`);
        console.log(`[ECIM] Status: ${response.status()}`);

        // Check for AWS header disclosure
        const awsHeaders = Object.entries(headers).filter(([k]) =>
          k.toLowerCase().startsWith('x-amz') || k.toLowerCase().startsWith('x-amzn')
        );

        if (awsHeaders.length > 0) {
          console.log('[ECIM] AWS Headers exposed:');
          for (const [key, value] of awsHeaders) {
            console.log(`[ECIM]   ${key}: ${value}`);
          }
        }

        if (analysis.sensitiveHeaders.length > 0) {
          console.log('[ECIM] Sensitive headers:', analysis.sensitiveHeaders.map(h => h.header).join(', '));
        }
      }
    });
  });

  test.describe('HTTP Method Disclosure', () => {
    const apiBase = config.endpoints.prod.api;

    test('should not expose all HTTP methods via OPTIONS', async () => {
      const endpoints = ['/rest/login', '/rest/bed', '/rest/sleeper'];

      for (const endpoint of endpoints) {
        const response = await apiContext.fetch(`${apiBase}${endpoint}`, {
          method: 'OPTIONS',
        });

        const allowHeader = response.headers()['allow'];
        console.log(`\n[HTTP] OPTIONS ${endpoint}`);
        console.log(`[HTTP] Allow header: ${allowHeader}`);

        // Check for dangerous methods
        if (allowHeader) {
          if (allowHeader.includes('TRACE')) {
            console.log('[HTTP] WARNING: TRACE method enabled (XST risk)');
          }
          if (allowHeader.includes('DELETE')) {
            console.log('[HTTP] INFO: DELETE method available');
          }
        }
      }
    });

    test('should handle unexpected HTTP methods gracefully', async () => {
      // Skip CONNECT as it can hang (proxy method)
      const unusualMethods = ['TRACE', 'PROPFIND', 'MOVE', 'COPY'];

      for (const method of unusualMethods) {
        try {
          const response = await apiContext.fetch(`${apiBase}/rest/bed`, {
            method: method,
            timeout: 5000, // 5 second timeout per request
          });

          const body = await response.text();
          console.log(`\n[HTTP] ${method} /rest/bed: Status ${response.status()}`);

          // TRACE reflection check
          if (method === 'TRACE' && body.includes('TRACE')) {
            console.log('[HTTP] WARNING: TRACE method reflects request');
          }
        } catch (e) {
          console.log(`[HTTP] ${method}: Request failed or timed out (expected)`);
        }
      }
    });
  });

  test.describe('Content-Type Error Handling', () => {
    const apiBase = config.endpoints.prod.api;

    test('should handle wrong Content-Type gracefully', async () => {
      const contentTypes = [
        'application/xml',
        'text/html',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain',
        'application/octet-stream',
      ];

      for (const contentType of contentTypes) {
        const response = await apiContext.put(`${apiBase}/rest/login`, {
          data: '{"login":"test@test.com","password":"test"}',
          headers: { 'Content-Type': contentType },
        });

        const analysis = await analyzer.analyze(response);
        const body = await response.text();

        console.log(`\n[CT] Content-Type: ${contentType}`);
        console.log(`[CT] Status: ${response.status()}`);

        if (analysis.verboseErrors.length > 0) {
          console.log(`[CT] Verbose error detected`);
        }
      }
    });
  });

  test.describe('Debug/Trace Header Exposure', () => {
    const apiBase = config.endpoints.prod.api;

    test('should not expose debug info via special headers', async () => {
      const debugHeaders = [
        { 'X-Debug': 'true' },
        { 'X-Debug-Mode': '1' },
        { 'X-Trace': 'enabled' },
        { 'X-Development': 'true' },
        { 'Debug': 'true' },
        { 'X-Custom-Debug-Header': 'verbose' },
      ];

      for (const headers of debugHeaders) {
        const response = await apiContext.get(`${apiBase}/rest/bed`, {
          headers: {
            ...headers,
            'User-Agent': 'SleepIQ/5.3.30 Android',
          },
        });

        const responseHeaders = response.headers();
        const body = await response.text();

        console.log(`\n[DEBUG] Request headers: ${JSON.stringify(headers)}`);
        console.log(`[DEBUG] Status: ${response.status()}`);

        // Check if debug mode activated
        const debugResponseHeaders = Object.entries(responseHeaders).filter(([k]) =>
          k.toLowerCase().includes('debug') || k.toLowerCase().includes('trace')
        );

        if (debugResponseHeaders.length > 0) {
          console.log('[DEBUG] WARNING: Debug headers in response!');
          for (const [key, value] of debugResponseHeaders) {
            console.log(`[DEBUG]   ${key}: ${value}`);
          }
        }

        // Check for additional info in body
        if (body.length > 100 && response.status() === 401) {
          console.log('[DEBUG] Unusually verbose 401 response');
        }
      }
    });
  });
});
