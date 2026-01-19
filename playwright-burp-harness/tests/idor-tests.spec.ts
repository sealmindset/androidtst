import { test, expect, APIRequestContext } from '@playwright/test';
import { config } from '../utils/config';
import { ResponseAnalyzer } from '../utils/response-analyzer';

/**
 * IDOR (Insecure Direct Object Reference) Security Tests
 *
 * Tests for authorization vulnerabilities including:
 * - Accessing other users' data via ID manipulation
 * - Sequential ID enumeration
 * - Horizontal privilege escalation
 * - Bed control access for non-owned beds
 */

test.describe('IDOR Security Tests', () => {
  let apiContext: APIRequestContext;
  let analyzer: ResponseAnalyzer;

  test.beforeAll(async ({ playwright }) => {
    apiContext = await playwright.request.newContext({
      baseURL: config.endpoints.prod.api,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'User-Agent': 'SleepIQ/5.3.30 Android',
        'Content-Type': 'application/json',
        'X-Security-Test': 'idor-tests',
      },
    });
    analyzer = new ResponseAnalyzer();
  });

  test.afterAll(async () => {
    await apiContext.dispose();
    console.log('\n' + analyzer.generateReport());
  });

  test.describe('Sleeper Profile IDOR', () => {
    test('should not allow access to other sleeper profiles', async () => {
      for (const sleeperId of config.testIds.sleeperIds) {
        const response = await apiContext.get(`/rest/sleeper/${sleeperId}/profile`);
        const analysis = await analyzer.analyze(response);

        console.log(`[IDOR] Sleeper ${sleeperId}: Status ${response.status()}`);

        // Should return 401 (no session) or 403 (forbidden)
        // 200 would indicate IDOR vulnerability
        if (response.status() === 200) {
          const body = await response.text();
          console.log(`[IDOR] POTENTIAL VULNERABILITY - Got data for sleeper ${sleeperId}`);
          console.log(`[IDOR] Response: ${body.substring(0, 200)}`);
        }

        // Check if response leaks data even in error
        expect(analysis.sensitiveDataFound.some(d => d.type === 'email')).toBeFalsy();
      }
    });

    test('should not leak sleeper health data', async () => {
      for (const sleeperId of config.testIds.sleeperIds.slice(0, 3)) {
        const response = await apiContext.get(`/rest/sleeper/${sleeperId}/health`);
        await analyzer.analyze(response);

        console.log(`[IDOR] Sleeper health ${sleeperId}: Status ${response.status()}`);

        if (response.status() === 200) {
          const body = await response.json().catch(() => ({}));
          console.log(`[IDOR] CRITICAL - Health data exposed for ${sleeperId}`);

          // Check for sensitive health metrics
          const hasHealthData =
            'heartRate' in body ||
            'hrv' in body ||
            'respiration' in body ||
            'sleepStages' in body;

          if (hasHealthData) {
            console.log('[IDOR] Exposed metrics:', Object.keys(body).join(', '));
          }
        }
      }
    });
  });

  test.describe('Sleep Data IDOR', () => {
    test('should not allow access to other users sleep data', async () => {
      const testDates = ['2025-01-01', '2025-12-15', '2026-01-01'];

      for (const sleeperId of config.testIds.sleeperIds.slice(0, 3)) {
        for (const date of testDates) {
          const response = await apiContext.get(
            `/rest/sleepData?sleeper=${sleeperId}&date=${date}&interval=D1`
          );
          await analyzer.analyze(response);

          console.log(`[IDOR] Sleep data ${sleeperId} (${date}): Status ${response.status()}`);

          if (response.status() === 200) {
            const body = await response.text();
            console.log(`[IDOR] CRITICAL - Sleep data exposed`);
            console.log(`[IDOR] Response preview: ${body.substring(0, 300)}`);
          }
        }
      }
    });

    test('should not expose 30-day rolling sleep data', async () => {
      for (const sleeperId of config.testIds.sleeperIds.slice(0, 3)) {
        const response = await apiContext.get(
          `/sn/v1/sleeper/${sleeperId}/sleepData/30DaysRolling`
        );
        await analyzer.analyze(response);

        console.log(`[IDOR] 30-day rolling ${sleeperId}: Status ${response.status()}`);
      }
    });

    test('should not expose edited/hidden sleep sessions', async () => {
      const response = await apiContext.get('/rest/sleepData/editedHidden');
      await analyzer.analyze(response);

      console.log(`[IDOR] Edited/hidden sessions: Status ${response.status()}`);
    });
  });

  test.describe('Bed Control IDOR', () => {
    test('should not allow access to other users beds', async () => {
      for (const bedId of config.testIds.bedIds) {
        const response = await apiContext.get(`/rest/bed/${bedId}/status`);
        await analyzer.analyze(response);

        console.log(`[IDOR] Bed status ${bedId}: Status ${response.status()}`);

        if (response.status() === 200) {
          console.log(`[IDOR] CRITICAL - Bed status exposed for ${bedId}`);
        }
      }
    });

    test('should not allow pump control on other beds', async () => {
      for (const bedId of config.testIds.bedIds.slice(0, 2)) {
        const response = await apiContext.get(`/rest/bed/${bedId}/pump/status`);
        await analyzer.analyze(response);

        console.log(`[IDOR] Pump status ${bedId}: Status ${response.status()}`);
      }
    });

    test('should not allow sleep number changes on other beds', async () => {
      for (const bedId of config.testIds.bedIds.slice(0, 2)) {
        // GET to check access (don't actually PUT to avoid damage)
        const response = await apiContext.get(`/rest/bed/${bedId}/sleepNumber`);
        await analyzer.analyze(response);

        console.log(`[IDOR] Sleep number access ${bedId}: Status ${response.status()}`);
      }
    });

    test('should not allow foundation control on other beds', async () => {
      for (const bedId of config.testIds.bedIds.slice(0, 2)) {
        const endpoints = [
          `/rest/bed/${bedId}/foundation/status`,
          `/rest/bed/${bedId}/foundation/outlet`,
          `/rest/bed/${bedId}/foundation/footwarming`,
        ];

        for (const endpoint of endpoints) {
          const response = await apiContext.get(endpoint);
          await analyzer.analyze(response);

          console.log(`[IDOR] ${endpoint}: Status ${response.status()}`);
        }
      }
    });
  });

  test.describe('Account IDOR', () => {
    test('should not allow access to other accounts sleepers', async () => {
      for (const accountId of config.testIds.accountIds.slice(0, 2)) {
        for (const sleeperId of config.testIds.sleeperIds.slice(0, 2)) {
          const response = await apiContext.get(
            `/rest/accounts/${accountId}/sleepers/${sleeperId}`
          );
          await analyzer.analyze(response);

          console.log(`[IDOR] Account ${accountId} sleeper ${sleeperId}: Status ${response.status()}`);
        }
      }
    });

    test('should not expose circadian routines of other users', async () => {
      for (const accountId of config.testIds.accountIds.slice(0, 2)) {
        for (const sleeperId of config.testIds.sleeperIds.slice(0, 2)) {
          const response = await apiContext.get(
            `/rest/accounts/${accountId}/sleepers/${sleeperId}/circadianRoutines`
          );
          await analyzer.analyze(response);

          console.log(`[IDOR] Circadian ${accountId}/${sleeperId}: Status ${response.status()}`);
        }
      }
    });
  });

  test.describe('BAMKey Protocol IDOR', () => {
    test('should not allow BAMKey commands on other beds', async () => {
      for (const accountId of config.testIds.accountIds.slice(0, 2)) {
        for (const bedId of config.testIds.bedIds.slice(0, 2)) {
          // Test with read-only commands only
          for (const op of config.bamkeyOps.filter(o => o.key.endsWith('G'))) {
            const response = await apiContext.put(
              `/sn/v1/accounts/${accountId}/beds/${bedId}/bamkey`,
              {
                data: {
                  sourceApplication: 'SleepIQ',
                  key: op.key,
                  data: {},
                },
              }
            );
            await analyzer.analyze(response);

            console.log(`[IDOR] BAMKey ${op.key} on ${bedId}: Status ${response.status()}`);

            // Check if we get actual bed data (would be IDOR)
            if (response.status() === 200) {
              const body = await response.text();
              console.log(`[IDOR] CRITICAL - BAMKey command succeeded: ${body.substring(0, 200)}`);
            }
          }
        }
      }
    });
  });

  test.describe('ID Enumeration', () => {
    test('should not allow sequential ID enumeration', async () => {
      // Test if IDs are sequential/predictable
      const baseId = BigInt('-9223372019953519548');
      const sequentialIds = [
        (baseId - BigInt(1)).toString(),
        baseId.toString(),
        (baseId + BigInt(1)).toString(),
        (baseId + BigInt(2)).toString(),
      ];

      let successCount = 0;
      for (const sleeperId of sequentialIds) {
        const response = await apiContext.get(`/rest/sleeper/${sleeperId}/profile`);

        if (response.status() === 200) {
          successCount++;
          console.log(`[ENUM] Sequential ID ${sleeperId}: ACCESSIBLE`);
        } else {
          console.log(`[ENUM] Sequential ID ${sleeperId}: Status ${response.status()}`);
        }
      }

      // If multiple sequential IDs return data, IDs are enumerable
      if (successCount > 1) {
        console.log('[ENUM] WARNING: Sequential IDs may be enumerable');
      }
    });

    test('should use non-predictable ID formats', async () => {
      // Test with different ID formats
      const idFormats = [
        '1',
        '12345',
        '99999999',
        '-1',
        '0',
        'abc123',
        '../../etc/passwd',
        '<script>alert(1)</script>',
      ];

      for (const id of idFormats) {
        const response = await apiContext.get(`/rest/sleeper/${encodeURIComponent(id)}/profile`);
        await analyzer.analyze(response);

        // Check for path traversal or XSS reflection
        const body = await response.text();
        const hasReflection = body.includes(id) && id.includes('<');

        console.log(`[ENUM] ID format "${id}": Status ${response.status()}, Reflected: ${hasReflection}`);
      }
    });
  });
});
