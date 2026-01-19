import { APIResponse } from '@playwright/test';
import { config } from './config';

/**
 * Response Analyzer for Security Testing
 *
 * Analyzes API responses for sensitive data leakage, verbose errors,
 * and business logic issues.
 */

export interface AnalysisResult {
  url: string;
  status: number;
  sensitiveDataFound: SensitiveDataMatch[];
  sensitiveHeaders: HeaderMatch[];
  verboseErrors: string[];
  extraFields: string[];
  recommendations: string[];
}

export interface SensitiveDataMatch {
  type: string;
  pattern: string;
  matches: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface HeaderMatch {
  header: string;
  value: string;
  severity: 'high' | 'medium' | 'low';
}

export class ResponseAnalyzer {
  private results: AnalysisResult[] = [];

  /**
   * Analyze an API response for security issues
   */
  async analyze(response: APIResponse): Promise<AnalysisResult> {
    const url = response.url();
    const status = response.status();
    const headers = response.headers();

    let body = '';
    try {
      body = await response.text();
    } catch (e) {
      body = '';
    }

    const result: AnalysisResult = {
      url,
      status,
      sensitiveDataFound: [],
      sensitiveHeaders: [],
      verboseErrors: [],
      extraFields: [],
      recommendations: [],
    };

    // Check for sensitive data patterns in body
    this.checkSensitivePatterns(body, result);

    // Check for sensitive headers
    this.checkHeaders(headers, result);

    // Check for verbose error messages
    this.checkVerboseErrors(body, status, result);

    // Check for unexpected fields in JSON
    await this.checkExtraFields(body, result);

    // Generate recommendations
    this.generateRecommendations(result);

    this.results.push(result);
    return result;
  }

  /**
   * Check response body for sensitive data patterns
   */
  private checkSensitivePatterns(body: string, result: AnalysisResult): void {
    const patterns = config.sensitivePatterns;

    // Email addresses
    const emails = body.match(patterns.email);
    if (emails && emails.length > 0) {
      result.sensitiveDataFound.push({
        type: 'email',
        pattern: 'Email Address',
        matches: [...new Set(emails)],
        severity: 'high',
      });
    }

    // Stack traces
    const stackTraces = body.match(patterns.stackTrace);
    if (stackTraces && stackTraces.length > 0) {
      result.sensitiveDataFound.push({
        type: 'stackTrace',
        pattern: 'Stack Trace',
        matches: stackTraces.slice(0, 5), // Limit matches
        severity: 'critical',
      });
    }

    // Internal paths
    const paths = body.match(patterns.internalPath);
    if (paths && paths.length > 0) {
      result.sensitiveDataFound.push({
        type: 'internalPath',
        pattern: 'Internal Path',
        matches: [...new Set(paths)],
        severity: 'medium',
      });
    }

    // SQL errors
    const sqlErrors = body.match(patterns.sqlError);
    if (sqlErrors && sqlErrors.length > 0) {
      result.sensitiveDataFound.push({
        type: 'sqlError',
        pattern: 'SQL Error',
        matches: [...new Set(sqlErrors)],
        severity: 'critical',
      });
    }

    // Java exceptions
    const javaExceptions = body.match(patterns.javaException);
    if (javaExceptions && javaExceptions.length > 0) {
      result.sensitiveDataFound.push({
        type: 'javaException',
        pattern: 'Java Exception',
        matches: [...new Set(javaExceptions)],
        severity: 'high',
      });
    }

    // API keys/tokens (be careful not to flag test tokens)
    const apiKeys = body.match(patterns.apiKey);
    if (apiKeys && apiKeys.length > 0) {
      result.sensitiveDataFound.push({
        type: 'apiKey',
        pattern: 'API Key',
        matches: apiKeys.map(k => k.substring(0, 20) + '...'),
        severity: 'critical',
      });
    }
  }

  /**
   * Check response headers for information disclosure
   */
  private checkHeaders(headers: { [key: string]: string }, result: AnalysisResult): void {
    for (const sensitiveHeader of config.sensitiveHeaders) {
      const headerValue = headers[sensitiveHeader.toLowerCase()];
      if (headerValue) {
        let severity: 'high' | 'medium' | 'low' = 'low';

        // AWS internal headers are medium severity
        if (sensitiveHeader.startsWith('x-amz')) {
          severity = 'medium';
        }
        // Debug headers are high severity
        if (sensitiveHeader.includes('debug') || sensitiveHeader.includes('trace')) {
          severity = 'high';
        }

        result.sensitiveHeaders.push({
          header: sensitiveHeader,
          value: headerValue,
          severity,
        });
      }
    }

    // Check for verbose Server header
    const serverHeader = headers['server'];
    if (serverHeader && serverHeader.length > 20) {
      result.sensitiveHeaders.push({
        header: 'server',
        value: serverHeader,
        severity: 'low',
      });
    }
  }

  /**
   * Check for verbose error messages
   */
  private checkVerboseErrors(body: string, status: number, result: AnalysisResult): void {
    // Only check error responses
    if (status < 400) return;

    try {
      const json = JSON.parse(body);
      const errorMessages = this.extractErrorMessages(json);

      for (const msg of errorMessages) {
        // Check if error message reveals internal details
        if (
          msg.includes('Exception') ||
          msg.includes('Stack') ||
          msg.includes('/') ||
          msg.includes('null') ||
          msg.includes('undefined') ||
          msg.length > 100
        ) {
          result.verboseErrors.push(msg);
        }
      }
    } catch (e) {
      // Check non-JSON error responses
      if (body.includes('Exception') || body.includes('Error:') || body.includes('at ')) {
        result.verboseErrors.push(body.substring(0, 500));
      }
    }
  }

  /**
   * Extract error messages from JSON response
   */
  private extractErrorMessages(obj: any, messages: string[] = []): string[] {
    if (typeof obj === 'string') {
      messages.push(obj);
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key of Object.keys(obj)) {
        if (
          key.toLowerCase().includes('error') ||
          key.toLowerCase().includes('message') ||
          key.toLowerCase().includes('detail')
        ) {
          if (typeof obj[key] === 'string') {
            messages.push(obj[key]);
          } else {
            this.extractErrorMessages(obj[key], messages);
          }
        }
      }
    }
    return messages;
  }

  /**
   * Check for unexpected/extra fields in JSON responses
   */
  private async checkExtraFields(body: string, result: AnalysisResult): Promise<void> {
    try {
      const json = JSON.parse(body);

      // Look for fields that might indicate internal data
      const suspiciousFields = [
        'debug', 'internal', 'admin', 'password', 'secret',
        'key', 'token', 'hash', 'salt', 'private',
        'ssn', 'creditCard', 'bankAccount',
        '_id', '__v', 'createdBy', 'modifiedBy',
      ];

      const foundFields = this.findFields(json, suspiciousFields);
      result.extraFields = foundFields;
    } catch (e) {
      // Not JSON, skip
    }
  }

  /**
   * Recursively find suspicious fields in JSON
   */
  private findFields(obj: any, suspiciousFields: string[], path = ''): string[] {
    const found: string[] = [];

    if (typeof obj === 'object' && obj !== null) {
      for (const key of Object.keys(obj)) {
        const currentPath = path ? `${path}.${key}` : key;

        if (suspiciousFields.some(f => key.toLowerCase().includes(f))) {
          found.push(currentPath);
        }

        if (typeof obj[key] === 'object') {
          found.push(...this.findFields(obj[key], suspiciousFields, currentPath));
        }
      }
    }

    return found;
  }

  /**
   * Generate security recommendations based on findings
   */
  private generateRecommendations(result: AnalysisResult): void {
    if (result.sensitiveDataFound.some(d => d.severity === 'critical')) {
      result.recommendations.push('CRITICAL: Remove sensitive data from API responses immediately');
    }

    if (result.verboseErrors.length > 0) {
      result.recommendations.push('Implement generic error messages for production');
    }

    if (result.sensitiveHeaders.length > 0) {
      result.recommendations.push('Suppress internal headers (X-Amzn-*, Server version)');
    }

    if (result.extraFields.length > 0) {
      result.recommendations.push('Review API responses for unnecessary field exposure');
    }
  }

  /**
   * Get all analysis results
   */
  getResults(): AnalysisResult[] {
    return this.results;
  }

  /**
   * Generate summary report
   */
  generateReport(): string {
    let report = '# Security Analysis Report\n\n';
    report += `Total Requests Analyzed: ${this.results.length}\n\n`;

    const criticalFindings = this.results.filter(r =>
      r.sensitiveDataFound.some(d => d.severity === 'critical')
    );
    const highFindings = this.results.filter(r =>
      r.sensitiveDataFound.some(d => d.severity === 'high')
    );

    report += `## Summary\n`;
    report += `- Critical Findings: ${criticalFindings.length}\n`;
    report += `- High Findings: ${highFindings.length}\n`;
    report += `- Verbose Errors: ${this.results.filter(r => r.verboseErrors.length > 0).length}\n\n`;

    report += `## Detailed Findings\n\n`;

    for (const result of this.results) {
      if (
        result.sensitiveDataFound.length > 0 ||
        result.verboseErrors.length > 0 ||
        result.extraFields.length > 0
      ) {
        report += `### ${result.url}\n`;
        report += `Status: ${result.status}\n\n`;

        if (result.sensitiveDataFound.length > 0) {
          report += `**Sensitive Data:**\n`;
          for (const data of result.sensitiveDataFound) {
            report += `- [${data.severity.toUpperCase()}] ${data.pattern}: ${data.matches.length} matches\n`;
          }
          report += '\n';
        }

        if (result.verboseErrors.length > 0) {
          report += `**Verbose Errors:**\n`;
          for (const error of result.verboseErrors) {
            report += `- ${error.substring(0, 100)}...\n`;
          }
          report += '\n';
        }

        if (result.recommendations.length > 0) {
          report += `**Recommendations:**\n`;
          for (const rec of result.recommendations) {
            report += `- ${rec}\n`;
          }
          report += '\n';
        }
      }
    }

    return report;
  }
}
