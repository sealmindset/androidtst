# Playwright + Burp Security Test Harness

Security testing harness for SleepIQ API that routes all traffic through Burp Suite for capture and analysis.

## Prerequisites

1. **Burp Suite** running on `localhost:8080`
2. **Node.js** v18 or higher
3. **Playwright browsers** installed

## Setup

```bash
# Install dependencies
npm install

# Install Playwright browsers (if not already done)
npx playwright install chromium
```

## Running Tests

### Start Burp Suite First!

Ensure Burp Suite is running and listening on port 8080 before running tests.

```bash
# Check if Burp is running
npm run check-burp
```

### Run All Tests

```bash
npm test
```

### Run Specific Test Suites

```bash
# Authentication security tests
npm run test:auth

# IDOR (authorization) tests
npm run test:idor

# Error disclosure tests
npm run test:error

# API tests
npm run test:api
```

### Debug Mode

```bash
# Run with browser visible
npm run test:headed

# Run with Playwright inspector
npm run test:debug
```

### View Report

```bash
npm run report
```

## Test Suites

### 1. Authentication Tests (`auth-flows.spec.ts`)
- Login enumeration prevention
- SQL injection handling
- Rate limiting detection
- JWT token security
- Session cookie security
- Malformed request handling

### 2. IDOR Tests (`idor-tests.spec.ts`)
- Sleeper profile access control
- Sleep data authorization
- Bed control authorization
- Account data isolation
- BAMKey protocol access control
- ID enumeration prevention

### 3. Error Disclosure Tests (`error-disclosure.spec.ts`)
- Legacy BAM endpoint disclosure
- REST API error handling
- ECIM header exposure
- HTTP method disclosure
- Debug header detection
- Content-Type handling

## Burp Integration

All traffic is routed through Burp proxy at `127.0.0.1:8080`. Tests include:

- Custom `X-Security-Test` header to identify test traffic
- Timestamp header for correlating test runs
- Full request/response capture
- SSL certificate bypass for HTTPS interception

### Filtering Test Traffic in Burp

Use Burp's filter to show only test traffic:
```
X-Security-Test: playwright-burp-harness
```

## Configuration

Edit `utils/config.ts` to modify:
- API endpoints (prod, stage, qa)
- Test IDs for IDOR testing
- Sensitive data patterns
- BAMKey operations to test

## Output

### Test Results
- `test-results/` - HTML report, screenshots, traces
- `test-results/results.json` - JSON test results

### Console Output
- Real-time findings logged to console
- Summary report after each test suite

## Security Notes

- Tests use read-only operations where possible
- No destructive BAMKey commands are executed
- Test accounts should be used when valid credentials needed
- All traffic is captured in Burp for review

## Sample Output

```
[AUTH] Login enumeration test: SECURE
[AUTH] SQL injection "' OR '1'='1...": Status 400
[IDOR] Sleeper -9223372019953519548: Status 401
[BAM] getSoftware.jsp: WARNING: Internal API structure leaked!
[ECIM] AWS Headers exposed: x-amzn-requestid, x-amz-apigw-id
```

## Troubleshooting

### Tests fail with connection errors
- Ensure Burp Suite is running on port 8080
- Check Burp's proxy listener is active

### SSL errors
- Tests ignore SSL errors by default (for Burp's certificate)
- If issues persist, install Burp's CA certificate

### Tests timeout
- Increase timeout in `playwright.config.ts`
- Check network connectivity through Burp

## Files

```
playwright-burp-harness/
├── playwright.config.ts      # Playwright + Burp configuration
├── package.json              # Dependencies and scripts
├── README.md                 # This file
├── tests/
│   ├── auth-flows.spec.ts    # Authentication tests
│   ├── idor-tests.spec.ts    # IDOR/authorization tests
│   └── error-disclosure.spec.ts  # Error disclosure tests
└── utils/
    ├── config.ts             # Test configuration
    └── response-analyzer.ts  # Response analysis utilities
```
