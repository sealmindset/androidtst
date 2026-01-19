# External Integrations

**Analysis Date:** 2026-01-19

## APIs & External Services

**SleepIQ API (Target Under Test):**
- Primary API: `https://prod-api.sleepiq.sleepnumber.com`
- Legacy REST: `https://api.sleepiq.sleepnumber.com/rest`
- Web Portal: `https://sleepiq.sleepnumber.com`
- ECIM Service: `https://ecim.sleepnumber.com`
- BAM Service: `https://svcsleepiq.sleepnumber.com`

**Stage/QA Environments:**
- Stage API: `https://stage-api.sleepiq.sleepnumber.com`
- QA API: `https://qa-api.sleepiq.sleepnumber.com`
- ECIM Stage: `https://ecim-stage.sleepnumber.com`
- ECIM QA: `https://ecim-qa.sleepnumber.com`

**Google Play Store:**
- App installation via Play Store
- Package: `com.selectcomfort.SleepIQ`
- URL scheme: `market://details?id=com.selectcomfort.SleepIQ`

## Android Platform Integration

**ADB (Android Debug Bridge):**
- Device communication: USB and TCP/IP
- Shell command execution
- APK installation/extraction
- Screenshot capture (`screencap`)
- UI hierarchy dumping (`uiautomator dump`)
- Logcat monitoring

**Android Emulator:**
- AVD management via `avdmanager`
- System image: `android-34;google_apis_playstore;arm64-v8a`
- GPU passthrough: Host GPU
- Networking: NAT with host proxy support

**UI Automator:**
- UI hierarchy XML parsing
- Element identification by resource-id, text, content-desc
- Coordinate-based tap/swipe gestures

## Security Tool Integration

**Frida (Dynamic Instrumentation):**
- Purpose: SSL pinning bypass, traffic interception
- Scripts: `frida_ssl_bypass.js`, `frida_mixpanel_bypass.js`
- Hooks:
  - `com.android.org.conscrypt.TrustManagerImpl.verifyChain`
  - `javax.net.ssl.SSLContext.init`
  - `okhttp3.CertificatePinner.check`
  - `javax.net.ssl.HttpsURLConnection` methods
  - Mixpanel SDK classes

**Burp Suite (HTTP Proxy):**
- Proxy address: `http://127.0.0.1:8080`
- Purpose: HTTP/S traffic interception and analysis
- Integration: Playwright routes all traffic through proxy
- Certificate: Playwright ignores HTTPS errors for Burp's cert
- Traffic identification: Custom `X-Security-Test` header

## Data Storage

**Local File Storage:**
- Screenshots: `./screenshots/` directory
- APK extraction: `./apks/` directory
- UI hierarchy: `./ui_hierarchy.xml`
- JWT tokens: `/tmp/jwt_token.txt`
- Session cookies: `/tmp/test_cookies.txt`
- Emulator logs: `/tmp/emulator.log`

**Test Results:**
- Playwright HTML reports: `playwright-burp-harness/test-results/`
- JSON results: `playwright-burp-harness/test-results/results.json`

**No Database:**
- All state is ephemeral
- No persistent database storage

## Authentication & Identity

**SleepIQ Authentication:**
- Login endpoint: `PUT /rest/login`
- Credentials: JSON body `{"login": "email", "password": "password"}`
- Session: `JSESSIONID` cookie
- JWT: Extracted from app logs or network traffic
- Headers required:
  - `X-App-Version: 5.3.30`
  - `X-App-Platform: android`
  - `User-Agent: okhttp/4.12.0`

**Test Credentials:**
- Stored in `test_idor.py` (line 16-18)
- WARNING: Hardcoded credentials in source code

## Monitoring & Observability

**Logging:**
- Android logcat for app monitoring
- Frida console output for hook activity
- Python print statements for test progress
- Playwright test output (list, HTML, JSON reporters)

**Traffic Analysis:**
- Burp Suite captures all HTTP/S traffic
- Playwright traces stored in test-results
- Screenshots and videos captured per test

**Error Tracking:**
- None configured
- Manual review of test output required

## CI/CD & Deployment

**Hosting:**
- Local development environment only
- No cloud deployment

**CI Pipeline:**
- None configured
- Manual script execution

**Automation Scripts:**
- `setup.sh` - Initial environment setup
- `start-emulator.sh` - Launch Android emulator
- `install-sleepiq.sh` - Install target app
- `run-tests.sh` - Execute test harness
- `connect-device.sh` - Physical device connection
- `extract-apk.sh` - APK extraction from device

## Environment Configuration

**Required Environment Variables:**
```bash
ANDROID_SDK_ROOT="$HOME/Library/Android/sdk"
ANDROID_HOME="$ANDROID_SDK_ROOT"
PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
```

**Shell Profile:**
- Automatically added to `~/.zshrc` by `setup.sh`

**Test Configuration:**
- `playwright-burp-harness/utils/config.ts` - API endpoints, test IDs, patterns
- `playwright-burp-harness/playwright.config.ts` - Playwright settings

## Network Endpoints Tested

**REST API Paths:**
```
/rest/login
/rest/user/jwt
/rest/registration
/rest/bed
/rest/bed/{bedId}/status
/rest/bed/{bedId}/pauseMode
/rest/bed/{bedId}/pump/status
/rest/bed/{bedId}/sleepNumber
/rest/bed/{bedId}/foundation/*
/rest/sleeper
/rest/sleeper/{sleeperId}/profile
/rest/sleeper/{sleeperId}/health
/rest/sleepData
/rest/sleepSliceData
/rest/sleepData/editedHidden
/rest/accounts/{accountId}/sleepers/{sleeperId}
/rest/feedback
```

**BAMKey Protocol:**
```
/sn/v1/accounts/{accountId}/beds/{bedId}/bamkey
/sn/v1/sleeper/{sleeperId}/sleepData/30DaysRolling
```

**Legacy BAM Endpoints:**
```
/bam/device/getTime.jsp
/bam/device/getConfig.jsp
/bam/device/getSoftware.jsp
```

**ECIM Endpoints:**
```
/ping
/health
/admin
/internal
/api/users
/api/beds
/metrics
/graphql
```

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None

## Third-Party SDK Monitoring

**Mixpanel:**
- Frida hooks monitor Mixpanel traffic
- SSL bypass specifically targets Mixpanel SDK
- URL pattern: `*mixpanel*`

---

*Integration audit: 2026-01-19*
