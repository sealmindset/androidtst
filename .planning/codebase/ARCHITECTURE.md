# Architecture

**Analysis Date:** 2026-01-19

## Pattern Overview

**Overall:** Multi-layer Security Test Harness with Dual Entry Points

**Key Characteristics:**
- Shell scripts for environment setup and interactive testing
- Python automation layer for programmatic Android/ADB interaction
- Playwright/TypeScript harness for HTTP-level API security testing
- Frida scripts for runtime mobile app instrumentation
- All components target the SleepIQ Android application and its backend APIs

## Layers

**Environment Setup Layer:**
- Purpose: Bootstrap Android SDK, emulator, and development environment
- Location: `setup.sh`
- Contains: Android SDK installation, AVD creation, PATH configuration
- Depends on: Homebrew (for Java), network (for SDK download)
- Used by: All other components (must run first)

**Emulator Management Layer:**
- Purpose: Start/manage Android emulator instances
- Location: `start-emulator.sh`
- Contains: Emulator launch with GPU acceleration, boot detection
- Depends on: Setup layer (ANDROID_SDK_ROOT, AVD)
- Used by: Test harness scripts, physical device connection

**Device Interaction Layer:**
- Purpose: Connect to physical Android devices for Bluetooth testing
- Location: `connect-device.sh`
- Contains: ADB device detection, Bluetooth status checks, device info
- Depends on: ADB (from setup)
- Used by: Physical device testing workflows

**App Management Layer:**
- Purpose: Install and manage SleepIQ app on device/emulator
- Location: `install-sleepiq.sh`, `extract-apk.sh`
- Contains: Play Store navigation, APK extraction from installed apps
- Depends on: Running emulator or connected device
- Used by: Test preparation workflows

**Shell Test Harness Layer:**
- Purpose: Interactive UI automation via command line
- Location: `run-tests.sh`
- Contains: Screenshot capture, UI hierarchy dump, input simulation, gesture commands
- Depends on: Running emulator with SleepIQ installed
- Used by: Manual testing, exploration

**Python Test Harness Layer:**
- Purpose: Programmatic Android test automation
- Location: `test_harness.py`
- Contains: ADBWrapper class, UIAutomator class, SleepIQTestHarness class
- Depends on: ADB, running emulator/device
- Used by: Automated test scripts, vulnerability testing

**Security Testing Layer:**
- Purpose: IDOR and API vulnerability validation
- Location: `test_idor.py`
- Contains: JWT extraction from logcat, API authentication, IDOR testing
- Depends on: Python harness, running app with logged-in user
- Used by: Security assessment workflows

**Playwright API Testing Layer:**
- Purpose: HTTP-level API security testing through Burp proxy
- Location: `playwright-burp-harness/`
- Contains: Playwright test suites, response analysis utilities
- Depends on: Node.js, Burp Suite (localhost:8080)
- Used by: Comprehensive API security testing

**Frida Instrumentation Layer:**
- Purpose: Runtime SSL pinning bypass and traffic interception
- Location: `frida_ssl_bypass.js`, `frida_mixpanel_bypass.js`
- Contains: TrustManager hooks, SSLContext bypasses, certificate pinner disabling
- Depends on: Frida, rooted device or Frida-gadget
- Used by: Traffic interception when app uses certificate pinning

## Data Flow

**Emulator Test Flow:**

1. `setup.sh` installs Android SDK and creates AVD
2. `start-emulator.sh` launches emulator and waits for boot
3. `install-sleepiq.sh` installs SleepIQ via Play Store
4. `run-tests.sh` or `test_harness.py` interacts with app via ADB
5. Screenshots saved to `screenshots/` directory

**Physical Device Test Flow:**

1. User enables USB debugging on Android device
2. `connect-device.sh` detects device and displays info
3. `test_harness.py` or `run-tests.sh` interacts with device
4. Bluetooth testing available on physical devices

**IDOR Vulnerability Test Flow:**

1. User logs into SleepIQ app on emulator/device
2. `test_idor.py` monitors logcat for JWT token (15 seconds)
3. Script authenticates to API with test credentials
4. Script attempts to access other users' sleeper IDs
5. Results indicate if IDOR vulnerability is confirmed

**Playwright API Security Test Flow:**

1. Burp Suite started on localhost:8080
2. `npm test` runs Playwright tests
3. All HTTP traffic routes through Burp proxy
4. Tests check authentication, IDOR, error disclosure
5. `ResponseAnalyzer` detects sensitive data in responses
6. Results output to console and `test-results/` directory

**State Management:**
- No persistent state between test runs
- JWT tokens temporarily stored in `/tmp/jwt_token.txt`
- Session cookies stored in `/tmp/test_cookies.txt`
- Screenshots accumulated in `screenshots/` directory

## Key Abstractions

**ADBWrapper (`test_harness.py`):**
- Purpose: Encapsulate all ADB command execution
- Examples: `test_harness.py` lines 47-157
- Pattern: Method-per-command with subprocess execution

**UIAutomator (`test_harness.py`):**
- Purpose: Parse UI hierarchy XML and locate elements
- Examples: `test_harness.py` lines 159-273
- Pattern: Element search with caching, automatic refresh

**UIElement (`test_harness.py`):**
- Purpose: Represent Android UI elements with bounds and properties
- Examples: `test_harness.py` lines 27-44
- Pattern: Dataclass with computed center property

**SleepIQTestHarness (`test_harness.py`):**
- Purpose: SleepIQ-specific test orchestration
- Examples: `test_harness.py` lines 275-403
- Pattern: Facade combining ADB and UI automation

**ResponseAnalyzer (`playwright-burp-harness/utils/response-analyzer.ts`):**
- Purpose: Detect sensitive data patterns in HTTP responses
- Examples: `response-analyzer.ts` lines 34-378
- Pattern: Regex pattern matching with severity classification

**Config (`playwright-burp-harness/utils/config.ts`):**
- Purpose: Centralize API endpoints, test IDs, and patterns
- Examples: `config.ts` lines 8-160
- Pattern: Typed configuration object with nested structure

## Entry Points

**Setup Entry Point:**
- Location: `setup.sh`
- Triggers: Manual execution (one-time setup)
- Responsibilities: Install Android SDK, create AVD, configure shell environment

**Emulator Entry Point:**
- Location: `start-emulator.sh`
- Triggers: Manual execution before testing
- Responsibilities: Launch emulator, wait for boot, display device info

**Device Connection Entry Point:**
- Location: `connect-device.sh`
- Triggers: Manual execution for physical device testing
- Responsibilities: Detect USB device, display info, check Bluetooth status

**App Installation Entry Point:**
- Location: `install-sleepiq.sh`
- Triggers: Manual execution after emulator started
- Responsibilities: Open Play Store to SleepIQ page, guide user through install

**APK Extraction Entry Point:**
- Location: `extract-apk.sh`
- Triggers: Manual execution with optional package name argument
- Responsibilities: Pull APK from device, save to `apks/` directory

**Interactive Shell Testing Entry Point:**
- Location: `run-tests.sh`
- Triggers: Manual execution for interactive testing
- Responsibilities: Launch app, provide REPL for commands (screenshot, tap, text, etc.)

**Python Testing Entry Point:**
- Location: `test_harness.py` (run as main)
- Triggers: `python3 test_harness.py`
- Responsibilities: Interactive menu for app control and automated tests

**IDOR Testing Entry Point:**
- Location: `test_idor.py`
- Triggers: `python3 test_idor.py`
- Responsibilities: Extract JWT, authenticate, test IDOR vulnerabilities

**Playwright Testing Entry Point:**
- Location: `playwright-burp-harness/` (npm scripts)
- Triggers: `npm test`, `npm run test:auth`, `npm run test:idor`, etc.
- Responsibilities: Run HTTP-level security tests through Burp proxy

## Error Handling

**Strategy:** Fail-fast with descriptive error messages

**Patterns:**
- Shell scripts use `set -e` to exit on any command failure
- Device/emulator presence checked before operations begin
- App installation verified before test execution
- Python subprocess errors captured and displayed
- Playwright tests use explicit assertions with descriptive failure messages

**Shell Script Error Handling:**
```bash
# Check if emulator is running
if ! adb devices | grep -q "emulator"; then
    echo "ERROR: No emulator running. Start it first with: ./start-emulator.sh"
    exit 1
fi
```

**Python Error Handling:**
```python
def wait_for_device(self, timeout: int = 60):
    """Wait for device to be ready."""
    self.run("wait-for-device")
    start = time.time()
    while time.time() - start < timeout:
        boot_completed = self.shell("getprop sys.boot_completed")
        if boot_completed == "1":
            return True
        time.sleep(2)
    raise TimeoutError("Device did not boot within timeout")
```

## Cross-Cutting Concerns

**Logging:**
- Shell scripts: `echo` statements with section headers (`===`)
- Python: `print()` statements with prefixes (`[IDOR]`, `[*]`, etc.)
- Playwright: Console output with test prefixes, HTML reports

**Validation:**
- Device connectivity checked at start of each script
- App installation verified before testing
- Emulator boot completion polled via `sys.boot_completed` property

**Authentication:**
- Test credentials stored in `test_idor.py` (lines 16-18)
- JWT tokens extracted from Android logcat
- Session cookies managed via curl cookie jars
- Playwright tests add custom headers for Burp filtering

**Configuration:**
- Android SDK path: `$HOME/Library/Android/sdk`
- Target package: `com.selectcomfort.SleepIQ`
- API base URL: `https://api.sleepiq.sleepnumber.com/rest`
- Burp proxy: `127.0.0.1:8080`
- AVD name: `SleepIQ_Test_Device`

---

*Architecture analysis: 2026-01-19*
