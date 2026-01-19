# Codebase Structure

**Analysis Date:** 2026-01-19

## Directory Layout

```
android/
├── .git/                           # Git repository
├── .planning/                      # Planning documents
│   └── codebase/                   # Architecture documentation
├── playwright-burp-harness/        # Playwright API security testing
│   ├── node_modules/               # NPM dependencies
│   ├── test-results/               # Test output (HTML, JSON, traces)
│   ├── tests/                      # Playwright test suites
│   │   ├── auth-flows.spec.ts      # Authentication security tests
│   │   ├── error-disclosure.spec.ts # Error disclosure tests
│   │   └── idor-tests.spec.ts      # IDOR vulnerability tests
│   ├── utils/                      # Shared utilities
│   │   ├── config.ts               # Test configuration
│   │   └── response-analyzer.ts    # Response analysis utilities
│   ├── package.json                # NPM configuration
│   ├── package-lock.json           # Dependency lockfile
│   ├── playwright.config.ts        # Playwright configuration
│   └── README.md                   # Playwright harness documentation
├── screenshots/                    # Test screenshots (created at runtime)
├── apks/                           # Extracted APKs (created at runtime)
├── connect-device.sh               # Physical device connection
├── extract-apk.sh                  # APK extraction utility
├── frida_mixpanel_bypass.js        # Frida SSL bypass for Mixpanel
├── frida_ssl_bypass.js             # Frida SSL pinning bypass
├── install-sleepiq.sh              # App installation via Play Store
├── LICENSE                         # GPL-3.0 license
├── README.md                       # Main documentation
├── RUN_IDOR_TEST.md                # IDOR testing instructions
├── run-tests.sh                    # Interactive shell test harness
├── setup.sh                        # One-time environment setup
├── start-emulator.sh               # Emulator launch script
├── test_harness.py                 # Python test automation framework
└── test_idor.py                    # IDOR vulnerability test script
```

## Directory Purposes

**Root Directory (`/`):**
- Purpose: Shell scripts and Python modules for Android testing
- Contains: Entry point scripts, Python harnesses, Frida scripts
- Key files: `setup.sh`, `test_harness.py`, `test_idor.py`

**playwright-burp-harness/:**
- Purpose: HTTP-level API security testing through Burp proxy
- Contains: TypeScript test suites, configuration, utilities
- Key files: `playwright.config.ts`, `tests/*.spec.ts`, `utils/config.ts`

**playwright-burp-harness/tests/:**
- Purpose: Playwright test specifications organized by security concern
- Contains: Test files following `*-*.spec.ts` naming pattern
- Key files: `idor-tests.spec.ts`, `auth-flows.spec.ts`, `error-disclosure.spec.ts`

**playwright-burp-harness/utils/:**
- Purpose: Shared utilities for test configuration and response analysis
- Contains: TypeScript modules for config and analysis
- Key files: `config.ts`, `response-analyzer.ts`

**playwright-burp-harness/test-results/:**
- Purpose: Test output artifacts
- Contains: HTML reports, JSON results, screenshots, traces, videos
- Generated: Yes (by Playwright test runs)
- Committed: No (should be in .gitignore)

**screenshots/:**
- Purpose: Test screenshot storage
- Contains: PNG images with timestamp filenames
- Generated: Yes (by test harness during execution)
- Committed: No (should be in .gitignore)

**apks/:**
- Purpose: Extracted APK storage
- Contains: APK files pulled from devices
- Generated: Yes (by `extract-apk.sh`)
- Committed: No (should be in .gitignore)

**.planning/codebase/:**
- Purpose: Architecture and convention documentation
- Contains: Markdown analysis documents
- Key files: `ARCHITECTURE.md`, `STRUCTURE.md`

## Key File Locations

**Entry Points:**
- `setup.sh`: One-time Android SDK and emulator setup
- `start-emulator.sh`: Launch Android emulator
- `connect-device.sh`: Connect to physical Android device
- `install-sleepiq.sh`: Install SleepIQ from Play Store
- `extract-apk.sh`: Extract APK from installed app
- `run-tests.sh`: Interactive shell test harness
- `test_harness.py`: Python test automation (run as main)
- `test_idor.py`: IDOR vulnerability testing

**Configuration:**
- `playwright-burp-harness/playwright.config.ts`: Playwright test configuration
- `playwright-burp-harness/utils/config.ts`: API endpoints, test IDs, patterns
- `playwright-burp-harness/package.json`: NPM scripts and dependencies

**Core Logic:**
- `test_harness.py`: ADBWrapper, UIAutomator, SleepIQTestHarness classes
- `test_idor.py`: JWT extraction, authentication, IDOR testing functions
- `playwright-burp-harness/utils/response-analyzer.ts`: ResponseAnalyzer class

**Testing:**
- `playwright-burp-harness/tests/idor-tests.spec.ts`: IDOR security tests
- `playwright-burp-harness/tests/auth-flows.spec.ts`: Authentication tests
- `playwright-burp-harness/tests/error-disclosure.spec.ts`: Error disclosure tests

**Frida Scripts:**
- `frida_ssl_bypass.js`: General SSL pinning bypass
- `frida_mixpanel_bypass.js`: Mixpanel-specific SSL bypass

**Documentation:**
- `README.md`: Main project documentation
- `RUN_IDOR_TEST.md`: IDOR testing instructions
- `playwright-burp-harness/README.md`: Playwright harness documentation

## Naming Conventions

**Files:**
- Shell scripts: `lowercase-with-dashes.sh`
- Python modules: `lowercase_with_underscores.py`
- TypeScript tests: `kebab-case.spec.ts`
- TypeScript utilities: `kebab-case.ts`
- Frida scripts: `frida_descriptive_name.js`
- Documentation: `UPPERCASE.md` for generated docs, `kebab-case.md` for guides

**Directories:**
- All lowercase with dashes: `playwright-burp-harness/`, `test-results/`
- Node modules: `node_modules/` (standard NPM)

## Where to Add New Code

**New Shell Utility:**
- Location: Root directory (`/`)
- Naming: `descriptive-name.sh`
- Follow pattern of existing scripts (set -e, check prerequisites, echo progress)

**New Python Test/Module:**
- Location: Root directory (`/`)
- Naming: `test_descriptive_name.py` for tests, `descriptive_name.py` for modules
- Import from `test_harness.py` for ADB/UI utilities

**New Playwright Test Suite:**
- Location: `playwright-burp-harness/tests/`
- Naming: `category-tests.spec.ts`
- Add project in `playwright.config.ts` with matching `testMatch` pattern
- Add npm script in `package.json`

**New Playwright Utility:**
- Location: `playwright-burp-harness/utils/`
- Naming: `descriptive-name.ts`
- Export from module, import in test files

**New Frida Script:**
- Location: Root directory (`/`)
- Naming: `frida_descriptive_function.js`
- Follow pattern: `Java.perform()` wrapper, console logging, try-catch blocks

**New Configuration:**
- API endpoints/paths: Add to `playwright-burp-harness/utils/config.ts`
- Test IDs: Add to `config.testIds` object
- Sensitive patterns: Add to `config.sensitivePatterns` object

**New Documentation:**
- User guides: Root directory as `DESCRIPTIVE_GUIDE.md`
- Architecture docs: `.planning/codebase/UPPERCASE.md`

## Special Directories

**node_modules/:**
- Purpose: NPM dependency packages for Playwright harness
- Generated: Yes (by `npm install`)
- Committed: No (should be in .gitignore)

**test-results/:**
- Purpose: Playwright test output (reports, screenshots, traces, videos)
- Generated: Yes (by Playwright test runs)
- Committed: No (should be in .gitignore)

**screenshots/:**
- Purpose: Test screenshots from shell/Python harness
- Generated: Yes (by test harness execution)
- Committed: No (should be in .gitignore)

**apks/:**
- Purpose: Extracted APK files from devices
- Generated: Yes (by `extract-apk.sh`)
- Committed: No (should be in .gitignore, may contain proprietary code)

**$HOME/Library/Android/sdk/:**
- Purpose: Android SDK installation (external to repo)
- Generated: Yes (by `setup.sh`)
- Committed: N/A (not in repo)
- Note: Referenced by scripts via `ANDROID_SDK_ROOT` variable

---

*Structure analysis: 2026-01-19*
