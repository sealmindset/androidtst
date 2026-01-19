# Technology Stack

**Analysis Date:** 2026-01-19

## Languages

**Primary:**
- Python 3 - Core test harness and IDOR vulnerability testing (`test_harness.py`, `test_idor.py`)
- TypeScript - Playwright security test framework (`playwright-burp-harness/`)
- JavaScript (ES6) - Frida instrumentation scripts (`frida_ssl_bypass.js`, `frida_mixpanel_bypass.js`)

**Secondary:**
- Bash - Automation scripts for setup, emulator management, APK extraction (6 shell scripts)
- XML - UI hierarchy parsing via Android UI Automator

## Runtime

**Python Environment:**
- Python 3 (uses standard library only)
- No external Python dependencies required
- Uses: `subprocess`, `json`, `time`, `re`, `pathlib`, `dataclasses`, `xml.etree.ElementTree`

**Node.js Environment:**
- Node.js with CommonJS modules (`"type": "commonjs"`)
- Package manager: npm
- Lockfile: `package-lock.json` present

**Java Environment:**
- OpenJDK 17 (required for Android SDK/emulator)
- Installed via Homebrew on macOS

## Frameworks

**Core Testing:**
- Playwright `^1.57.0` - Browser automation and API testing
- @playwright/test `^1.57.0` - Test runner and assertions

**Android Automation:**
- Android UI Automator - UI element identification and interaction
- ADB (Android Debug Bridge) - Device communication and control

**Security Instrumentation:**
- Frida - Dynamic instrumentation for SSL pinning bypass

**Build/Dev:**
- TypeScript `^5.9.3` - Type checking for Playwright tests

## Key Dependencies

**Playwright Harness (`playwright-burp-harness/package.json`):**
```json
{
  "dependencies": {
    "@playwright/test": "^1.57.0",
    "playwright": "^1.57.0"
  },
  "devDependencies": {
    "typescript": "^5.9.3"
  }
}
```

**Python (Standard Library Only):**
- `subprocess` - ADB command execution
- `json` - API response parsing
- `re` - JWT token extraction, pattern matching
- `xml.etree.ElementTree` - UI hierarchy parsing
- `dataclasses` - UIElement data structures
- `pathlib` - File path handling

## External Tools

**Android SDK Components:**
- Platform Tools (ADB) - Device interaction
- Emulator - Android virtual device
- System Images `android-34;google_apis_playstore;arm64-v8a` - Android 14 with Play Store
- Build Tools `34.0.0` - APK handling
- Command Line Tools - SDK management

**Security Tools:**
- Frida - Runtime instrumentation for SSL pinning bypass
- Burp Suite (external) - HTTP proxy for traffic interception
- curl - API endpoint testing

**Platform Tools:**
- Homebrew - macOS package management
- adb - Android Debug Bridge
- avdmanager - AVD creation
- sdkmanager - SDK component management
- emulator - Android Virtual Device

## Configuration

**Android SDK:**
- SDK Root: `$HOME/Library/Android/sdk`
- Environment variables required:
  - `ANDROID_SDK_ROOT`
  - `ANDROID_HOME`
  - `PATH` additions for platform-tools, emulator, cmdline-tools

**Playwright:**
- Config file: `playwright-burp-harness/playwright.config.ts`
- Proxy: `http://127.0.0.1:8080` (Burp Suite)
- Test directory: `playwright-burp-harness/tests/`
- Reports: HTML, JSON, list formats

**Shell Profile:**
- Target: `$HOME/.zshrc`
- Auto-appended by setup script

## Platform Requirements

**Development:**
- macOS (Darwin) - Primary development platform
- ARM64 architecture (Apple Silicon) - System image target
- Homebrew - Package management
- 10+ GB disk space for Android SDK

**Emulator:**
- AVD Name: `SleepIQ_Test_Device`
- Device Profile: `pixel_6`
- System Image: Android 14 (API 34) with Google Play Store
- GPU: Host GPU acceleration (`-gpu host`)

**Network:**
- Burp Suite proxy on `localhost:8080`
- HTTPS error ignoring enabled
- Custom headers for test traffic identification

## Version Requirements

**Minimum Versions:**
- Java: OpenJDK 17
- Android SDK: API 34 (Android 14)
- Node.js: Compatible with Playwright 1.57.0
- Python: 3.7+ (dataclasses, pathlib)
- TypeScript: 5.9.3

**Android SDK Components:**
```
platform-tools
emulator
system-images;android-34;google_apis_playstore;arm64-v8a
platforms;android-34
build-tools;34.0.0
```

## Architecture Notes

**Test Harness Layers:**
1. Shell scripts - Environment setup and orchestration
2. Python harness - ADB wrapper and UI automation
3. Playwright/TypeScript - API security testing with Burp integration
4. Frida/JavaScript - Runtime instrumentation

**Data Flow:**
```
Shell Scripts (setup/launch)
    |
    v
Python Harness <---> ADB <---> Android Device/Emulator
    |                              |
    v                              v
API Testing (curl)          Frida Scripts (SSL bypass)
    |
    v
Playwright Tests <---> Burp Proxy <---> Target API
```

---

*Stack analysis: 2026-01-19*
