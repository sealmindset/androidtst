# Android Test Harness

## What This Is

A scripted automation environment for mobile app security testing on macOS. Sets up and configures an Android emulator with Play Store access, routes traffic through Burp Suite CE for interception, enables security bypass tools (Frida for SSL pinning, root/emulator detection), and provides APK decompilation and code browsing capabilities. Playwright-style automation scripts control the workflow.

## Core Value

Automated setup that takes a macOS with prerequisites and stands up a complete, ready-to-use Android security testing environment — emulator running, proxy configured, bypasses active, analysis tools available.

## Requirements

### Validated

**v1.0 (2026-01-19):**
- ✓ Configure and launch Android emulator with Pixel 6 profile and Play Store — `setup.sh`, `start-emulator.sh`
- ✓ Pull APKs from the emulated device — `extract-apk.sh`
- ✓ Frida SSL pinning bypass scripts — `frida_ssl_bypass.js`
- ✓ Python test harness with ADB wrapper and UI automation — `test_harness.py`
- ✓ Playwright + Burp proxy integration for API testing — `playwright-burp-harness/`
- ✓ Interactive shell testing interface — `run-tests.sh`
- ✓ Generalize harness (remove SleepIQ-specific code, make app-agnostic) — v1.0
- ✓ Add APK decompilation tooling (jadx, apktool integration) — v1.0
- ✓ Add code browsing/examination workflow — v1.0
- ✓ Configure emulator proxy routing to Burp Suite CE — v1.0
- ✓ Add root detection bypass (extend Frida scripts) — v1.0
- ✓ Add emulator detection bypass (extend Frida scripts) — v1.0
- ✓ Configuration management (replace hardcoded credentials with env vars) — v1.0
- ✓ Secure credential handling (remove /tmp storage, add cleanup) — v1.0

### Active

(None - v1.0 complete)

Future enhancements:
- [ ] GUI/dashboard for visual test management
- [ ] Additional CLI security tools (semgrep integration)
- [ ] iOS support

### Out of Scope

- GUI/dashboard — deferred to later phase
- Additional CLI security tools (semgrep, etc.) — will add incrementally later
- Host system modifications — prerequisites handled separately by user
- Android SDK installation — prerequisite
- Burp Suite CE installation — prerequisite
- SleepIQ-specific testing — generalizing the harness

## Context

**Use case:** Personal mobile app security testing and reverse engineering. Install apps from Google Play Store using valid credentials, operate them normally while intercepting and examining network traffic, and analyze the APK code through decompilation.

**Workflow:** Get an APK (from Play Store or sideload) → Run app in emulator → Traffic captured by Burp → Pull and decompile APK → Examine code and correlate with network behavior.

**Starting point:** Cloned from `sealmindset/androidtst` — a SleepIQ-specific test harness. Core infrastructure exists but needs generalization and additional tooling for the full workflow.

**Codebase analysis:** See `.planning/codebase/` for detailed architecture, stack, quality, and concerns analysis.

**Prerequisites on host:**
- macOS
- Android SDK (emulator, ADB, platform-tools)
- Burp Suite CE

## Constraints

- **Platform**: macOS only
- **Self-contained**: No modifications to host system beyond prerequisites
- **Prerequisites**: User responsible for Android SDK and Burp Suite CE installation
- **Emulator**: Must support Play Store and Google Play Services for realistic app behavior
- **Proxy**: Must integrate with Burp Suite CE specifically

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Android SDK as prerequisite | Complex install, user may have preferences, avoids host modifications | — Pending |
| Burp Suite CE as prerequisite | User's existing tool of choice, avoid bundling commercial-adjacent software | — Pending |
| Playwright-style automation | Scriptable, familiar pattern, good for future GUI integration | ✓ Good (existing) |
| Frida for bypasses | Industry standard for mobile security testing, handles pinning/detection | ✓ Good (existing) |
| Clone and enhance androidtst | Existing infrastructure saves effort; generalize rather than rebuild | ✓ Good |
| Remove hardcoded credentials | Critical security issue in existing code | ✓ Good |
| python-dotenv for config | Industry standard, simple .env file loading | ✓ Good |
| Dual decompilation (jadx + apktool) | jadx for Java source, apktool for manifest/resources | ✓ Good |
| Frida for all bypasses | Industry standard, comprehensive hook support | ✓ Good |

---
*Last updated: 2026-01-19 after v1.0 milestone*
