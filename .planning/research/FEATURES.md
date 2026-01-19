# Features Research: Android Security Testing Harness

**Domain:** Android mobile application security testing
**Researched:** 2026-01-19
**Confidence:** HIGH (based on OWASP MASTG, professional tooling analysis)

## Executive Summary

Professional Android security testing environments cover eight core domains defined by OWASP MASVS: Storage, Crypto, Auth, Network, Platform, Code, Resilience, and Privacy. Your existing harness covers Network well (Burp/Playwright, SSL bypass) and has basic Platform support (ADB automation). The main gaps are in Storage analysis, Resilience bypass depth, and systematic Code review tooling.

---

## Table Stakes

Features users expect from any competent Android security testing harness. Missing these makes the tool feel incomplete.

| Feature | Why Essential | Complexity | Your Status |
|---------|---------------|------------|-------------|
| **Emulator Management** | Foundation for all testing - need controlled environment | Medium | DONE |
| **APK Installation/Extraction** | Basic access to target application | Low | DONE |
| **ADB Command Wrapper** | Core automation primitive for all device interactions | Medium | DONE |
| **SSL/TLS Pinning Bypass** | Most apps use pinning; can't test network layer without bypass | Medium | DONE (Frida) |
| **Network Traffic Interception** | MASVS-NETWORK testing requires traffic analysis | Medium | DONE (Burp) |
| **APK Decompilation** | Static analysis requires readable code (JADX/apktool) | Low | PLANNED |
| **Root Detection Bypass** | Many apps block rooted/emulated devices | Medium | PARTIAL (need systematic approach) |
| **Emulator Detection Bypass** | Apps detect emulators via system props, files, sensors | Medium | NOT DONE |
| **Log Capture/Analysis** | `adb logcat` analysis for sensitive data leakage | Low | PARTIAL (raw ADB available) |
| **SharedPreferences Inspection** | MASVS-STORAGE: check for plaintext secrets | Low | NOT DONE |
| **SQLite Database Inspection** | MASVS-STORAGE: check for unencrypted sensitive data | Low | NOT DONE |
| **Config/Profile Management** | Switch between target apps easily | Low | PLANNED |

### Why These Are Table Stakes

Per [OWASP MASTG](https://mas.owasp.org/MASTG/), security testing requires coverage across all eight MASVS domains. The features above enable testing of the most critical domains:

- **MASVS-STORAGE**: SharedPreferences, SQLite, file permissions
- **MASVS-NETWORK**: Traffic interception, pinning bypass
- **MASVS-PLATFORM**: IPC analysis, intent testing
- **MASVS-RESILIENCE**: Root/emulator detection bypass

---

## Differentiators

Features that elevate beyond basic tooling. Not expected, but add significant value.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Frida Script Library** | Pre-built hooks for common bypasses (root, emulator, debug detection) | Medium | Build collection over time; leverage [Frida CodeShare](https://codeshare.frida.re/) |
| **Automated Component Testing** | Test exported Activities/Services/Receivers automatically | High | [APK Components Inspector](https://www.mobile-hacker.com/2025/09/18/automating-android-app-component-testing-with-new-apk-inspector/) approach |
| **Runtime Method Hooking UI** | Interactive Frida hooking without writing scripts | High | Nice but complex |
| **Credential/Secret Scanning** | Grep decompiled code for API keys, tokens, hardcoded secrets | Medium | High value, straightforward |
| **Certificate Management** | Automated CA cert installation to system store | Medium | Streamlines Burp setup |
| **Multi-App Profiles** | Quick switch between target apps with saved configs | Low | Productivity boost |
| **Decompiled Code Browser** | Navigate JADX output with search, cross-references | Medium | VS Code + APKLab does this |
| **Test Case Tracking** | Map testing to OWASP MASTG test cases | Medium | Professional rigor |
| **Network Traffic Diff** | Compare before/after traffic to spot changes | High | Useful for regression |
| **Play Integrity Bypass** | Pass SafetyNet/Play Integrity checks on rooted device | High | Requires [Magisk modules](https://github.com/osm0sis/PlayIntegrityFork), complex |

### Recommended Differentiators to Prioritize

1. **Frida Script Library** - Leverage existing scripts, curate what works
2. **Credential/Secret Scanning** - Simple grep patterns, high value
3. **Multi-App Profiles** - Low effort, daily productivity gain

---

## Anti-Features (Skip These)

Features that seem useful but are wrong for a personal security testing tool.

| Anti-Feature | Why Skip | What to Do Instead |
|--------------|----------|-------------------|
| **Web Dashboard/GUI** | Overkill for personal use; maintenance burden | CLI + VS Code is fine |
| **CI/CD Integration** | Designed for enterprise DevSecOps pipelines | Manual testing is your use case |
| **Multi-User Support** | You're the only user | Single-user config |
| **Cloud Deployment** | MobSF offers this; not needed for local testing | Keep it local |
| **iOS Support** | Different toolchain entirely (Corellium, Xcode) | Separate project if needed |
| **Automated Report Generation** | Enterprise compliance feature | Notes/markdown is sufficient |
| **Vulnerability Database Sync** | Enterprise feature for CVE tracking | Manual research per-app |
| **Paid Tool Integration** | NowSecure, Checkmarx, etc. are enterprise | Stick to FOSS stack |
| **Device Farm Management** | Testing across many physical devices | Single emulator is enough |
| **Full MobSF Reimplementation** | MobSF already exists and is comprehensive | Use MobSF when you need it |

### Philosophy

This is a **personal testing harness**, not an enterprise platform. Build what accelerates YOUR workflow. Use existing tools (MobSF, Objection) for comprehensive scans; your harness fills gaps and provides quick targeted testing.

---

## Gap Analysis

Comparing your existing harness to a complete security testing solution.

### What You Have (Strong)

| Capability | Implementation |
|------------|----------------|
| Emulator setup | Pixel 6, Play Store image |
| SSL pinning bypass | Frida-based |
| APK extraction | Working |
| ADB automation | Python wrapper with UI automation |
| Network proxy | Playwright + Burp integration |
| Interactive testing | Shell-based |

### Critical Gaps (High Priority)

| Gap | Why Critical | Effort to Close |
|-----|--------------|-----------------|
| **Emulator detection bypass** | Many apps refuse to run on emulators | Medium - Frida scripts exist |
| **Root detection bypass** | Systematic approach needed beyond ad-hoc | Medium - [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) |
| **Data storage analysis** | MASVS-STORAGE is major attack surface | Low - scripts to pull/inspect SharedPrefs, SQLite |
| **APK decompilation pipeline** | Can't do static analysis without readable code | Low - JADX + apktool integration |

### Moderate Gaps (Medium Priority)

| Gap | Why Useful | Effort to Close |
|-----|------------|-----------------|
| **Frida script collection** | Repeatable bypasses across apps | Medium - curate over time |
| **Decompiled code search** | Find interesting patterns (URLs, keys) | Low - grep patterns |
| **Log analysis automation** | Catch debug logs leaking sensitive data | Low - logcat filtering |
| **Config management** | Switch between apps efficiently | Low - JSON/YAML profiles |

### Nice-to-Have Gaps (Lower Priority)

| Gap | Why Useful | Effort to Close |
|-----|------------|-----------------|
| **Automated IPC testing** | Test exported components systematically | High |
| **MASTG test mapping** | Track coverage against standard | Medium |
| **Credential scanning** | Automated secret detection | Medium |

---

## Feature Prioritization Recommendation

Based on gap analysis, here's a suggested build order:

### Phase 1: Close Critical Gaps
1. APK decompilation (JADX + apktool wrapper)
2. Emulator detection bypass (Frida scripts)
3. Root detection bypass (integrate FridaBypassKit approach)
4. Data storage inspection (SharedPrefs, SQLite pull scripts)

### Phase 2: Productivity Enhancements
5. Config/profile management (per-app settings)
6. Frida script library (curated bypasses)
7. Decompiled code search (grep patterns for secrets)
8. Log analysis automation

### Phase 3: Advanced Capabilities (If Needed)
9. Automated component testing
10. MASTG test case tracking

---

## OWASP MASVS Domain Coverage

Mapping harness capabilities to [OWASP MASVS](https://mas.owasp.org/checklists/) domains:

| Domain | Current Coverage | Gap |
|--------|------------------|-----|
| **MASVS-STORAGE** | LOW | Need SharedPrefs, SQLite, file permission inspection |
| **MASVS-CRYPTO** | LOW | Static analysis of crypto usage (post-decompilation) |
| **MASVS-AUTH** | MEDIUM | Can test via network traffic |
| **MASVS-NETWORK** | HIGH | Burp + SSL bypass covers this well |
| **MASVS-PLATFORM** | MEDIUM | Basic ADB, need IPC testing |
| **MASVS-CODE** | LOW | Need decompilation and code review |
| **MASVS-RESILIENCE** | MEDIUM | SSL bypass works, need root/emulator bypass |
| **MASVS-PRIVACY** | LOW | Requires storage + network analysis |

---

## Sources

### OWASP Standards
- [OWASP MASTG](https://mas.owasp.org/MASTG/) - Mobile Application Security Testing Guide
- [OWASP MAS Checklist](https://mas.owasp.org/checklists/) - Security testing checklist

### Tools and Frameworks
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Comprehensive mobile security framework
- [Frida](https://frida.re/docs/examples/android/) - Dynamic instrumentation toolkit
- [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) - Universal bypass framework
- [APK Components Inspector](https://www.mobile-hacker.com/2025/09/18/automating-android-app-component-testing-with-new-apk-inspector/) - Automated component testing
- [Frida CodeShare](https://codeshare.frida.re/) - Community Frida scripts

### Techniques and Best Practices
- [Android Penetration Testing Tools](https://infosecone.com/blog/android-penetration-testing-tools/) - Tool comparison
- [JADX Reverse Engineering](https://blog1.neuralengineer.org/reverse-engineering-android-apks-with-jadx-ebded67ceb8f) - APK decompilation
- [Root Detection Bypass](https://dghostninja.github.io/posts/Bypass-root/) - Bypass techniques
- [Network Traffic Analysis with Burp](https://portswigger.net/burp/documentation/desktop/mobile) - Mobile testing setup
- [Data Storage Security Testing](https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/) - OWASP storage testing
