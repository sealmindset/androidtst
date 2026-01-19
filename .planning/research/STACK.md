# Stack Research: Android Security Testing Harness

**Project:** Android Security Testing Harness Enhancement
**Researched:** 2026-01-19
**Overall Confidence:** HIGH

## Executive Summary

This research covers the 2025/2026 toolset for Android APK analysis and security bypass. The ecosystem has matured significantly, with JADX and Apktool remaining the gold standard for decompilation, while Frida-based solutions dominate the runtime bypass space. Play Integrity API changes in May 2025 have made hardware-backed attestation harder to bypass, but most apps still rely on simpler detection methods that are readily bypassable.

**Key finding:** The existing project already has Frida SSL bypass. The recommended additions are complementary tools (JADX for code analysis, comprehensive bypass scripts) rather than replacements.

---

## Decompilation Tools

### JADX (Recommended for Code Analysis)

| Attribute | Value |
|-----------|-------|
| **Version** | 1.5.3 (September 2024, latest stable) |
| **Install** | `brew install jadx` |
| **Purpose** | DEX to Java decompilation for code reading/analysis |
| **Confidence** | HIGH |

**Why JADX:**
- Produces human-readable Java source code directly from APK/DEX
- Includes GUI (`jadx-gui`) with code navigation, search, jump-to-declaration
- Community-ranked #1 decompilation tool on Slant (2025)
- Supports APK, DEX, JAR, AAB, XAPK formats
- Search functionality: Ctrl+Shift+F for full-text search, find usages, jump to declaration

**GUI Features (jadx-gui):**
- Syntax highlighting
- Code navigation (Ctrl+click to jump to declaration)
- Full-text search across decompiled code
- Package exclusion for memory optimization
- Export as Gradle project for IDE import
- Plugin system for custom deobfuscation

**Limitations:**
- Cannot decompile 100% of code (some obfuscated/complex code fails)
- Output is not recompilable - analysis only
- Struggles with heavily ProGuard/R8 obfuscated apps

**Sources:**
- [JADX GitHub](https://github.com/skylot/jadx)
- [Homebrew Formula](https://formulae.brew.sh/formula/jadx)
- [JADX-GUI Features Wiki](https://github.com/skylot/jadx/wiki/jadx-gui-features-overview)

---

### Apktool (Recommended for Resource Extraction & Modification)

| Attribute | Value |
|-----------|-------|
| **Version** | 2.12.1 (September 2025) |
| **Install** | `brew install apktool` |
| **Purpose** | Resource decoding, smali extraction, APK rebuilding |
| **Confidence** | HIGH |

**Why Apktool:**
- Decodes ALL resources (AndroidManifest.xml, layouts, images, strings)
- Outputs smali (low-level but modifiable bytecode)
- Can rebuild modified APK for testing
- Essential for patching and re-signing apps

**When to use Apktool over JADX:**
- Need to modify and rebuild the APK
- Need full resource extraction (images, layouts, strings.xml)
- Need smali code for Frida hook targeting
- Need AndroidManifest.xml analysis (permissions, components)

**Limitations:**
- Smali is harder to read than Java
- Requires Java 8+ runtime
- Rebuilding requires re-signing (breaks original signature)

**Sources:**
- [Apktool Official Docs](https://apktool.org/docs/install/)
- [Homebrew Formula](https://formulae.brew.sh/formula/apktool)

---

### Recommendation: Use Both Together

**Standard workflow:**
1. **JADX** for initial code analysis - understand app logic, find interesting methods
2. **Apktool** for resource extraction and smali inspection when needed
3. Target Frida hooks based on method names/classes discovered in JADX

```bash
# Installation
brew install jadx apktool

# Analysis workflow
jadx-gui app.apk              # Browse code, search for API endpoints
apktool d app.apk -o app_dir  # Extract resources and smali
```

---

## Code Analysis/Browsing

### Primary: jadx-gui

**Features for Security Testing:**
- Search for API endpoints: `http`, `/api`, `@GET`, `@POST`
- Search for crypto: `AES`, `encrypt`, `decrypt`, `SecretKey`
- Search for auth: `token`, `bearer`, `authorization`, `password`
- Search for detection: `root`, `emulator`, `frida`, `xposed`
- Find usages to trace data flow

**Keyboard Shortcuts:**
- `Ctrl+Shift+F` - Full text search
- `Ctrl+Click` - Jump to declaration
- `Ctrl+Alt+F7` - Find usages

### Alternative: Android Studio

For deeper analysis, export JADX output as Gradle project and open in Android Studio:
- Better refactoring tools
- Smarter code completion
- Integration with ADB

**Not recommended for this project** - JADX-GUI is sufficient for security testing workflows.

---

## Bypass Frameworks

### Existing: frida_ssl_bypass.js

The project already has a working SSL bypass script. No changes needed for SSL pinning.

---

### Root Detection Bypass

#### Option 1: FridaBypassKit (Recommended)

| Attribute | Value |
|-----------|-------|
| **Type** | Frida script |
| **Install** | Download from GitHub |
| **Bypasses** | Root, SSL pinning, emulator, debug detection |
| **Confidence** | HIGH |

**Features:**
- Hides root/su binaries, Magisk, root management apps
- SSL pinning bypass (overlaps with existing script)
- Emulator detection bypass (spoofs device properties to Samsung)
- Debug detection bypass

**Usage:**
```bash
frida -U -f com.example.app -l FridaBypassKit.js
```

**Source:** [FridaBypassKit GitHub](https://github.com/okankurtuluss/FridaBypassKit)

---

#### Option 2: frida-interception-and-unpinning (HTTP Toolkit)

| Attribute | Value |
|-----------|-------|
| **Type** | Frida script |
| **Maintainer** | HTTP Toolkit |
| **Bypasses** | Root detection, SSL pinning |
| **Confidence** | HIGH |

**Features:**
- Well-maintained by HTTP Toolkit team
- Intercepts file system access for root indicators
- Fakes system properties (ro.debuggable, etc.)
- Blocks execution of root-related commands

**Source:** [GitHub](https://github.com/httptoolkit/frida-interception-and-unpinning)

---

#### Option 3: Frida CodeShare Scripts

| Attribute | Value |
|-----------|-------|
| **Type** | Community scripts |
| **URL** | https://codeshare.frida.re/ |
| **Confidence** | MEDIUM |

**Useful scripts:**
- `Q0120S/root-detection-bypass` - Generic root bypass
- Various SSL unpinning scripts
- App-specific bypasses

**Caveat:** Quality varies. Test thoroughly before relying on CodeShare scripts.

---

### Emulator Detection Bypass

Most emulator detection checks for:
- IMEI = `000000000000000` (default emulator value)
- System properties (`ro.kernel.qemu`, `ro.hardware`)
- File existence (`/system/bin/qemu-props`)
- Build fingerprint patterns

**FridaBypassKit handles these** by spoofing device properties to appear as a real Samsung device.

**For stubborn apps**, additional hooks may be needed:
```javascript
// Example: Spoof IMEI
Java.perform(function() {
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
        return "352099001761481"; // Real device IMEI format
    };
});
```

---

### Play Integrity API Considerations

**Current Status (January 2026):**
- Google enforced hardware-backed attestation in May 2025
- MEETS_STRONG_INTEGRITY is very difficult to bypass
- MEETS_DEVICE_INTEGRITY can sometimes be bypassed via keybox spoofing

**For security testing:**
- Most apps do NOT use Play Integrity (too complex to implement)
- Apps that do use it often only check MEETS_BASIC_INTEGRITY
- If app uses STRONG integrity, testing on a non-rooted physical device may be required

**Tools for Play Integrity bypass (if needed):**
- Play Integrity Fix (PIF) Magisk module
- Shamiko + Zygisk DenyList
- ReZygisk + Treat Wheels

**Recommendation:** Don't pre-optimize for Play Integrity bypass. Most target apps won't use it. Handle on a case-by-case basis.

**Sources:**
- [XDA Guide - Play Integrity Bypass (Jan 2026)](https://xdaforums.com/t/guide-how-to-pass-strong-integrity-and-bypass-root-detection-apps-revolut-company-portal-google-wallet-etc-working-as-of-january-13th-2026.4773849/)
- [Play Integrity Fix Module](https://tryigit.dev/pif/)

---

## Configuration Management

### Recommendation: Environment Variables + .env Files

**Why:**
- Simple, standard approach
- Works with existing shell scripts
- No additional dependencies
- Easy to switch between targets

**Structure:**
```
.env.template          # Committed - documents required vars
.env                   # Git-ignored - actual credentials
.env.sleepiq          # Git-ignored - app-specific config
.env.banking          # Git-ignored - another target config
```

**Required Variables:**
```bash
# .env.template
ANDROID_SDK_ROOT=$HOME/Library/Android/sdk
TARGET_PACKAGE=                  # e.g., com.example.app
TARGET_APK_PATH=                 # Path to extracted APK
BURP_PROXY_HOST=127.0.0.1
BURP_PROXY_PORT=8080

# Optional - for apps requiring auth
TARGET_USERNAME=
TARGET_PASSWORD=
TARGET_API_KEY=
```

**Loading:**
```bash
# In scripts
source .env 2>/dev/null || true
source ".env.${TARGET_APP}" 2>/dev/null || true
```

---

### Alternative: python-dotenv (for Python scripts)

```python
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file
load_dotenv(f".env.{os.environ.get('TARGET_APP', 'default')}")

package = os.environ.get('TARGET_PACKAGE')
```

**Install:** `pip install python-dotenv`

---

### What NOT to Use

| Approach | Why Not |
|----------|---------|
| HashiCorp Vault | Overkill for local testing harness |
| AWS Secrets Manager | Cloud dependency unnecessary |
| Hardcoded values | Commits credentials to git |
| macOS Keychain | Adds complexity, scripts need sudo |

---

## Complete Tool Installation

### macOS Installation (Homebrew)

```bash
# Core decompilation tools
brew install jadx apktool

# Java runtime (required for jadx/apktool)
brew install openjdk@17
echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zshrc

# Frida (already present in project, but for reference)
pip3 install frida-tools

# Optional: objection (higher-level Frida wrapper)
pip3 install objection
```

### Verify Installation

```bash
jadx --version        # Should show 1.5.x
apktool --version     # Should show 2.x.x
frida --version       # Should show 16.x.x
```

---

## Summary Recommendations

### Must Have (Phase 1)

| Tool | Purpose | Install |
|------|---------|---------|
| JADX 1.5.3 | Code decompilation & browsing | `brew install jadx` |
| Apktool 2.12.1 | Resource extraction, smali | `brew install apktool` |
| FridaBypassKit | Root/emulator/debug bypass | Download from GitHub |
| .env files | Credential management | Create template |

### Nice to Have (Phase 2)

| Tool | Purpose | Install |
|------|---------|---------|
| Objection | Simplified Frida interface | `pip3 install objection` |
| Shamiko/Zygisk | Magisk-based root hiding | For stubborn apps |

### Do Not Include

| Tool | Reason |
|------|--------|
| dex2jar | JADX does this better, directly |
| JD-GUI | JADX includes GUI, more features |
| Ghidra | Overkill for APK analysis |
| apkx | Abandoned, use jadx+apktool instead |

---

## Sources Summary

### HIGH Confidence (Official/Authoritative)
- [JADX GitHub](https://github.com/skylot/jadx) - Official repository
- [Homebrew jadx](https://formulae.brew.sh/formula/jadx) - Official formula
- [Homebrew apktool](https://formulae.brew.sh/formula/apktool) - Official formula
- [Apktool Install Guide](https://apktool.org/docs/install/) - Official documentation
- [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) - Source repository
- [Frida CodeShare](https://codeshare.frida.re/) - Official script repository
- [OWASP MASTG Objection](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/) - OWASP reference

### MEDIUM Confidence (Verified Community)
- [Slant APK Decompilers Comparison](https://www.slant.co/topics/3101/~best-apk-decompilation-tools) - Community ranking
- [XDA Play Integrity Guide](https://xdaforums.com/t/guide-how-to-pass-strong-integrity-and-bypass-root-detection-apps-revolut-company-portal-google-wallet-etc-working-as-of-january-13th-2026.4773849/) - Community guide
- [HTTP Toolkit frida-interception](https://github.com/httptoolkit/frida-interception-and-unpinning) - Maintained tool

### LOW Confidence (Single Source/Blog)
- Various Medium articles on bypass techniques - Useful for ideas but verify independently
