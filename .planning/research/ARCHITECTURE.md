# Architecture Research

**Project:** Android Security Test Harness
**Dimension:** Architecture - Decompilation and Code Analysis Integration
**Researched:** 2026-01-19
**Confidence:** HIGH (based on codebase analysis and authoritative tool documentation)

## Executive Summary

The existing harness has a layered architecture with clear separation: shell scripts for setup/orchestration, Python for ADB/UI automation, TypeScript for API testing, and JavaScript for runtime bypasses. Decompilation tooling should integrate as a **new layer** that connects to the APK extraction output and feeds into a code browsing workflow. Configuration management needs centralization to eliminate scattered hardcoded values across all language layers.

## Current Architecture Analysis

### Existing Layers

```
+------------------+     +------------------+     +------------------+
|   Shell Layer    |     |   Python Layer   |     |  TypeScript Layer|
|------------------|     |------------------|     |------------------|
| setup.sh         |     | test_harness.py  |     | playwright-burp/ |
| start-emulator.sh|     | test_idor.py     |     |   tests/*.ts     |
| extract-apk.sh   |     | ADBWrapper       |     |   utils/config.ts|
| connect-device.sh|     | UIAutomator      |     |   response-*.ts  |
| run-tests.sh     |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         v                       v                        v
+--------------------------------------------------------------+
|                    Android Emulator / Device                  |
|                    (via ADB over TCP/USB)                     |
+--------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------+
|                    Burp Suite CE Proxy                        |
|                    (HTTP/HTTPS interception)                  |
+--------------------------------------------------------------+

+------------------+
| JavaScript Layer |
|------------------|
| frida_ssl_bypass |
| frida_mixpanel   |
+------------------+
         |
         v
    Frida Server (on device)
```

### Data Flow (Current)

1. **Setup:** `setup.sh` installs SDK, creates AVD
2. **Launch:** `start-emulator.sh` starts emulator with proxy config
3. **Device:** `connect-device.sh` verifies physical device connection
4. **Extract:** `extract-apk.sh` pulls APK from device to `./apks/`
5. **Test:** Python harness controls app via ADB, TypeScript tests API
6. **Bypass:** Frida scripts inject into running app for SSL/detection bypass

### Gaps Identified

| Gap | Impact | Current State |
|-----|--------|---------------|
| No decompilation pipeline | Cannot examine app code | APKs extracted but not analyzed |
| No code browsing workflow | Manual jadx launch required | No automation |
| Scattered configuration | Hardcoded values in each language | Security risk, maintenance burden |
| No shared state | Each tool operates independently | Duplication, inconsistency |

## Integration Approach

### Principle: Additive Layers

Add new components without modifying existing working functionality. The decompilation layer sits **between** APK extraction and code browsing, producing artifacts that downstream tools can consume.

### Recommended Architecture

```
+------------------------------------------------------------------+
|                         ORCHESTRATION LAYER                       |
|                    (Shell scripts - existing + new)               |
+------------------------------------------------------------------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
          v                        v                        v
+------------------+    +------------------+    +------------------+
|  DEVICE LAYER    |    | DECOMPILATION    |    |   API TESTING    |
|  (existing)      |    | LAYER (NEW)      |    |   LAYER          |
|------------------|    |------------------|    |------------------|
| setup.sh         |    | decompile.sh     |    | playwright-burp/ |
| start-emulator   |    | jadx wrapper     |    | TypeScript tests |
| extract-apk      |    | apktool wrapper  |    | Burp proxy       |
| test_harness.py  |    | output indexer   |    |                  |
+------------------+    +------------------+    +------------------+
          |                        |                        |
          v                        v                        v
+------------------+    +------------------+    +------------------+
| ./apks/          |    | ./decompiled/    |    | ./test-results/  |
| (APK files)      |    | (source, smali)  |    | (reports, traces)|
+------------------+    +------------------+    +------------------+

+------------------------------------------------------------------+
|                      CONFIGURATION LAYER (NEW)                    |
|            (Shared .env, config.json, loaded by all)              |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|                       BYPASS LAYER (existing)                     |
|                    (Frida scripts - JS runtime)                   |
+------------------------------------------------------------------+
```

## Decompilation Layer

### Component Design

The decompilation layer wraps jadx and apktool with standardized interfaces.

#### Directory Structure

```
decompilation/
  decompile.sh          # Main entry point
  jadx-wrapper.sh       # jadx CLI wrapper with defaults
  apktool-wrapper.sh    # apktool CLI wrapper
  index-output.py       # Creates searchable index of decompiled code
  config/
    jadx-defaults.json  # Default jadx options
    apktool-defaults    # Default apktool options
```

#### Output Structure

```
decompiled/
  {package_name}_v{version}/
    jadx/
      sources/          # Java source from jadx
      resources/        # Decoded resources
    apktool/
      smali/            # Smali disassembly
      res/              # Resources (XML, images)
      AndroidManifest.xml
    index/
      classes.json      # Class listing with paths
      strings.json      # Extracted strings
      permissions.json  # Declared/used permissions
      endpoints.json    # Extracted API endpoints
```

### Tool Selection

| Tool | Purpose | Why |
|------|---------|-----|
| **jadx** (CLI) | DEX to Java decompilation | Industry standard, JSON output mode, good obfuscation handling |
| **apktool** | Resource decoding, smali extraction | Best for resources, enables recompilation |
| **No GUI tools** | Keep automation-first | jadx-gui is for interactive use only |

### jadx Integration

jadx supports automation-friendly options:

```bash
# Recommended command structure
jadx \
  --output-dir ./decompiled/{pkg}/jadx \
  --output-format java \
  --deobf \
  --deobf-min 3 \
  --deobf-max 64 \
  --threads-count 8 \
  --log-level progress \
  ./apks/{apk_file}
```

Key options for scripted use:
- `--output-format json` - Machine-readable output for indexing
- `--deobf` - Rename obfuscated classes/methods
- `--single-class` - Decompile specific class (for targeted analysis)
- `--threads-count` - Parallel processing

### apktool Integration

```bash
# Recommended command structure
apktool decode \
  --output ./decompiled/{pkg}/apktool \
  --force \
  ./apks/{apk_file}

# Resources only (skip smali)
apktool decode --no-src --output ./decompiled/{pkg}/resources ./apks/{apk_file}

# Smali only (skip resources)
apktool decode --no-res --output ./decompiled/{pkg}/smali ./apks/{apk_file}
```

### Workflow Integration

```
extract-apk.sh
      |
      v
  ./apks/{pkg}_v{version}.apk
      |
      v
decompile.sh {apk_path}
      |
      +---> jadx-wrapper.sh --> ./decompiled/{pkg}/jadx/
      |
      +---> apktool-wrapper.sh --> ./decompiled/{pkg}/apktool/
      |
      v
index-output.py --> ./decompiled/{pkg}/index/
      |
      v
Ready for code browsing / analysis
```

## Configuration Layer

### Problem Statement

Current state has configuration scattered:
- `playwright-burp-harness/utils/config.ts` - TypeScript config with hardcoded API paths, test IDs
- `test_idor.py` - Hardcoded credentials (TEST_EMAIL, TEST_PASSWORD)
- Shell scripts - Hardcoded paths (ANDROID_SDK_ROOT, package names)

### Recommended Approach: Dotenv with JSON Overlay

Use `.env` for secrets and environment-specific values, with a shared `config.json` for structural configuration that all languages can read.

#### File Structure

```
.env                    # Secrets (gitignored)
.env.example            # Template (committed)
config.json             # Shared structure config (committed)
```

#### .env Format

```bash
# .env (gitignored - user creates from .env.example)

# Paths
ANDROID_SDK_ROOT=/Users/username/Library/Android/sdk
DECOMPILED_OUTPUT=./decompiled
APK_OUTPUT=./apks

# Test credentials (never commit real values)
TEST_EMAIL=test@example.com
TEST_PASSWORD=changeme

# Device
EMULATOR_NAME=Test_Device
DEVICE_ID=

# Proxy
BURP_PROXY_HOST=127.0.0.1
BURP_PROXY_PORT=8080

# Decompilation
JADX_THREADS=8
```

#### config.json Format

```json
{
  "app": {
    "defaultPackage": "",
    "description": "General-purpose Android security testing"
  },
  "endpoints": {
    "prod": {},
    "stage": {},
    "qa": {}
  },
  "testIds": {
    "sleeperIds": [],
    "accountIds": [],
    "bedIds": []
  },
  "decompilation": {
    "jadxOptions": {
      "deobf": true,
      "deobfMin": 3,
      "deobfMax": 64,
      "outputFormat": "java"
    },
    "apktoolOptions": {
      "force": true
    }
  }
}
```

### Language-Specific Loading

#### Shell Scripts

```bash
# Load .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

# Use with defaults
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
```

#### Python

```python
# Use python-dotenv
from dotenv import load_dotenv
import json
import os

load_dotenv()

# Load shared config
with open('config.json') as f:
    config = json.load(f)

# Access values
sdk_root = os.getenv('ANDROID_SDK_ROOT', '~/Library/Android/sdk')
test_email = os.getenv('TEST_EMAIL')  # Required, no default
```

#### TypeScript

```typescript
// Use dotenv
import * as dotenv from 'dotenv';
import config from '../../config.json';

dotenv.config();

// Access values
const sdkRoot = process.env.ANDROID_SDK_ROOT || '~/Library/Android/sdk';
const endpoints = config.endpoints;
```

### Migration Strategy

1. **Phase 1:** Create `.env.example` and `config.json` templates
2. **Phase 2:** Add dotenv loading to Python scripts
3. **Phase 3:** Update TypeScript to read from root config
4. **Phase 4:** Update shell scripts to source `.env`
5. **Phase 5:** Remove hardcoded values from all files
6. **Phase 6:** Add validation on startup (fail fast if required vars missing)

## Data Flow

### Updated Flow with Decompilation

```
1. SETUP
   setup.sh
      |
      v
   Android SDK configured, AVD created

2. LAUNCH
   start-emulator.sh
      |
      v
   Emulator running with proxy

3. INSTALL & EXTRACT
   User installs app (Play Store or sideload)
      |
      v
   extract-apk.sh
      |
      v
   ./apks/{package}_v{version}.apk

4. DECOMPILE (NEW)
   decompile.sh ./apks/{apk}
      |
      +---> jadx --> ./decompiled/{pkg}/jadx/sources/
      |
      +---> apktool --> ./decompiled/{pkg}/apktool/smali/
      |
      v
   index-output.py --> ./decompiled/{pkg}/index/

5. ANALYZE (PARALLEL WORKFLOWS)

   A. Dynamic Testing
      test_harness.py OR run-tests.sh
         |
         v
      App controlled via ADB
         |
         v
      Traffic captured in Burp

   B. API Testing
      playwright test
         |
         v
      API requests through Burp
         |
         v
      ./test-results/

   C. Code Review (NEW)
      Browse ./decompiled/{pkg}/jadx/sources/
      Cross-reference with ./decompiled/{pkg}/index/
      Correlate with Burp traffic observations

6. BYPASS (AS NEEDED)
   frida -U -f {package} -l frida_ssl_bypass.js
      |
      v
   SSL pinning disabled, traffic visible in Burp
```

### Data Dependencies

```
.env  -----> All scripts (credentials, paths)
   |
   v
config.json -----> All scripts (structure, options)
   |
   v
./apks/{apk} -----> decompile.sh
   |                     |
   |                     v
   |              ./decompiled/{pkg}/
   |                     |
   v                     v
test_harness.py    Code browsing (manual or scripted)
   |
   v
Burp capture <---- playwright tests
```

## Recommendations

### Architectural Decisions

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| Decompilation entry point | Shell script wrapping jadx/apktool | Consistent with existing orchestration pattern |
| Output format | Separate jadx and apktool directories | Different tools for different purposes; keep distinct |
| Index format | JSON files | Machine-readable, language-agnostic, easy to query |
| Configuration | Dotenv + JSON | Industry standard, cross-language support |
| Code browsing | File-based initially | Defer interactive browser to GUI phase |

### Phase Ordering (Roadmap Implications)

Based on this architecture research, the recommended phase order:

1. **Configuration Layer First**
   - Rationale: Every other component needs config; establishes patterns
   - Creates: `.env`, `.env.example`, `config.json`, loading utilities

2. **Decompilation Layer Second**
   - Rationale: Builds on config layer; independent of other changes
   - Creates: `decompile.sh`, wrappers, indexer

3. **Code Browsing Workflow Third**
   - Rationale: Requires decompilation output to exist
   - Creates: Search scripts, cross-reference utilities

4. **Generalization Fourth**
   - Rationale: Can now generalize with config layer in place
   - Modifies: Remove hardcoded package names, use config

5. **Bypass Extensions Fifth**
   - Rationale: Independent; can be done anytime but benefits from config
   - Creates: New Frida scripts for root/emulator detection

### Anti-Patterns to Avoid

| Anti-Pattern | Why Bad | Instead Do |
|--------------|---------|------------|
| jadx-gui for automation | Requires human interaction | Use jadx CLI |
| Storing decompiled code in apks/ | Mixes input and output | Separate directories |
| Duplicating config in each language | Maintenance nightmare | Single source of truth |
| Hardcoding tool paths | Breaks on different systems | Environment variables |
| Running decompilation synchronously | Slow for large APKs | Allow background processing |

### Integration Points

| Component | Integrates With | How |
|-----------|-----------------|-----|
| decompile.sh | extract-apk.sh | Reads APK path from output |
| index-output.py | jadx output | Parses decompiled sources |
| test_harness.py | config.json | Reads endpoints, credentials |
| playwright tests | config.json | Reads API paths, test IDs |
| Frida scripts | .env | Reads package name |

## Sources

Research sources used:

- [jadx GitHub Repository](https://github.com/skylot/jadx) - Official documentation for command line options and JSON output
- [Apktool CLI Parameters](https://apktool.org/docs/cli-parameters/) - Official CLI documentation
- [APK Reverse Engineering Workflow](https://www.marginaldeer.com/blog/apk-reverse-engineering-workflow/) - Workflow patterns
- [Dotenv Managing Environment Variables](https://configu.com/blog/dotenv-managing-environment-variables-in-node-python-php-and-more/) - Cross-language configuration
- [python-dotenv GitHub](https://github.com/theskumar/python-dotenv) - Python configuration loading
- [Managing Multiple Languages in Monorepo](https://graphite.com/guides/managing-multiple-languages-in-a-monorepo) - Polyglot configuration patterns
- [JADX Android Decompiler MCP Server](https://www.pulsemcp.com/servers/mobilehackinglab-jadx-android-decompiler) - Advanced automation capabilities

## Confidence Assessment

| Area | Confidence | Rationale |
|------|------------|-----------|
| Existing architecture | HIGH | Based on direct codebase analysis |
| jadx integration | HIGH | Official documentation confirms CLI options |
| apktool integration | HIGH | Official documentation confirms CLI options |
| Configuration approach | HIGH | Industry standard pattern (dotenv) |
| Data flow design | MEDIUM | Logical but not yet validated |
| Index format | MEDIUM | JSON is reasonable but specifics may need iteration |
