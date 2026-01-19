# Project Research Summary

**Project:** Android Security Testing Harness Enhancement
**Domain:** Mobile Application Security Testing
**Researched:** 2026-01-19
**Confidence:** HIGH

## Executive Summary

This Android security testing harness is being enhanced from a single-app tool into a generalized platform for APK analysis and runtime bypass testing. The existing foundation is solid: emulator management, SSL pinning bypass via Frida, ADB automation, and Burp Suite integration are all functional. The research reveals that the recommended approach is to add complementary tooling (JADX for decompilation, Apktool for resources, comprehensive bypass scripts) rather than replacing what works.

The recommended build approach follows a layered architecture pattern: establish a centralized configuration layer first (to eliminate hardcoded credentials and enable multi-app support), then add a decompilation pipeline (JADX + Apktool), followed by bypass extensions (root/emulator detection). The existing shell/Python/TypeScript/JavaScript stack is appropriate and should be extended, not replaced. This matches how professional Android security testers organize their tooling.

The primary risks are security-related: hardcoded credentials in source code and world-readable temp files for JWT storage must be addressed immediately before any feature work. Secondary risks include Frida version mismatches causing silent bypass failures and ADB race conditions creating flaky automation. The research provides clear mitigation strategies for each.

## Key Findings

### Recommended Stack

The existing Frida-based toolset is correct. Enhancement should add static analysis capabilities without disrupting working dynamic analysis.

**Core technologies:**
- **JADX 1.5.3**: DEX to Java decompilation for code analysis. Industry standard, includes GUI for interactive browsing, supports search and navigation. Install: `brew install jadx`
- **Apktool 2.12.1**: Resource extraction, smali disassembly, APK rebuilding. Essential for manifest analysis and modification testing. Install: `brew install apktool`
- **FridaBypassKit**: Comprehensive bypass framework for root detection, emulator detection, and debug detection. Handles most common detection methods.
- **Dotenv + JSON config**: Cross-language configuration management. `.env` for secrets, `config.json` for structural configuration.

**Version requirements:**
- Java 17+ (OpenJDK) required for JADX and Apktool
- Frida client/server versions must match exactly

### Expected Features

**Must have (table stakes):**
- APK decompilation pipeline (JADX + Apktool integration)
- Root detection bypass (systematic, not ad-hoc)
- Emulator detection bypass (spoof device properties)
- Data storage inspection (SharedPreferences, SQLite analysis)
- Configuration/profile management (switch between target apps)
- Log capture and analysis automation

**Should have (differentiators):**
- Curated Frida script library for common bypasses
- Credential/secret scanning in decompiled code
- Multi-app profiles with saved configurations
- Decompiled code search with grep patterns

**Defer (v2+):**
- Web dashboard/GUI (CLI + VS Code sufficient)
- Automated IPC component testing (high complexity)
- Play Integrity bypass (most apps do not use it)
- MASTG test case tracking framework
- CI/CD integration (personal tool, not enterprise)

### Architecture Approach

The existing layered architecture (shell orchestration, Python automation, TypeScript API testing, JavaScript runtime bypass) should be preserved and extended. New components plug in as additive layers without modifying working functionality. The decompilation layer sits between APK extraction and code browsing, producing artifacts for downstream analysis.

**Major components:**
1. **Configuration Layer (NEW)**: Centralized `.env` + `config.json` loaded by all language layers, eliminating scattered hardcoded values
2. **Decompilation Layer (NEW)**: `decompile.sh` wrapping JADX and Apktool with standardized output structure under `./decompiled/{package}/`
3. **Bypass Layer (EXTEND)**: Add FridaBypassKit-style scripts for root and emulator detection to existing SSL bypass

**Output directory structure:**
```
decompiled/{package}_v{version}/
  jadx/sources/          # Java source code
  apktool/smali/         # Smali disassembly
  apktool/res/           # Decoded resources
  index/                 # Machine-readable indexes
```

### Critical Pitfalls

1. **Hardcoded credentials in source code** — Active security vulnerability. Implement `.env` files with gitignore, add `detect-secrets` pre-commit hook. Address in Phase 1.

2. **World-readable temp files for JWT storage** — Tokens in `/tmp` accessible to any process. Use app-private directories with restricted permissions. Address in Phase 1.

3. **Silent exception handling** — `except: pass` hides bugs and security issues. Catch specific exceptions, always log with traceback. Address in Phase 2.

4. **Frida version mismatch** — Client/server version differences cause silent failures. Pin versions explicitly, validate at startup. Address in Phase 2.

5. **ADB race conditions** — Commands sent too quickly after boot fail intermittently. Add explicit waits, verify device state with `dumpsys`. Address in Phase 2.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: Security Foundation
**Rationale:** Critical security vulnerabilities must be fixed before any feature work. Research identified hardcoded credentials and world-readable temp files as active risks.
**Delivers:** Secure credential management, proper temp file handling, pre-commit hooks
**Addresses:** Table stakes (config management), foundation for multi-app support
**Avoids:** CP-1 (hardcoded credentials), CP-2 (world-readable temp files)

### Phase 2: Decompilation Pipeline
**Rationale:** Static analysis capability is the primary gap. Requires configuration layer from Phase 1.
**Delivers:** `decompile.sh` wrapper, JADX integration, Apktool integration, output indexing
**Uses:** JADX 1.5.3, Apktool 2.12.1, dotenv configuration
**Implements:** Decompilation Layer from architecture

### Phase 3: Bypass Extensions
**Rationale:** Root and emulator detection bypass complete the testing capability. Benefits from config layer.
**Delivers:** FridaBypassKit integration, emulator detection bypass, root detection bypass
**Addresses:** Table stakes (root detection bypass, emulator detection bypass)
**Avoids:** SP-1 (Frida version mismatch), SP-3 (emulator detection)

### Phase 4: Data Storage Analysis
**Rationale:** MASVS-STORAGE testing is a major gap. Straightforward after core infrastructure.
**Delivers:** SharedPreferences inspection, SQLite database analysis, file permission auditing
**Addresses:** Table stakes (data storage inspection), MASVS-STORAGE coverage

### Phase 5: Generalization
**Rationale:** With infrastructure in place, remove app-specific assumptions to support multiple targets.
**Delivers:** App configuration schema, multi-app profile support, abstraction of hardcoded values
**Addresses:** Differentiators (multi-app profiles)
**Avoids:** GP-1 (tight coupling), GP-3 (over-engineering)

### Phase Ordering Rationale

- **Security first:** Phases 1 addresses vulnerabilities that exist today. No feature work until credentials are secured.
- **Foundation before features:** Configuration layer enables all subsequent phases. Decompilation pipeline is independent of bypass work.
- **Low coupling:** Phases 2-4 are relatively independent after Phase 1. Could potentially be parallelized.
- **Defer generalization:** Extract abstractions only after concrete implementations exist (Rule of Three).

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3:** Bypass techniques vary significantly per app. May need `/gsd:research-phase` for specific detection methods.
- **Phase 5:** Generalization patterns depend on which additional apps are targeted. Research specific apps during planning.

Phases with standard patterns (skip research-phase):
- **Phase 1:** Well-documented. Dotenv is industry standard, pre-commit hooks are straightforward.
- **Phase 2:** JADX and Apktool have excellent official documentation. Standard workflow.
- **Phase 4:** OWASP MASTG provides detailed guidance for storage testing.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | JADX/Apktool/Frida are industry standard, official docs verified |
| Features | HIGH | Based on OWASP MASTG and MASVS standards |
| Architecture | HIGH | Direct codebase analysis, established patterns |
| Pitfalls | MEDIUM-HIGH | OWASP and community sources, some pitfalls need validation |

**Overall confidence:** HIGH

### Gaps to Address

- **Play Integrity bypass:** Research noted this is difficult for MEETS_STRONG_INTEGRITY. Handle on case-by-case basis if encountered.
- **App-specific bypass requirements:** Generic bypasses work for 80% of apps. Stubborn apps may need custom hooks.
- **Index format:** JSON structure proposed but not validated. May need iteration during Phase 2.
- **Flutter/Xamarin apps:** Standard SSL bypass may not work. Note in per-app documentation.

## Sources

### Primary (HIGH confidence)
- [JADX GitHub](https://github.com/skylot/jadx) — Decompilation tool documentation
- [Apktool Official Docs](https://apktool.org/docs/install/) — Resource extraction documentation
- [OWASP MASTG](https://mas.owasp.org/MASTG/) — Mobile security testing standards
- [OWASP MASVS Checklist](https://mas.owasp.org/checklists/) — Feature prioritization
- [Frida Documentation](https://frida.re/docs/android/) — Runtime bypass toolkit
- [Android Security Checklist](https://developer.android.com/training/articles/security-tips) — Official security guidance

### Secondary (MEDIUM confidence)
- [FridaBypassKit](https://github.com/okankurtuluss/FridaBypassKit) — Bypass framework
- [HTTP Toolkit frida-interception](https://github.com/httptoolkit/frida-interception-and-unpinning) — SSL bypass
- [NetSPI SSL Pinning Bypass](https://www.netspi.com/blog/technical-blog/mobile-application-pentesting/four-ways-bypass-android-ssl-verification-certificate-pinning/) — Bypass techniques
- [XDA Play Integrity Guide](https://xdaforums.com/t/guide-how-to-pass-strong-integrity-and-bypass-root-detection-apps-revolut-company-portal-google-wallet-etc-working-as-of-january-13th-2026.4773849/) — Advanced bypass

### Tertiary (LOW confidence)
- Various Medium articles on bypass techniques — Useful for ideas, verify independently
- Frida CodeShare scripts — Quality varies, test before relying

---
*Research completed: 2026-01-19*
*Ready for roadmap: yes*
