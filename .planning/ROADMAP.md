# Roadmap: Android Test Harness

## Overview

Transform the SleepIQ-specific test harness into a general-purpose Android security testing environment. Starting with security hardening and configuration cleanup, then generalizing the codebase, adding proxy integration, APK analysis tooling, and finally extending Frida scripts for comprehensive bypass capabilities.

## Domain Expertise

None

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Configuration & Security** - Replace hardcoded credentials with env vars, secure temp file handling
- [ ] **Phase 2: Generalization** - Remove SleepIQ-specific code, make harness app-agnostic
- [ ] **Phase 3: Proxy Integration** - Configure emulator traffic routing through Burp Suite CE
- [ ] **Phase 4: APK Analysis Tooling** - Integrate jadx and apktool for decompilation
- [ ] **Phase 5: Code Browsing Workflow** - Add workflow for examining decompiled code
- [ ] **Phase 6: Security Bypasses** - Extend Frida scripts for root/emulator detection bypass

## Phase Details

### Phase 1: Configuration & Security
**Goal**: Eliminate hardcoded credentials and insecure temp file storage; establish proper configuration management
**Depends on**: Nothing (first phase)
**Research**: Unlikely (internal refactoring, established patterns)
**Plans**: TBD

Plans:
- [x] 01-01: Environment variable configuration system
- [x] 01-02: Secure credential handling and temp file cleanup

### Phase 2: Generalization
**Goal**: Remove all SleepIQ-specific code and make the harness work with any Android app
**Depends on**: Phase 1
**Research**: Unlikely (internal code cleanup)
**Plans**: 2

Plans:
- [ ] 02-01: Generalize Python harness (rename class, configurable package, optional auth)
- [ ] 02-02: Generalize shell scripts and documentation

### Phase 3: Proxy Integration
**Goal**: Configure Android emulator to route all traffic through Burp Suite CE for interception
**Depends on**: Phase 2
**Research**: Likely (Android emulator proxy configuration)
**Research topics**: Android emulator proxy settings, ADB proxy commands, Burp CA certificate installation on emulator
**Plans**: TBD

Plans:
- [ ] 03-01: Emulator proxy configuration and CA certificate setup
- [ ] 03-02: Verify traffic capture and test with sample app

### Phase 4: APK Analysis Tooling
**Goal**: Integrate jadx and apktool for APK decompilation and analysis
**Depends on**: Phase 1 (uses config system)
**Research**: Likely (external tool integration)
**Research topics**: jadx CLI usage and output format, apktool CLI usage, integration patterns
**Plans**: TBD

Plans:
- [ ] 04-01: jadx integration for Java source decompilation
- [ ] 04-02: apktool integration for resource extraction

### Phase 5: Code Browsing Workflow
**Goal**: Create workflow for navigating and examining decompiled APK code
**Depends on**: Phase 4
**Research**: Unlikely (internal workflow using Phase 4 tools)
**Plans**: TBD

Plans:
- [ ] 05-01: Code browsing scripts and output organization

### Phase 6: Security Bypasses
**Goal**: Extend Frida scripts to bypass root detection and emulator detection
**Depends on**: Phase 2 (harness must be generalized first)
**Research**: Likely (Frida scripting patterns)
**Research topics**: Root detection bypass techniques, emulator detection bypass, common detection methods to hook
**Plans**: TBD

Plans:
- [ ] 06-01: Root detection bypass Frida script
- [ ] 06-02: Emulator detection bypass Frida script

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Configuration & Security | 2/2 | Complete | 2026-01-19 |
| 2. Generalization | 0/2 | Planned | - |
| 3. Proxy Integration | 0/2 | Not started | - |
| 4. APK Analysis Tooling | 0/2 | Not started | - |
| 5. Code Browsing Workflow | 0/1 | Not started | - |
| 6. Security Bypasses | 0/2 | Not started | - |
