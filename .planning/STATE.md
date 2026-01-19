# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-19)

**Core value:** Automated setup that takes a macOS with prerequisites and stands up a complete, ready-to-use Android security testing environment — emulator running, proxy configured, bypasses active, analysis tools available.
**Current focus:** Phase 5 — Code Browsing Workflow

## Current Position

Phase: 5 of 6 (Code Browsing Workflow)
Plan: 0 of 1 in current phase
Status: Ready to plan
Last activity: 2026-01-19 — Completed Phase 4: APK Analysis Tooling

Progress: ██████░░░░ 67%

## Performance Metrics

**Velocity:**
- Total plans completed: 8
- Average duration: 6.1 min
- Total execution time: 0.82 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1 | 2 | 17 min | 8.5 min |
| 2 | 2 | 17 min | 8.5 min |
| 3 | 2 | 11 min | 5.5 min |
| 4 | 2 | 6 min | 3 min |

**Recent Trend:**
- Last 5 plans: 6 min, 5 min, 6 min, 3 min, 3 min
- Trend: ↓

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [01-01]: Use python-dotenv for .env loading
- [01-01]: Use dataclass for typed configuration
- [01-01]: No default values for credentials
- [01-02]: Use tempfile.mkstemp for secure temp files
- [01-02]: Set 0o600 permissions (owner read/write only)
- [01-02]: Register cleanup with atexit for automatic removal
- [02-01]: Config module uses Optional types - credentials not required on import
- [02-01]: Template files prefixed with `example_` to indicate they need customization
- [02-01]: `CUSTOMIZE` comments mark all app-specific code sections
- [02-02]: Shell scripts accept package as argument OR from TARGET_PACKAGE env var
- [02-02]: AVD uses generic name `Android_Test_Device`
- [03-01]: Use 10.0.2.2 to reach host's localhost from emulator
- [03-01]: Convert DER to PEM for Android CA certificate compatibility
- [03-02]: configure-proxy.sh supports BURP_PROXY env var (CLI > env > default)
- [04-01]: Output structure decompiled/<app>/<tool>/ for multiple decompilation tools
- [04-01]: Scripts auto-select most recent APK from apks/ if none specified
- [04-02]: Dual tooling approach - jadx for Java source, apktool for manifest/resources

### Deferred Issues

None yet.

### Blockers/Concerns

None yet.

## Session Continuity

Last session: 2026-01-19T20:52:00Z
Stopped at: Completed Phase 2: Generalization
Resume file: None
