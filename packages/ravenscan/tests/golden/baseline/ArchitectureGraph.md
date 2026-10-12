# Architecture Graph

**Scanned:** <TS>
**Schema version:** 1
**Modules:** 1
**Findings:** 1

## Findings

### 🟢 Potentially dead module: app
**Category:** dead_code | **Confidence:** Confidence.LOW

app is not imported by any other module in the project.

**Evidence:** No modules import app.

**Files:** app.py

**Recommendation:** Verify if this module is an entry point or still needed, otherwise remove it.

## Module List
| Module | Lines | Classes | Functions | Imports | Imported By |
|--------|-------|---------|-----------|---------|-------------|
| app | 27 | 0 | 4 | 0 | 0 |