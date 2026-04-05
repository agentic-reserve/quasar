# Branch Comparison Report: Fork vs Upstream

**Fork:** agentic-reserve/quasar  
**Upstream:** blueshift-gg/quasar  
**Date:** 2026-04-06  
**Base Commit:** `1ba0780` (Merge PR #105)

---

## Executive Summary

Your fork is **ahead** of upstream master by **4 audit-related commits** containing:
- Security bug fixes (5 critical fixes)
- Comprehensive audit documentation (5 reports)
- No conflicts with upstream branches

**Recommendation:** Your changes are valuable for upstream - consider submitting as PRs.

---

## Branch Overview

### Upstream Branches

| Branch | Purpose | Status vs Your Fork |
|--------|---------|---------------------|
| `upstream/master` | Main branch | Behind (missing your fixes) |
| `upstream/feat/cleanup` | Code cleanup | Diverged, has additional cleanup |
| `upstream/feat/multisig-deploy` | Multisig feature | Ahead, has client/IDL changes |
| `upstream/sonic/add-audit-command` | Audit tooling | Ahead, has macro improvements |
| `upstream/upstream-fix` | Compilation fixes | Diverged, has SBF fixes |
| `upstream/ci-self-hosted-runner` | CI changes | Same as multisig-deploy base |

### Your Fork's Unique Commits

| Commit | Description | Value to Upstream |
|--------|-------------|-------------------|
| `a7f0bca` | Security fixes (5 bugs) | **HIGH** - Critical fixes |
| `d8f6b00` | Main audit report | **HIGH** - Documentation |
| `a7ef79c` | Deep audit - PDA/Account/Remaining | **MEDIUM** - Analysis |
| `5021a65` | Deep audit master compilation | **MEDIUM** - Analysis |
| `d2db00b` | Automated audit reports | **MEDIUM** - Tooling results |

---

## Detailed Branch Comparison

### 1. upstream/master

**Status:** Your fork is **4 commits ahead**

```
Your fork:  d2db00b docs: complete automated security audit reports
Upstream:   1ba0780 Merge pull request #105
```

**Missing from upstream:**
1. Security bug fixes (executable check, PDA validation, etc.)
2. All audit documentation
3. Automated security scan results

**Recommendation:** Submit PR with security fixes first (highest value).

---

### 2. upstream/feat/cleanup

**Status:** **Diverged** - Cleanup work + your audit docs

**Unique to upstream/cleanup:**
```
9d87b93 chore: remove docs/ from repo and gitignore it
b3a10ef chore: inline check scripts into Makefile
369c996 fix(ci): unblock PR checks
833fa5e fix(lang): restore normal CPI invoke results
264c7aa chore(audit): add invariant guards and finish derive split
dd5df96 fix(lang): harden parsing and split account codegen
40e2852 refactor(cli): tighten command execution
db6b282 chore(workspace): add audit guardrails
5ef3491 chore: checkpoint current work
```

**Note:** The `cleanup` branch removes docs from repo (`.gitignore`) while your fork adds comprehensive audit docs.

**Conflict potential:** MEDIUM - If upstream merges cleanup first, your docs will conflict with `.gitignore`

**Recommendation:** Consider upstreaming docs to separate location (GitHub Wiki?) or as markdown in repo.

---

### 3. upstream/feat/multisig-deploy

**Status:** **Ahead** - Has features your fork lacks

**Unique to upstream/multisig-deploy:**
```
a70832b feat: add `quasar client` command, split IDL and client generation
2b37fd3 fix: wire validate() into dispatch, remove dead public API surface
bdda531 style: fix clippy question_mark
add1311 fix: Go/Python codegen — correct DynVec/DynString prefix handling
ee0d3ca refactor: delete TokenClose trait, use direct CPI
```

**Value:** Client generation and macro improvements are significant features.

**Recommendation:** Merge or cherry-pick these features into your fork.

---

### 4. upstream/sonic/add-audit-command

**Status:** Same commits as `feat/multisig-deploy` base

**Appears to be a feature branch** for audit tooling that hasn't progressed beyond the multisig-deploy base.

**Recommendation:** Monitor for audit-related tooling improvements.

---

### 5. upstream/upstream-fix

**Status:** **Diverged** - Has SBF-specific fixes

**Unique to upstream/upstream-fix:**
```
85cf807 fmt
3ad947c separate abort implementations from solana and bpf
12129bc fmt
dec3592 fix upstream compilation
```

**Value:** SBF compilation fixes may be needed for your fork.

**Potential issue:** Your security fixes + their SBF fixes = compilation conflict?

**Recommendation:** Test `cargo build-sbf` on your fork to verify it compiles for Solana.

---

### 6. upstream/ci-self-hosted-runner

**Status:** Same base as `feat/multisig-deploy`

**No unique commits visible** - likely a CI configuration branch.

---

## Commit Analysis

### Your Security Fixes (a7f0bca)

**Files changed:** 8  
**Insertions:** 118  
**Deletions:** 10

**Key fixes:**
1. `decode_header_error()` - Added executable flag check
2. `pda.rs` - Off-chain PDA verification with `sha2`
3. `derive/accounts/mod.rs` - Strengthened duplicate index validation
4. `spl/lib.rs` - Debug assertion for duplicate account mutable access

**Upstream value:** CRITICAL - These are genuine security bug fixes.

---

### Upstream's Cleanup (feat/cleanup)

**Notable changes:**
- Removes docs from repo (conflict with your audit docs)
- Adds `Makefile` improvements
- Splits account codegen in derive macro
- Adds audit guardrails to workspace

**Upstream value:** MEDIUM - Code organization improvements.

---

### Upstream's Multisig (feat/multisig-deploy)

**Notable changes:**
- New `quasar client` command
- IDL generation split from client generation
- Go/Python codegen fixes for dynamic types
- TokenClose trait deleted (direct CPI instead)

**Upstream value:** HIGH - New features and bug fixes.

---

## Recommendations

### Immediate Actions

1. **Test SBF compilation** on your fork:
   ```bash
   cargo build-sbf
   ```
   If it fails, cherry-pick `3ad947c` from `upstream/upstream-fix`.

2. **Consider cherry-picking** upstream features:
   - `a70832b` - quasar client command
   - `add1311` - Go/Python codegen fixes

### For Upstreaming

3. **Submit security fixes first** (`a7f0bca`):
   - Highest value for upstream
   - Clean, focused PR
   - Fixes real bugs

4. **Audit docs discussion**:
   - Upstream `feat/cleanup` removes docs
   - Your fork adds comprehensive docs
   - Suggest: GitHub Wiki or separate `docs/` repo

### Long-term

5. **Stay synced** with upstream master:
   ```bash
   git fetch upstream
   git merge upstream/master
   ```

6. **Monitor** these branches for valuable commits:
   - `feat/cleanup` - Code quality
   - `feat/multisig-deploy` - Features
   - `upstream-fix` - Compilation fixes

---

## Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Doc conflicts with cleanup | MEDIUM | Separate docs from code PRs |
| SBF compilation fails | LOW | Test and cherry-pick fixes |
| Security fixes rejected | LOW | Fixes are genuine bugs |
| Feature divergence | MEDIUM | Regular upstream sync |

---

## Git Commands for Syncing

```bash
# Add upstream remote
git remote add upstream https://github.com/blueshift-gg/quasar.git

# Fetch all upstream branches
git fetch upstream

# Check what's new in upstream master
git log HEAD..upstream/master --oneline

# Cherry-pick specific upstream commits
git cherry-pick a70832b  # quasar client command

# Merge upstream master (if desired)
git merge upstream/master
```

---

**Conclusion:** Your fork contains valuable security fixes that upstream should accept. The audit documentation is comprehensive but may conflict with upstream's cleanup efforts. Consider separating code fixes from documentation when submitting PRs.
