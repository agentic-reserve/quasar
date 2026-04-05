# Quasar Framework Security Audit Scope

## Executive Summary

**Project:** Quasar - Zero-copy Solana program framework  
**Commit:** `a7f0bca` (with security fixes applied)  
**Repository:** https://github.com/agentic-reserve/quasar  
**Audit Type:** Comprehensive security review  
**Priority:** High (beta software, unaudited, handling financial assets)

---

## 1. Audit Objectives

### Primary Goals
1. **Critical Bug Discovery** - Find bugs that could lead to fund loss, unauthorized access, or program crashes
2. **Security Vulnerability Assessment** - Identify exploitable security flaws
3. **Safety Verification** - Validate `unsafe` code blocks and memory safety guarantees
4. **Correctness Validation** - Ensure cryptographic operations and account validation work correctly
5. **Economic Security** - Assess risks to DeFi protocols built on Quasar

### Success Criteria
- Zero critical/high severity vulnerabilities in production code
- Documented safety invariants for all `unsafe` blocks
- Validated PDA derivation and signature verification
- Confirmed account ownership and permission checks

---

## 2. In-Scope Components

### Core Framework (`lang/`)
| File | Lines | Criticality | Focus Areas |
|------|-------|-------------|-------------|
| `src/lib.rs` | ~263 | **CRITICAL** | Header validation, `decode_header_error`, `keys_eq`, `is_system_program` |
| `src/entrypoint.rs` | ~183 | **CRITICAL** | Dispatch macro, program ID access, account parsing |
| `src/pda.rs` | ~252 | **CRITICAL** | PDA derivation, `verify_program_address`, `based_try_find_program_address` |
| `src/traits.rs` | ~273 | **HIGH** | `ZeroCopyDeref`, `ParseAccounts`, ownership traits |
| `src/accounts/account.rs` | ~292 | **HIGH** | Account operations, resize, realloc, close |
| `src/remaining.rs` | ~273 | **HIGH** | Remaining accounts iterator, duplicate resolution |
| `src/cpi/mod.rs` | ~278 | **HIGH** | Cross-program invocation, `invoke_raw` |
| `src/cpi/buf.rs` | ~92 | **MEDIUM** | Variable-length CPI buffer management |
| `src/dynamic.rs` | ~116 | **MEDIUM** | Dynamic string/vec field handling |
| `src/error.rs` | ~42 | **LOW** | Error definitions |

### Proc Macro Derive (`derive/`)
| File | Lines | Criticality | Focus Areas |
|------|-------|-------------|-------------|
| `src/accounts/mod.rs` | ~889 | **CRITICAL** | Account parsing code generation, duplicate index validation |
| `src/accounts/fields.rs` | ~1520 | **HIGH** | Field validation, init blocks, constraints |
| `src/account/mod.rs` | ~185 | **HIGH** | `#[account]` macro, discriminator validation |
| `src/instruction.rs` | ~400 | **HIGH** | Instruction handler generation, data deserialization |
| `src/program.rs` | ~? | **MEDIUM** | `#[program]` entrypoint generation |

### SPL Integration (`spl/`)
| File | Lines | Criticality | Focus Areas |
|------|-------|-------------|-------------|
| `src/lib.rs` | ~166 | **HIGH** | `impl_program_account!` macro, `ZeroCopyDeref` implementations |
| `src/instructions/*.rs` | ~? | **HIGH** | Token CPI operations (transfer, mint, burn, etc.) |
| `src/interface.rs` | ~? | **HIGH** | `InterfaceAccount`, `TokenInterface` |
| `src/validate.rs` | ~? | **MEDIUM** | Token account validation |

### CLI Tool (`cli/`)
| File | Criticality | Focus Areas |
|------|-------------|-------------|
| `src/main.rs` | **LOW** | Entry point |
| `src/build.rs` | **LOW** | Build command |
| `src/deploy.rs` | **MEDIUM** | Deployment (key handling) |
| `src/idl.rs` | **MEDIUM** | IDL generation |

---

## 3. Out-of-Scope Components

### Explicitly Excluded
- **Examples** (`examples/*`) - Demo code, not production
- **Test Suite** (`tests/*`) - Test programs and harnesses
- **Documentation** - README, docs site content
- **External Dependencies** - All crates.io dependencies (assumed audited separately)
- **Profile Tool** (`profile/`) - Performance profiling (not security-critical)
- **IDL Parser** (`idl/`) - IDL format parsing (not on-chain code)

### Dependency Assumptions
The following upstream crates are **assumed secure** and out of audit scope:
- `solana-program-error`, `solana-account-view`, `solana-address`
- `solana-instruction-view`, `solana-program-log`
- `const-crypto`, `sha2`, `curve25519-dalek`
- `syn`, `quote`, `proc-macro2` (proc macro tooling)

---

## 4. Critical Security Boundaries

### Boundary 1: Account Validation Pipeline
```
SVM Input Buffer → parse_accounts() → AccountView → Type Validation → User Code
```
**Risks:**
- Duplicate account aliasing (writable mutable references)
- Wrong owner checks
- Missing discriminator validation
- Invalid header flags

### Boundary 2: PDA Derivation & Verification
**Critical Functions:**
- `verify_program_address()` - Must validate PDA correctly
- `based_try_find_program_address()` - Must find valid bumps
- `find_program_address_const()` - Must match runtime behavior

**Risks:**
- Off-curve check bypass
- Wrong program ID used in derivation
- Bump collision

### Boundary 3: Cross-Program Invocation (CPI)
**Critical Functions:**
- `invoke_raw()` - Raw syscall wrapper
- `CpiCall::invoke()` - Const-generic CPI builder
- `BufCpiCall::invoke()` - Variable-length CPI

**Risks:**
- Signer escalation
- Unauthorized program invocation
- Data injection

### Boundary 4: Account Lifecycle Operations
**Critical Operations:**
- `Account::close()` - Drain lamports, reassign ownership
- `realloc_account()` - Resize with rent adjustment
- `set_lamports()` - Balance manipulation

**Risks:**
- Lamport theft
- Account resurrection
- Rent exemption bypass

### Boundary 5: Proc Macro Generated Code
**Critical Macros:**
- `#[derive(Accounts)]` - Generates parsing code
- `#[account]` - Generates discriminators, accessors
- `#[instruction]` - Generates dispatch handlers

**Risks:**
- Generated code unsoundness
- Missing validation
- Edge cases not handled

---

## 5. Trust Assumptions & Threat Model

### Trust Assumptions
1. **SVM Guarantees:**
   - Input buffer layout is correct (program_id after ix_data)
   - Account data is properly aligned
   - CPI syscalls enforce standard Solana security rules
   
2. **Developer Behavior:**
   - `#[account(dup)]` is only used with documented safety justification
   - Discriminators are unique and non-zero
   - Account types match on-chain layout

3. **Dependencies:**
   - Upstream Solana crates are secure
   - Crypto libraries are correct

### Threat Model

#### Attacker Capabilities
- Can craft arbitrary transactions
- Can provide malicious account data
- Can manipulate CPI calls (as calling program)
- Can attempt to create duplicate account references

#### Attacker Goals
- Steal funds from programs
- Cause unauthorized state changes
- Crash/block programs (DoS)
- Bypass access controls

#### Not in Threat Model
- SVM runtime exploits (assume SVM is secure)
- Validator-level attacks
- Network-level attacks

---

## 6. Key Areas of Concern (Pre-Audit Findings)

Based on initial code review, the following areas require deep scrutiny:

### 🔴 Critical (Already Fixed in Fork)
1. **Fixed:** `decode_header_error()` missing executable check
2. **Fixed:** Off-chain PDA verification returning errors
3. **Fixed:** PDA duplicate index validation gaps

### 🟡 High (Needs Audit Attention)
4. `unsafe` pointer casts in `keys_eq()`, `is_system_program()`
5. Bump allocator thread safety (though SVM is single-threaded)
6. `ZeroCopyDeref::deref_from_mut()` aliasing potential
7. Proc macro generated code coverage
8. Remaining accounts iterator boundary checks
9. Dynamic field (String/Vec) validation completeness

### 🟢 Medium (Standard Review)
10. Error handling paths
11. Debug assertion coverage
12. Documentation accuracy

---

## 7. Audit Timeline & Deliverables

### Phase 1: Static Analysis & Architecture Review (Week 1)
- [ ] Run `cargo audit`, `cargo geiger` (unsafe count)
- [ ] Run `clippy` with all lints
- [ ] Generate call graphs for critical functions
- [ ] Review all `unsafe` blocks (count: ~50+)
- [ ] Document architectural invariants

### Phase 2: Manual Code Review (Weeks 2-3)
- [ ] Core framework (`lang/src/`)
- [ ] Proc macro derive (`derive/src/`)
- [ ] SPL integration (`spl/src/`)
- [ ] CLI security review (`cli/src/`)

### Phase 3: Testing & Fuzzing (Week 4)
- [ ] Miri testing for undefined behavior
- [ ] Unit test coverage analysis
- [ ] Property-based testing for PDA ops
- [ ] Fuzzing for account parsing

### Phase 4: Report & Remediation (Week 5)
- [ ] Draft findings report
- [ ] Severity classification
- [ ] Remediation guidance
- [ ] Final review

### Deliverables
1. **Executive Summary** - High-level findings for stakeholders
2. **Technical Report** - Detailed vulnerability descriptions
3. **Proof of Concepts** - Demonstrable exploits for confirmed bugs
4. **Remediation Guide** - Step-by-step fix instructions
5. **Post-Audit Testing Plan** - Verification steps after fixes

---

## 8. Success Metrics

- **Critical/High vulnerabilities:** 0 remaining post-fix
- **Unsafe blocks reviewed:** 100%
- **Test coverage increase:** +20% minimum
- **Miri clean:** No UB detected
- **Documentation:** All safety invariants documented

---

## 9. Risk Acceptance

The following are **known and accepted risks**:

1. **Beta Software:** APIs may change, breaking compatibility
2. **No Formal Verification:** Crypto primitives not formally verified
3. **SVM Dependence:** Relies on Solana runtime security guarantees
4. **Proc Macro Complexity:** Generated code is hard to manually audit

---

## 10. Audit Team Requirements

### Required Expertise
- **Rust systems programming** - Memory safety, unsafe code
- **Solana program development** - SVM semantics, account model
- **Cryptography** - Ed25519, SHA-256, PDA derivation
- **DeFi security** - Common exploit patterns, economic attacks

### Tools Required
- `cargo audit`, `cargo geiger`, `cargo clippy`
- `miri` (for undefined behavior detection)
- `cargo fuzz` (for fuzzing)
- Custom linting for `unsafe` blocks

---

## Appendix A: File Inventory

### Total Lines of Code (In-Scope)
| Component | Estimated LOC |
|-----------|---------------|
| `lang/` | ~3,500 |
| `derive/` | ~4,000 |
| `spl/` | ~2,500 |
| `cli/` | ~1,500 |
| **Total** | **~11,500** |

### Unsafe Block Count (Estimated)
| Component | Estimated `unsafe` Blocks |
|-----------|---------------------------|
| `lang/` | ~40 |
| `derive/` | ~10 (generated code) |
| `spl/` | ~15 |
| **Total** | **~65** |

---

## Appendix B: Dependency Tree (Security-Critical)

```
quasar-lang
├── solana-program-error (trust: external)
├── solana-account-view (trust: external)
├── solana-address (trust: external)
├── solana-instruction-view (trust: external)
├── const-crypto (trust: external)
├── sha2 (trust: external, new addition)
└── curve25519-dalek (trust: external, optional)

quasar-spl
└── quasar-lang

quasar-derive
└── syn, quote, proc-macro2 (trust: external)
```

---

## Appendix C: Pre-Audit Checklist

Before audit begins:

- [x] Code compiles without warnings (`cargo check`)
- [x] Tests pass (`cargo test`)
- [x] Clippy clean (`cargo clippy -- -D warnings`)
- [ ] Miri testing enabled
- [ ] Fuzzing harness ready
- [ ] Documentation complete
- [ ] Frozen commit hash documented (current: `a7f0bca`)

---

**Document Version:** 1.0  
**Last Updated:** 2026-04-06  
**Prepared For:** Security Audit Team  
**Contact:** agentic-reserve/quasar maintainers
