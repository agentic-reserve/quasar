# Deep Audit Report: Account Lifecycle Operations

**Functions:** `resize()`, `set_lamports()`, `realloc_account()`, `Account::close()`  
**Location:** `lang/src/accounts/account.rs`  
**Criticality:** CRITICAL - Directly manipulate account state and lamports

---

## Function 1: `resize()` - Account Data Resizing

**Location:** `account.rs:36-80`  
**Lines:** 45

### Purpose

Resizes account data and tracks accumulated resize delta in the `padding` field. This is a **reimplementation** of upstream v2's removed `resize()` using the padding bytes as an `i32` resize delta.

### Inputs & Assumptions

**Explicit Inputs:**
- `view: &mut AccountView` - Account to resize
- `new_len: usize` - Target data length

**RuntimeAccount Layout Assumptions:**
```
offset 0x00: borrow_state (1 byte)
...
offset 0x48: data_len (8 bytes, u64)
offset 0x50: padding (4 bytes, reused as i32 resize delta)
```

**Critical Assumptions:**
1. `padding` at offset 0x50 is 4 bytes (can hold i32)
2. `MAX_PERMITTED_DATA_INCREASE` (10KB) is never exceeded
3. SVM provides 10KB realloc region after account data
4. `RuntimeAccount` layout is stable (enforced by compile-time assert)

### Outputs & Effects

**Success:**
- Updates `data_len` to `new_len`
- Accumulates resize delta in `padding` field
- Zero-fills newly allocated bytes (if growing)

**Failure:**
- `InvalidRealloc` if resize would exceed 10KB increase
- `InvalidRealloc` if `new_len` doesn't fit in i32

### Block-by-Block Analysis

#### Block 1: Length Validation (Lines 36-45)

```rust
let raw = view.account_mut_ptr();
let current_len = unsafe { (*raw).data_len } as i32;
let new_len_i32 = i32::try_from(new_len).map_err(|_| ProgramError::InvalidRealloc)?;

if new_len_i32 == current_len {
    return Ok(());
}
```

**What:** Gets current length, validates new length fits in i32.

**Safety:**
- `account_mut_ptr()` returns valid `RuntimeAccount` pointer
- Dereferencing `raw` is safe (AccountView guarantees validity)

**First Principles:**
- **Why i32?** Solana's resize delta tracking uses signed 32-bit
- **Why check equality first?** Fast path for no-op resizes
- **Why try_from?** Prevents truncation of large usize values

**Invariant:** `current_len` and `new_len_i32` are valid i32 values

---

#### Block 2: Delta Calculation & Accumulation (Lines 47-63)

```rust
let difference = new_len_i32 - current_len;

let delta_ptr = unsafe { core::ptr::addr_of_mut!((*raw).padding) as *mut i32 };
let accumulated = unsafe { delta_ptr.read_unaligned() } + difference;

if crate::utils::hint::unlikely(accumulated > MAX_PERMITTED_DATA_INCREASE as i32) {
    return Err(ProgramError::InvalidRealloc);
}

unsafe {
    (*raw).data_len = new_len as u64;
    delta_ptr.write_unaligned(accumulated);
}
```

**What:** Calculates size difference, accumulates delta, updates fields.

**Critical Safety Analysis:**

**Pointer Arithmetic:**
```rust
let delta_ptr = unsafe { core::ptr::addr_of_mut!((*raw).padding) as *mut i32 };
```

- Uses `addr_of_mut!` to get field address without creating reference
- Cast to `*mut i32` interprets 4 padding bytes as signed integer
- `read_unaligned`/`write_unaligned` handle potential misalignment

**5 Whys for Unaligned Access:**
1. Why unaligned? Padding field may not be 4-byte aligned
2. Why not aligned? RuntimeAccount layout prioritizes other fields
3. Why prioritize? SVM memory layout constraints
4. Why constraints? Backward compatibility with older versions
5. Why compatibility? Existing accounts on-chain

**Security Check:**
```rust
if accumulated > MAX_PERMITTED_DATA_INCREASE as i32 {
```
- `MAX_PERMITTED_DATA_INCREASE` = 10 * 1024 = 10,240 bytes
- Prevents unbounded growth (denial of service via large allocations)
- Tracks cumulative growth across multiple resizes

**Invariant Established:** `accumulated <= 10,240` (10KB limit)

---

#### Block 3: Zero-Fill (Lines 65-77)

```rust
if difference > 0 {
    unsafe {
        core::ptr::write_bytes(
            view.data_mut_ptr().add(current_len as usize),
            0,
            difference as usize,
        );
    }
}
```

**What:** Zero-fills newly allocated bytes when growing account.

**Safety:**
- `data_mut_ptr()` returns valid pointer to account data
- `add(current_len)` points to first new byte
- `difference` bytes were just validated as within bounds

**Security Importance:**
- Prevents data leakage from previous account contents
- SVM may reuse memory regions
- Zero-fill is security best practice

**5 Hows for Bounds Safety:**
1. How do we know pointer is valid? AccountView guarantees it
2. How do we know offset is valid? `current_len` was original data_len
3. How do we know size is valid? `difference = new - current`, both validated
4. How do we know total is in bounds? `MAX_PERMITTED_DATA_INCREASE` check
5. How do we prevent overflow? `i32` arithmetic, checked conversion

---

### Security Analysis

#### Vulnerability 1: Integer Overflow in Delta
**Risk:** `accumulated + difference` could overflow i32

**Current Mitigation:**
- Both `accumulated` and `difference` are bounded by 10KB limit
- `i32` max is ~2 billion, 10KB << 2 billion
- Realistically impossible to overflow

**Verdict:** Safe (defense in depth sufficient)

#### Vulnerability 2: Negative Delta Underflow
**Risk:** Shrinking could make `accumulated` negative, breaking future growth checks

**Analysis:**
- `accumulated` is signed i32
- Shrinking (negative difference) correctly reduces accumulated
- Subsequent growth checks against 10KB limit still valid
- Negative accumulated allows more future growth (correct behavior)

**Verdict:** By design, not a vulnerability

#### Vulnerability 3: Padding Field Corruption
**Risk:** Other code might write to padding field, corrupting delta

**Analysis:**
- Padding field is explicitly reserved in RuntimeAccount
- No other code should access it
- Compile-time assertion checks offset hasn't changed

**Verdict:** Low risk (relying on upstream contract)

---

## Function 2: `set_lamports()` - Lamport Mutation

**Location:** `account.rs:87-92`  
**Lines:** 6

### Purpose

Sets lamport balance on an account, used for cross-account mutations.

### Code

```rust
pub fn set_lamports(view: &AccountView, lamports: u64) {
    unsafe { 
        (*(view.account_ptr() as *mut RuntimeAccount)).lamports = lamports 
    };
}
```

### Security Analysis

**Critical Issue:** Takes `&AccountView` (immutable reference) but performs mutable write!

**Why This Is Safe (Per Solana Model):**
1. SVM input buffer is inherently mutable
2. `&AccountView` is a view into SVM-owned memory
3. Solana runtime permits lamport mutations within transactions
4. Borrow checker doesn't know about SVM guarantees

**5 Whys for Safety:**
1. Why cast `*const → *mut`? AccountView is immutable reference
2. Why safe? SVM buffer is actually writable
3. Why writable? Transaction must modify accounts
4. Why modify? State changes are the point of transactions
5. Why bypass borrow checker? FFI/syscall boundary

**Risk:** If caller passes non-SVM account view, this is UB

**Mitigation:** This function is only called in SVM context

---

## Function 3: `realloc_account()` - Full Reallocation

**Location:** `account.rs:97-135`  
**Lines:** 39

### Purpose

Complete reallocation: resize data + adjust lamports for rent exemption.

### Logic Flow

```
1. Calculate rent-exempt lamports for new_space
2. Compare to current lamports
3. If short: transfer from payer
4. If excess: return to payer
5. Zero trailing bytes if shrinking
6. Call resize() to update data_len
```

### Critical Path Analysis

#### Rent Calculation (Lines 103-108)

```rust
let rent_exempt_lamports = if let Some(r) = rent {
    r.try_minimum_balance(new_space)?
} else {
    crate::sysvars::rent::Rent::get()?.try_minimum_balance(new_space)?
}
```

**Security:** Rent sysvar is trusted (provided by SVM)

#### Lamport Transfer (Lines 112-119)

**Case 1: Need more lamports**
```rust
crate::cpi::system::transfer(payer, &*view, rent_exempt_lamports - current_lamports)
    .invoke()?;
```
- CPI to system program
- Transfers from payer to account

**Case 2: Excess lamports**
```rust
let excess = current_lamports - rent_exempt_lamports;
view.set_lamports(rent_exempt_lamports);
set_lamports(payer, payer.lamports() + excess);
```
- Direct lamport manipulation (no CPI)
- Updates both accounts atomically

**Security Concern:** No check that payer is different from account

**Attack Scenario:**
```rust
// If payer == account
view.set_lamports(rent_exempt);  // Set to rent-exempt
set_lamports(payer, payer.lamports() + excess);  // Adds excess to itself
// Result: account has (rent_exempt + excess) instead of rent_exempt
```

**Mitigation:** Caller must ensure payer ≠ account (usually enforced by `#[account(...)]` constraints)

**Recommendation:** Add debug assertion:
```rust
debug_assert!(view.address() != payer.address(), "payer cannot be the account being reallocated");
```

#### Zero-Fill on Shrink (Lines 124-130)

```rust
if new_space < old_len {
    unsafe {
        core::ptr::write_bytes(view.data_mut_ptr().add(new_space), 0, old_len - new_space);
    }
}
```

**Security:** Prevents data leakage when shrinking
**Safety:** `new_space < old_len`, so range is valid

---

## Function 4: `Account::close()` - Account Destruction

**Location:** `account.rs:198-226`  
**Lines:** 29

### Purpose

Closes a program-owned account: zeros discriminator, drains lamports, reassigns to system program.

### Logic Flow

```
1. Check destination is writable
2. Zero discriminator bytes
3. Transfer all lamports to destination
4. Set own lamports to 0
5. Reassign owner to system program
6. Resize to 0
```

### Block-by-Block Security Analysis

#### Block 1: Writable Check (Lines 201-203)

```rust
if crate::utils::hint::unlikely(!destination.is_writable()) {
    return Err(ProgramError::Immutable);
}
```

**Critical:** Prevents closing to non-writable account

**Why Important:**
- Lamport transfer would fail silently or cause issues
- SVM enforces writability on destination
- Quasar adds explicit check for clear error

---

#### Block 2: Zero Discriminator (Lines 208-214)

```rust
unsafe {
    core::ptr::write_bytes(
        view.data_mut_ptr(),
        0,
        <T as crate::traits::Discriminator>::DISCRIMINATOR.len(),
    );
}
```

**Security:** Prevents "account resurrection" attacks

**Attack Without This:**
1. Attacker closes account (lamports drained)
2. Attacker reallocates same address with minimum lamports
3. Old data still present (including discriminator)
4. Program thinks account is valid type
5. Attacker exploits type confusion

**Defense:** Zeroing discriminator makes account appear uninitialized

---

#### Block 3: Lamport Transfer (Lines 217-219)

```rust
let new_lamports = destination.lamports().wrapping_add(view.lamports());
set_lamports(destination, new_lamports);
view.set_lamports(0);
```

**Critical:** `wrapping_add` instead of `checked_add`

**Risk Analysis:**
- Total SOL supply ~5.8e17 lamports
- `u64::MAX` is ~1.8e19
- Sum of two valid lamport balances cannot overflow u64
- Realistically impossible

**Order Matters:**
1. Add to destination FIRST
2. Then set source to 0

**Attack if Reversed:**
```rust
view.set_lamports(0);  // Source now 0
destination.set_lamports(destination.lamports() + 0);  // Destination unchanged!
// Result: lamports lost (burned)
```

**Current Order:** Correct (safe)

---

#### Block 4: Owner Reassignment (Line 223)

```rust
unsafe { view.assign(&SYSTEM_PROGRAM_ID) };
```

**Security:** Account is now owned by system program

**Why Important:**
- System program is the "uninitialized" state
- Prevents program from accessing closed account
- Required for proper cleanup

---

#### Block 5: Resize to Zero (Line 224)

```rust
resize(view, 0)?;
```

**Security:** Minimizes rent-exempt balance requirement

**Note:** This doesn't free memory (SVM doesn't support that), but sets data_len to 0.

---

### Security Properties of Close Operation

| Property | Implementation | Status |
|----------|---------------|--------|
| Discriminator zeroed | `write_bytes(..., 0, disc_len)` | ✅ |
| Lamports transferred | `wrapping_add` to destination | ✅ |
| Owner reassigned | `assign(SYSTEM_PROGRAM_ID)` | ✅ |
| Data minimized | `resize(view, 0)` | ✅ |
| Destination writable | Explicit check | ✅ |

---

## Cross-Function Analysis

### Shared Invariants

1. **Pointer Validity:** All functions assume AccountView provides valid RuntimeAccount pointer
2. **SVM Context:** All unsafe operations assume running in SVM (not off-chain)
3. **Rent Compliance:** Operations maintain rent-exemption invariants

### Vulnerability Chain Analysis

**Scenario: Malicious Resize Loop**
```rust
// Attacker repeatedly grows and shrinks account
loop {
    resize(&mut account, 10_240)?;  // Max growth
    resize(&mut account, 0)?;      // Shrink
}
```

**Impact:** 
- Accumulated delta grows each iteration (10KB each time)
- Eventually hits 10KB limit
- Not exploitable (limit enforced)

**Verdict:** Safe (bounded)

---

## Recommendations

### Immediate
1. Add `debug_assert!` in `realloc_account()` for payer ≠ account check
2. Document that `set_lamports()` requires SVM context

### Short-Term
3. Add test for close-resurrection attack prevention
4. Add test for lamport overflow scenarios (theoretical)

### Long-Term
5. Consider `checked_add` for lamports (defense in depth)
6. Document all unsafe pointer operations with security rationale

---

## Overall Assessment

**Status:** SECURE with minor improvements recommended

**Risk Level:** LOW-MEDIUM

**Key Strengths:**
- Clear safety comments on all unsafe blocks
- Compile-time assertions for struct layout
- Rent exemption properly maintained
- Discriminator zeroing prevents resurrection

**Areas for Improvement:**
- Add more defensive assertions
- Document SVM context requirements

