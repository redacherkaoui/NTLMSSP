# Static Analysis of SMB NTLMSSP Handlers: Five Unchecked-Parsing Vulnerabilities in `msv1_0.dll`

Modern Windows networks rely on the NTLM Security Support Provider (SSP) to authenticate clients over SMB. In the latest builds of `msv1_0.dll`, a series of static-review findings reveal that NTLMSSP parsing routines perform unguarded memory operations and loops—each missing critical bounds or consistency checks. These flaws allow a remote, unauthenticated attacker to craft malformed NTLM blobs that trigger out-of-bounds reads or writes, potentially leading to denial-of-service or arbitrary code execution.

---

## Background: NTLMSSP in SMB Authentication

When a client initiates NTLM authentication (wrapped in SPNEGO) over SMB:

1. **Negotiate Phase (Type 1):** Client sends supported flags and encoding info.
2. **Challenge Phase (Type 2):** Server returns a nonce challenge.
3. **Authenticate Phase (Type 3):** Client replies with LM and NT responses, plus optional domain/workstation names and AV-pairs.

Each of these message types is parsed in `msv1_0.dll` by distinct handlers. Robust parsing must verify:

* That any **length fields** (e.g., `ntLen`, `lmLen`) combined with their **offsets** never exceed the overall blob size.
* That destination buffers are large enough to hold copied data.
* That length-prefixed loops over AV-pairs cannot run past the blob’s end.

Failure to enforce these checks opens the door to heap or stack corruption.

---

## 1. Unbounded Context Copy in Dispatcher

**Function:** `FUN_180001920`
**Issue:**

```c
// After LocalAlloc(ctx, 0x160):
memcpy(ctx, InBuf, in_buf_len);
```

No check ensures `in_buf_len ≤ 0x160`. An oversized `in_buf_len` immediately overflows the allocated heap block for `ctx`, corrupting adjacent memory.

---

## 2. NT Response Copy Without Bounds Check

**Function:** `FUN_180059768` (Authenticate parser)
**Issue:**

```c
ntLen = *(USHORT *)(InBuf + 20);
ntOff = *(ULONG  *)(InBuf + 24);
// Missing: if (ntOff + ntLen > in_buf_len) → reject
memcpy(ctx->NtResponse, InBuf + ntOff, ntLen);
```

Without verifying the sum of offset and length against the blob size, attackers can overflow the fixed-size `NtResponse` buffer, potentially corrupting heap metadata or control structures.

---

## 3. LM Response Copy Without Bounds Check

**Function:** `FUN_180059768` (Authenticate parser)
**Issue:**

```c
lmLen = *(USHORT *)(InBuf + 12);
lmOff = *(ULONG  *)(InBuf + 16);
// Missing: if (lmOff + lmLen > in_buf_len) → reject
memcpy(ctx->LmResponse, InBuf + lmOff, lmLen);
```

Similarly, the LM response copy omits any guard against out-of-range offsets or lengths, enabling heap overflows of `LmResponse`.

---

## 4. Domain/Workstation Name Copy Without Bounds Check

**Function:** `FUN_180022630` (Negotiate parser)
**Issue:**

```c
domLen = *(USHORT *)(InBuf + 16);
domOff = *(ULONG  *)(InBuf + 20);
if (domLen != 0) {
    memcpy(ctx->Domain, InBuf + domOff, domLen);
}
```

Two critical checks are missing:

1. **Blob-bounds check:** `domOff + domLen ≤ in_buf_len`.
2. **Destination size check:** `domLen ≤ sizeof(ctx->Domain)`.

Without these, both out-of-bounds reads from the input blob and writes into `ctx->Domain` occur. The same issue repeats for the Workstation name (offsets at +24/+28).

---

## 5. AV-Pair (TLV) Loop Without Overall Length Validation

**Function:** `FUN_1800225a0` (AV-scanner helper)
**Issue:**

```c
while (remaining > (length_field + 4)) {
    if ((u & 0xFFFF) == type) return ptr;
    length_field = u >> 16;
    ptr        += length_field + 4;
    remaining  -= length_field + 4;
}
```

This loop trusts each TLV’s internal length to advance pointers, but never ensures that the next `ptr + length_field + 4` remains within the blob’s end. A crafted TLV with an exaggerated length can drive `ptr` far past valid memory, leading to out-of-bounds parsing or a crash (denial-of-service).

---

## Impact

* **Remote, unauthenticated attackers** can send specially crafted NTLM blobs during SMB session setup to corrupt process memory in LSASS—a high-privilege service.
* **Heap overflows** in `ctx` allocations or response buffers can overwrite critical structures, function pointers, or vtables, leading to **elevation to SYSTEM privileges**.
* **Unchecked loops** in AV-pair parsing allow DoS by triggering access violations or infinite loops.

---

## Recommendations

1. **Bounds Enforcement:**

   * Before each `memcpy`, verify `offset + length ≤ blob_size`.
   * Ensure `length ≤ destination_buffer_size`.
2. **Integer-Overflow Checks:**

   * Validate multiplications (e.g., `numEntries * entrySize`) before allocating or looping.
3. **Fuzz Testing:**

   * Augment coverage with malformed NTLM blobs, especially extreme lengths and misaligned offsets.
4. **Code Review:**

   * Audit adjacent SSP handlers for similar patterns—avoiding single-point patches.

---

## Conclusion

Our static analysis of the latest `msv1_0.dll` build reveals a systemic lapse in parsing rigor: every NTLMSSP handler dives into memory operations or loops without verifying input consistency. Addressing these five unchecked-parsing bugs is critical to restoring SMB authentication’s integrity and preventing remote kernel-level compromises in Windows environments.
