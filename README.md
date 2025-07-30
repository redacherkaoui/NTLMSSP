
# Advisory: Potential Heap Corruption in SMB2 Preauth Integrity and SPNEGO/NTLMSSP Parsing

---

## Summary

A logic flaw has been identified in the SMB2 authentication pipeline which, under certain crafted input conditions, can result in **heap-based memory corruption** during the processing of Preauth Integrity Capabilities and SPNEGO-wrapped NTLMSSP tokens. Specifically, misalignment between advertised and actual buffer lengths in negotiate contexts and authentication tokens can lead to unbounded memory writes on the target server.

---

## Technical Details (High-Level)

### 1. SMB2 Preauth Integrity Context Heap Overrun

In the SMB2 “CreateContexts” handler, the server allocates a heap buffer based on the sum of all context lengths (including Extended Attributes, context headers, names, and salt). However, when processing the Preauth Integrity (salt) context, the implementation erroneously uses the *total* CreateContextsLength—rather than the actual salt DataLength—when copying the attacker-supplied blob. As a result, the server will `memmove` more data than the buffer size, overrunning heap memory and corrupting adjacent data structures.

### 2. SPNEGO Wrapper / OID Handling (ksecdd.sys → LSASS)

After initial protocol negotiation, the SPNEGO layer (`spnego.dll`/`ksecdd.sys`) passes NTLM authentication tokens to LSASS. Within `msv1_0.dll`, the parsing function receives an attacker-controlled buffer and performs:

```c
memcpy(ctx, SecBuffer, dataLen);
strncmp((char*)ctx, "NTLMSSP", 8);

No check ensures that dataLen fits within the fixed-size heap allocation (typically 0x160 bytes), so an oversized SPNEGO-wrapped NTLMSSP blob can overflow the heap, potentially leading to memory corruption.

3. NTLM Challenge Output Buffer Omission
When generating the NTLM Type 2 (“Challenge”) message, the server emits an 8-byte "NTLMSSP\0" header and random challenge into the output buffer without verifying the caller-provided length. A too-small buffer will be overrun, risking additional memory corruption if an attacker can influence buffer allocation.

Impact
A remote, unauthenticated attacker with access to TCP port 445 can trigger unbounded heap writes in both kernel mode (SMB2 CreateContext handler) and user mode (SPNEGO/NTLMSSP parser) by sending specially-crafted NEGOTIATE or SESSION_SETUP messages. Successful exploitation may result in denial-of-service (service crash), or—if the heap layout is controlled—arbitrary code execution under elevated privileges.

