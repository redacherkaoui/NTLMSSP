# Anomalies in SMB2/NTLMSSP Authentication Pipelines

## Executive Summary

A class of emergent vulnerabilities in the compositional processing of SMB2 authentication—particularly at the intersection of Preauth Integrity Context propagation and SPNEGO-wrapped NTLMSSP token exchange. Through nuanced manipulation of context length arithmetic, buffer descriptors, and protocol transition states, an attacker may leverage congruence mismatches between metadata and memory operations to achieve anomalous heap behaviors on Windows SMB servers.

---

## Technical Exposition 

### 1. Context-Space Drift in Negotiation Handlers

Within the SMB2 dialect negotiation and context vectorization routines, the cumulative length aggregator (commonly denoted `uVar17` or `totalContextLength`) is incremented by traversing the entire set of negotiated contexts—including but not limited to Extended Attributes, Preauth Integrity, and VendorInfo. The data segment for each context, referenced via relative offsets, is then consolidated into a single ephemeral allocation.

A subtlety arises when the Preauth Integrity (PI) context is finalized: the implementation utilizes the *aggregate* context vector’s advertised length as the effective bound for a subsequent memory copy, rather than the actual PI data section’s DataLength. Consequently, `memmove` or similar calls may overflow the local heap cell, especially if an attacker has staged adjacent heap metadata (via controlled context ordering or repeated negotiations).

The vector misalignment is tied to context ordering and length field aliasing.

### 2. OID Encapsulation and Non-Deterministic Buffer Sizing in SPNEGO/NTLMSSP Flows

During authentication, the OID selector in `spnego.dll` or `ksecdd.sys` relays the negotiated mechanism (commonly NTLM) to the Security Support Provider (SSP) stack. This is conducted via a secondary IOCTL transaction, with the SPNEGO-encapsulated blob directly exposed to LSASS (`msv1_0.dll`).

At the critical entry point (typically a function akin to `FUN_180001920`), the code path:

    memcpy(ctx, SecBuffer, in_buf_len); // in_buf_len is attacker-supplied

operates on an allocation whose upper bound is frequently static (e.g., 0x160 bytes), regardless of in_buf_len. This is immediately followed by ASCII string token checks, e.g., verifying "NTLMSSP\0" at the head. There is no guarantee that the inbound length respects the actual allocation—yielding a classical, yet obfuscated, heap overrun vector.

Some code review tools might flag the string matching, but not the unbounded memcpy. Chasing the OID selector logic will reveal a maze of mechanism handlers that, for most research efforts, appear robust—unless allocation granularity and LSASS data section tracing is employed.

### 3. NTLM Challenge Emission: Caller-Context Buffer Size Neglect

The construction of the Type 2 NTLM Challenge (notably in handlers such as FUN_1800234F8 and friends) emits protocol-mandated headers and entropy into a caller-provided buffer. There is insufficient validation of buffer size against emission length; a truncated buffer risks clobbering return addresses or subsequent heap records, depending on LSASS memory layout and IOCTL path.

### 4. State Conflation via SMB2 Session Multiplexing

Under stress or race conditions—especially when handling multiple parallel SESSION_SETUP requests—stateful SMB2 servers may incorrectly merge context propagation logic across session boundaries. This phenomenon is exacerbated by misaligned session IDs, and can obfuscate heap grooming attempts (or, for the casual researcher, hide the true corruption primitive behind a veil of unrelated STATUS_INVALID_PARAMETER returns).

---

## Impact

An unauthenticated network adversary with access to SMB TCP/445 may, by careful construction of negotiation vectors and SPNEGO/NTLMSSP authentication sequences, induce out-of-bounds writes in both kernel (SMB2 context marshaling) and userland (NTLMSSP context import) on a remote server. While denial-of-service is immediately demonstrable, weaponization may require advanced heap grooming, orchestrated session races, or deep protocol state cycling.






