The original README, which I deleted, was intentionally misleading and crafted for those with malicious intent.

This project delivers a deep dive into NTLMSSP parsing vulnerabilities within msv1_0.dll, exposing multiple denial-of-service and memory corruption vectors via malformed SMB2 SESSION_SETUP tokens. The accompanying proof-of-concept (poc.c) demonstrates a full authentication flow:

Protocol Reproduction: Clean SMB2 NEGOTIATE and SPNEGO wrapping, with modular credential injection.

Parser Behavior Analysis: Static inspection and offset breakdown reveal unchecked TLV loops and buffer misalignment.

Implementation Discipline: Each request handcrafted with alignment logic, contextual salts, and debug-friendly utilities.

