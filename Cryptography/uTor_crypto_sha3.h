#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h> //for htonll

#define CRYPTO_SHA3_256_HASH_LEN 32 //(256 / 8
#define CRYPTO_SHA3_256_HS3_HMAC_LEN 32

#define KECCAKF_ROUNDS 24
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

#define crypto_shake128_init(c) crypto_sha3_init(c, 16)
#define crypto_shake256_init(c) crypto_sha3_init(c, 32)
#define crypto_shake_update crypto_sha3_update

typedef struct {
    union {                                 // state:
        BYTE b[200];                        // 8-bit bytes
        UINT64 q[25];                       // 64-bit words
    } st;
    INT32 pt, rsiz, mdlen;                  // these don't overflow
} CRYPTO_SHA3_CTXT;

// Compression function.
VOID crypto_sha3_keccakf(UINT64 st[25]);

// OpenSSL - like interfece
VOID crypto_sha3_init(CRYPTO_SHA3_CTXT* c, INT32 mdlen);    // mdlen = hash output in bytes
VOID crypto_sha3_update(CRYPTO_SHA3_CTXT* c, CONST BYTE* data, SIZE_T len);
VOID crypto_sha3_final(BYTE* md, CRYPTO_SHA3_CTXT* c);    // digest goes to md
 
// SHAKE128 and SHAKE256 extensible-output functions
VOID crypto_shake_xof(CRYPTO_SHA3_CTXT* c);
VOID crypto_shake_out(CRYPTO_SHA3_CTXT* c, BYTE* out, SIZE_T len);
 
VOID crypto_sha3_tor_hs3_hmac(BYTE* mac_out, BYTE* key, UINT64 key_len, BYTE* message, UINT64 message_len);