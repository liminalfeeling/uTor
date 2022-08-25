#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "../Platform/uTor_memory.h"

#define CRYPTO_AES128_KEY_SZ 16
#define CRYPTO_AES256_KEY_LEN 32
#define CRYPTO_AES_CTR_IV_LEN 16

typedef struct {
	BYTE aes_ctr[CRYPTO_AES_CTR_IV_LEN];
	BYTE aes_ctr_out[CRYPTO_AES_CTR_IV_LEN];
	UINT8 aes_ctr_byte_index;
	BCRYPT_KEY_HANDLE h_key; //Key for receiving messages.
} CRYPTO_AES_CTR_CTXT;

BOOL crypto_aes_init_state(CRYPTO_AES_CTR_CTXT* ctr_state, const BYTE* key, const UINT8 key_sz, const BYTE* iv);
BOOL crypto_aes_crypt_message(CRYPTO_AES_CTR_CTXT* ctr_state, BYTE* data, const SIZE_T data_sz);
BOOL crypto_aes_destroy_state(CRYPTO_AES_CTR_CTXT* ctr_state);