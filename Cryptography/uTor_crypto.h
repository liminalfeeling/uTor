//TODO: Make cross platform.

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#include "../Platform/uTor_memory.h"

#define CRYPTO_SHA1_HASH_LEN 20
#define CRYPTO_HMAC_SHA256_LEN 32

BOOL crypto_hmac_sha256(const BYTE* buf_in, const ULONG buf_in_sz, const BYTE* salt_in, const ULONG salt_in_sz, BYTE* hmac_sha256_out);
BOOL crypto_rfc5869_expand_key(BYTE* input, const ULONG input_sz, BYTE* salt_key, const SIZE_T salt_key_sz, BYTE* salt_expand, const SIZE_T salt_expand_sz, BYTE* output, const SIZE_T output_sz);
BOOL crypto_bcrypt_hash_copied_handle(BCRYPT_KEY_HANDLE original, PUCHAR data_in, ULONG data_in_len, PUCHAR data_out, ULONG data_out_len);