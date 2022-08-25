#include "uTor_crypto.h"

BOOL crypto_hmac_sha256(const BYTE* buf_in, const ULONG buf_in_sz, const BYTE* salt_in, const ULONG salt_in_sz, BYTE* hmac_sha256_out) { //256 out.
	BCRYPT_HASH_HANDLE hash_handle = NULL;
	BOOL ret = FALSE;

	if (BCRYPT_SUCCESS(BCryptCreateHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, &hash_handle, NULL, 0, (PUCHAR)salt_in, salt_in_sz, 0)))
		if (BCRYPT_SUCCESS(BCryptHashData(hash_handle, (PUCHAR)buf_in, buf_in_sz, 0)))
			if (BCRYPT_SUCCESS(BCryptFinishHash(hash_handle, hmac_sha256_out, CRYPTO_HMAC_SHA256_LEN, 0)))
				ret = TRUE;

	return (BCRYPT_SUCCESS(BCryptDestroyHash(hash_handle)) && ret);
}

BOOL crypto_rfc5869_expand_key(BYTE* input, const ULONG input_sz, BYTE* salt_key, const SIZE_T salt_key_sz, BYTE* salt_expand, const SIZE_T salt_expand_sz, BYTE* output, const SIZE_T output_sz) { //HMAC sha256
	BYTE pseudo_random_key[CRYPTO_HMAC_SHA256_LEN] = { 0 };
	BYTE res_block[CRYPTO_HMAC_SHA256_LEN] = { 0 };

	//Generate pseudo random key.
	if (!crypto_hmac_sha256(input, input_sz, salt_key, salt_key_sz, pseudo_random_key))
		return FALSE;

	const SIZE_T hmac_buf_sz = CRYPTO_HMAC_SHA256_LEN + salt_expand_sz;
	SIZE_T bytes_remaining = output_sz;
	SIZE_T curr_output_index = 0;

	for (BYTE I = 1; bytes_remaining != 0; I++) {
		BYTE hmac_input[128];
		memory_copy(hmac_input, res_block, CRYPTO_HMAC_SHA256_LEN);
		memory_copy(hmac_input + CRYPTO_HMAC_SHA256_LEN, salt_expand, salt_expand_sz);
		hmac_input[hmac_buf_sz] = I;

		//If we are on the first cycle, ignore the result block, according to spec rfc5869
		const INT32 shft = ((I == 1) ? CRYPTO_HMAC_SHA256_LEN : 0);
		if (!crypto_hmac_sha256(hmac_input + shft, (hmac_buf_sz + 1) - shft, pseudo_random_key, CRYPTO_HMAC_SHA256_LEN, res_block))
			return FALSE;

		SIZE_T bytes_this_cycle = bytes_remaining;
		if (bytes_this_cycle > CRYPTO_HMAC_SHA256_LEN) //clamp to 32, less otw.
			bytes_this_cycle = CRYPTO_HMAC_SHA256_LEN;

		memory_copy(output + curr_output_index, res_block, bytes_this_cycle);
		curr_output_index += bytes_this_cycle;
		bytes_remaining -= bytes_this_cycle;
	}
	return TRUE;
}

BOOL crypto_bcrypt_hash_copied_handle(BCRYPT_KEY_HANDLE original, PUCHAR data_in, ULONG data_in_len, PUCHAR data_out, ULONG data_out_len) {
	BCRYPT_HASH_HANDLE tmp_new_hash = NULL;
	BOOL ret = FALSE;

	if (BCRYPT_SUCCESS(BCryptDuplicateHash(original, &tmp_new_hash, NULL, 0, 0)))
		if (BCRYPT_SUCCESS(BCryptHashData(tmp_new_hash, data_in, data_in_len, 0)))
			if (BCRYPT_SUCCESS(BCryptFinishHash(tmp_new_hash, data_out, data_out_len, 0)))
				ret = TRUE;

	return (BCRYPT_SUCCESS(BCryptDestroyHash(tmp_new_hash)) && ret);
}