#include "uTor_crypto_aes.h"

//TODO: Change all function names to uTor_
//TODO: memory_zero instead of RtlSecureZeroMemory

typedef struct {
	BCRYPT_KEY_DATA_BLOB_HEADER blob_header;
	BYTE aes_key[CRYPTO_AES256_KEY_LEN];
} CRYPTO_AES256_KEY_BLOB;

BOOL crypto_aes_init_state(CRYPTO_AES_CTR_CTXT* ctr_state, const BYTE* key, const UINT8 key_sz, const BYTE* iv) {
	RtlSecureZeroMemory(ctr_state, sizeof(CRYPTO_AES_CTR_CTXT));

	if (iv != NULL)
		memory_copy(ctr_state->aes_ctr, iv, sizeof(ctr_state->aes_ctr));

	ctr_state->aes_ctr_byte_index = sizeof(ctr_state->aes_ctr);

	CRYPTO_AES256_KEY_BLOB aes_key_blob = { 0 };
	aes_key_blob.blob_header.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	aes_key_blob.blob_header.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	aes_key_blob.blob_header.cbKeyData = key_sz;
	memory_copy(aes_key_blob.aes_key, key, key_sz);

	return (BCRYPT_SUCCESS(BCryptImportKey(BCRYPT_AES_ECB_ALG_HANDLE, NULL, BCRYPT_KEY_DATA_BLOB, &ctr_state->h_key, NULL, 0, &aes_key_blob, sizeof(aes_key_blob), 0)));
}

BOOL crypto_aes_crypt_message(CRYPTO_AES_CTR_CTXT* ctr_state, BYTE* data, const SIZE_T data_sz) { //used for both encryption and decryption due to the nature of how CTR mode AES works!
	for (SIZE_T c_index = 0; c_index != data_sz; c_index++) {
		if (ctr_state->aes_ctr_byte_index == sizeof(ctr_state->aes_ctr)) {
			ULONG res = 0; //for some stupid reason required.
			if (!BCRYPT_SUCCESS(BCryptEncrypt(ctr_state->h_key, ctr_state->aes_ctr, sizeof(ctr_state->aes_ctr), NULL, NULL, 0, ctr_state->aes_ctr_out, sizeof(ctr_state->aes_ctr), &res, 0)))
				return FALSE;

			for (BYTE i = sizeof(ctr_state->aes_ctr) - 1; i != 0; i--) {
				if (++ctr_state->aes_ctr[i])
					break;
			}
			ctr_state->aes_ctr_byte_index = 0;
		}
		data[c_index] ^= ctr_state->aes_ctr_out[ctr_state->aes_ctr_byte_index++];
	}
	return TRUE;
}

BOOL crypto_aes_destroy_state(CRYPTO_AES_CTR_CTXT* ctr_state) {
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(ctr_state->h_key)))
		return FALSE;
	RtlSecureZeroMemory(ctr_state, sizeof(CRYPTO_AES_CTR_CTXT));
	return TRUE;
}