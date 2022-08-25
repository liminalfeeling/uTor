#include "uTor_crypto_pk.h"

static BCRYPT_ALG_HANDLE CRYPTHANDLE_ECC25519;

BCRYPT_KEY_HANDLE crypto_ecc25519_import_pubkey(BYTE* pubkey) {
	BCRYPT_KEY_HANDLE remote_pubkey = NULL;
	CRYPTO_ECC25519_BLOB blob;

	memory_zero(&blob, sizeof(CRYPTO_ECC25519_BLOB));
	blob.magic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
	blob.keylen = CRYPTO_ECC25519_KEY_LEN;
	memory_copy(blob.public_key.data, pubkey, CRYPTO_ECC25519_KEY_LEN);

	if (!BCRYPT_SUCCESS(BCryptImportKeyPair(CRYPTHANDLE_ECC25519, NULL, BCRYPT_ECCPUBLIC_BLOB, &remote_pubkey, (PUCHAR)&blob, sizeof(CRYPTO_ECC25519_BLOB), 0)))
		return NULL;

	return remote_pubkey;
}

BCRYPT_KEY_HANDLE crypto_ecc25519_gen_keypair() {
	BCRYPT_KEY_HANDLE new_key_handle = NULL;
	CRYPTO_ECC25519_BLOB blob;

	memory_zero(&blob, sizeof(CRYPTO_ECC25519_BLOB));
	blob.magic = BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC;
	blob.keylen = CRYPTO_ECC25519_KEY_LEN;

	if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, blob.private_key.data, CRYPTO_ECC25519_KEY_LEN, 0)))
		return NULL;

	blob.private_key.data[0] &= 248;
	blob.private_key.data[31] &= 127;
	blob.private_key.data[31] |= 64;

	if (!BCRYPT_SUCCESS(BCryptImportKeyPair(CRYPTHANDLE_ECC25519, NULL, BCRYPT_ECCPRIVATE_BLOB, &new_key_handle, (PUCHAR)&blob, sizeof(CRYPTO_ECC25519_BLOB), 0)))
		return NULL;
	return new_key_handle;
}

BOOL crypto_ed25519_derive_shared_secret(BYTE* secret_out, BCRYPT_KEY_HANDLE pubkey, BCRYPT_KEY_HANDLE privkey) {
	BCRYPT_SECRET_HANDLE shared_secret_handle = NULL;
	ULONG result_size = CRYPTO_ECC25519_KEY_LEN;
	BOOL ret = FALSE;

	if (BCRYPT_SUCCESS(BCryptSecretAgreement(privkey, pubkey, &shared_secret_handle, 0))) {
		if (BCRYPT_SUCCESS(BCryptDeriveKey(shared_secret_handle, BCRYPT_KDF_RAW_SECRET, NULL, secret_out, result_size, &result_size, 0))) {
			for (BYTE low = 0, high = CRYPTO_ECC25519_KEY_LEN - 1; low < high; low++, high--) { //The KFD_RAW_SECRET function outputs the secret in little endian.
				BYTE temp = secret_out[low];
				secret_out[low] = secret_out[high];
				secret_out[high] = temp;
				ret = TRUE;
			}
		}
	}

	return (BCRYPT_SUCCESS(BCryptDestroySecret(shared_secret_handle)) && ret);
}

BOOL crypto_pk_init() {
	if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&CRYPTHANDLE_ECC25519, BCRYPT_ECDH_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0)))
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptSetProperty(CRYPTHANDLE_ECC25519, BCRYPT_ECC_CURVE_NAME, (PBYTE)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0)))
		return FALSE;
	return TRUE;
}