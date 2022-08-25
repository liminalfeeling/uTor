#include "utor_nTor_handshake.h"
#include "memory.h"
#include "../Platform/uTor_debug.h"
#include "../Platform/uTor_string.h"
#include "../Cryptography/uTor_crypto_pk.h"
#include "../Cryptography/uTor_crypto.h"

BOOL tor_ntor_gen_handshake_data(TOR_NTOR_HANDSHAKE_DATA* new_handshake_data, TOR_NODE_INFO_NTOR* target_node, BCRYPT_KEY_HANDLE client_keypair) {
	new_handshake_data->h_type = TOR_HANDSHAKE_ID_NTOR_BE;
	new_handshake_data->h_len = htons(CRYPTO_SHA1_HASH_LEN + (CRYPTO_ECC25519_KEY_LEN * 2));

	memory_copy(new_handshake_data->identity_fp, target_node->node_info->identity_fingerprint, CRYPTO_SHA1_HASH_LEN);
	memory_copy(new_handshake_data->ntor_onion_key, target_node->key_data, sizeof(target_node->key_data));

	CRYPTO_ECC25519_BLOB local_keypair_blob;
	if (BCryptExportKey(client_keypair, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)&local_keypair_blob, sizeof(CRYPTO_ECC25519_BLOB), &local_keypair_blob.keylen, 0) != 0)
		return FALSE;

	memory_copy(new_handshake_data->client_pk_raw, local_keypair_blob.public_key.data, CRYPTO_ECC25519_KEY_LEN);
	return TRUE;
}

//TODO: Merge this and the HS3 one.
BOOL tor_ntor_init_crypto_state(TOR_NTOR_HANDSHAKE_DATA* used_handshake_data, TOR_NTOR_CRYPTO_STATE* new_ntor_crypto_state, BYTE server_pubkey_raw[32], BYTE serv_auth_hash[32], BCRYPT_KEY_HANDLE client_keypair) {
	BCRYPT_KEY_HANDLE remote_pubkey = crypto_ecc25519_import_pubkey(server_pubkey_raw);
	if (remote_pubkey == NULL)
		return FALSE;
	BYTE pkey_shared_secret[CRYPTO_ECC25519_KEY_LEN];
	if (!crypto_ed25519_derive_shared_secret(pkey_shared_secret, remote_pubkey, client_keypair))
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(remote_pubkey)))
		return FALSE;

	BCRYPT_KEY_HANDLE ntor_key = crypto_ecc25519_import_pubkey(used_handshake_data->ntor_onion_key);
	if (ntor_key == NULL)
		return FALSE;
	BYTE nkey_shared_secret[CRYPTO_ECC25519_KEY_LEN];
	if (!crypto_ed25519_derive_shared_secret(nkey_shared_secret, ntor_key, client_keypair))
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(ntor_key)))
		return FALSE;

	const static BYTE proto_id[24] = "ntor-curve25519-sha256-1";
	const static BYTE verif_key[31] = "ntor-curve25519-sha256-1:verify";
	const static BYTE mac_key[28] = "ntor-curve25519-sha256-1:mac";
	const static BYTE salt_key[36] = "ntor-curve25519-sha256-1:key_extract";
	const static BYTE salt_expand[35] = "ntor-curve25519-sha256-1:key_expand";
	const static BYTE server_id[6] = "Server";

	// secret_input = shared pkey | shared nkey | Ident fingerprint | pub ntor onion key | local pub key | serv_pubkey | proto_id
	BYTE secret_input[204];
	BYTE secret_input_hash[32];
	BYTE auth_input[178];
	BYTE auth_hash[32];

	//secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
	memory_copy(secret_input, pkey_shared_secret, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + 32, nkey_shared_secret, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + 32 + 32, used_handshake_data->identity_fp, CRYPTO_SHA1_HASH_LEN);
	memory_copy(secret_input + 32 + 32 + 20, used_handshake_data->ntor_onion_key, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + 32 + 32 + 20 + 32, used_handshake_data->client_pk_raw, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + 32 + 32 + 20 + 32 + 32, server_pubkey_raw, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + 32 + 32 + 20 + 32 + 32 + 32, proto_id, sizeof(proto_id));
	//verify = H(secret_input, t_verify)

	if (!crypto_hmac_sha256(secret_input, 204, verif_key, 31, secret_input_hash))
		return FALSE;

	//auth_input = verify | ID | B | Y | X | PROTOID | "Server"
	memory_copy(auth_input, secret_input_hash, CRYPTO_HMAC_SHA256_LEN);
	memory_copy(auth_input + 32, used_handshake_data->identity_fp, CRYPTO_SHA1_HASH_LEN);
	memory_copy(auth_input + 32 + 20, used_handshake_data->ntor_onion_key, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(auth_input + 32 + 20 + 32, server_pubkey_raw, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(auth_input + 32 + 20 + 32 + 32, used_handshake_data->client_pk_raw, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(auth_input + 32 + 20 + 32 + 32 + 32, proto_id, sizeof(proto_id));
	memory_copy(auth_input + 32 + 20 + 32 + 32 + 32 + 24, server_id, sizeof(server_id));

	//The client verifies that AUTH == H(auth_input, t_mac)
	if (!crypto_hmac_sha256(auth_input, 178, mac_key, 28, auth_hash))
		return FALSE;
	if (nt_memcmp(auth_hash, serv_auth_hash, 32) != 0)
		return FALSE;

	/*   When used in the ntor handshake, the first HASH_LEN bytes form the
   forward digest Df; the next HASH_LEN form the backward digest Db; the
   next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final
   DIGEST_LEN bytes are taken as a nonce to use in the place of KH in the
   hidden service protocol.  Excess bytes from K are discarded.*/

	struct {
		BYTE digest_forward[CRYPTO_SHA1_HASH_LEN];
		BYTE digest_backward[CRYPTO_SHA1_HASH_LEN];
		BYTE key_forward[CRYPTO_AES128_KEY_SZ];
		BYTE key_backward[CRYPTO_AES128_KEY_SZ];
		BYTE hs_nonce[CRYPTO_SHA1_HASH_LEN];
	} expanded_key;

	if (!crypto_rfc5869_expand_key(secret_input, sizeof(secret_input), salt_key, 36, salt_expand, 35, &expanded_key, sizeof(expanded_key)))
		return FALSE;

	memory_zero(new_ntor_crypto_state, sizeof(TOR_NTOR_CRYPTO_STATE));

	if (BCryptCreateHash(BCRYPT_SHA1_ALG_HANDLE, &new_ntor_crypto_state->running_hash_f, NULL, 0, NULL, 0, 0) != 0)
		return FALSE;
	if (BCryptHashData(new_ntor_crypto_state->running_hash_f, expanded_key.digest_forward, CRYPTO_SHA1_HASH_LEN, 0) != 0)
		return FALSE;
	if (BCryptCreateHash(BCRYPT_SHA1_ALG_HANDLE, &new_ntor_crypto_state->running_hash_b, NULL, 0, NULL, 0, 0) != 0)
		return FALSE;
	if (BCryptHashData(new_ntor_crypto_state->running_hash_b, expanded_key.digest_backward, CRYPTO_SHA1_HASH_LEN, 0) != 0)
		return FALSE;

	if (!crypto_aes_init_state(&new_ntor_crypto_state->crypto_state_f, expanded_key.key_forward, CRYPTO_AES128_KEY_SZ, NULL))
		return FALSE;
	if (!crypto_aes_init_state(&new_ntor_crypto_state->crypto_state_b, expanded_key.key_backward, CRYPTO_AES128_KEY_SZ, NULL))
		return FALSE;

	DEBUG_VERBOSE("Successfully intialized the nTor crypto state.");
	return TRUE;
}
