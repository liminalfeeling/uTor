#include "../Platform/uTor_memory.h"
#include "uTor_hs3_ntor_handshake.h"
#include "uTor_hs3_calc.h"
#include "string.h"

//TODO: We can hs3 ntor way better, and merge it with regular ntor, and clean them both up.

#define INTRO_SECRET_HS_INPUT_LEN (32 + 32 + 32 + 32 + 33)

	/*
	The PROTOID for this variant is "tor-hs-ntor-curve25519-sha3-256-1".
	We also use the following tweak values:
	t_hsenc    = PROTOID | ":hs_key_extract"
	t_hsverify = PROTOID | ":hs_verify"
	t_hsmac    = PROTOID | ":hs_mac"
	m_hsexpand = PROTOID | ":hs_key_expand"
	*/

#define T_PROTOID "tor-hs-ntor-curve25519-sha3-256-1"
#define T_PROTOID_SZ sizeof(T_PROTOID) - 1

#define T_HSENC "tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract"
#define T_HSENC_SZ (sizeof(T_HSENC) - 1)
#define T_HSVERIFY "tor-hs-ntor-curve25519-sha3-256-1:hs_verify"
#define T_HSVERIFY_SZ sizeof(T_HSVERIFY) - 1
#define T_HSMAC "tor-hs-ntor-curve25519-sha3-256-1:hs_mac"
#define T_HSMAC_SZ (sizeof(T_HSMAC) - 1)
#define M_HSEXPAND "tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand"
#define M_HSEXPAND_SZ (sizeof(M_HSEXPAND) - 1)

#define REND_SECRET_HS_INPUT_LEN (32 * 2 + 32 + 32 * 3 + T_PROTOID_SZ)

	//Encrypts enc_data of enc_sz and makes out_buffer = PLAIN(CLIENT PK) + ENC(data_buffer) + PADDING + PLAIN(MAC(mac_data))
BOOL tor_hs3_ntor_generate_data(BYTE* enc_data, UINT32 enc_data_sz, BYTE* out_buffer, UINT32 out_buffer_sz, BYTE* mac_data, UINT32 mac_data_sz, BCRYPT_KEY_HANDLE client_keypair, TOR_HS3_INTRO_POINT* intro_point, BYTE* blinded_hs3_service_pubkey, MODULE_TORCONN_HEADER* module_header) {

	/*To make an INTRODUCE1 cell, the client must know a public encryption
	key B for the hidden service on this introduction circuit. The client
	generates a single-use keypair:
	x,X = KEYGEN()*/

	BCRYPT_KEY_HANDLE intro_enc_key = crypto_ecc25519_import_pubkey(intro_point->enc_key_ntor); //B
	if (intro_enc_key == NULL)
		return FALSE;

	BYTE shared_secret_hs_dk[CRYPTO_ECC25519_KEY_LEN];
	if (!crypto_ed25519_derive_shared_secret(shared_secret_hs_dk, intro_enc_key, client_keypair)) //EXP(B (intro_enc_key),x (private_client_key))
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(intro_enc_key)))
		return FALSE;

	CRYPTO_ECC25519_BLOB client_keypair_blob;
	if (BCryptExportKey(client_keypair, NULL, BCRYPT_ECCPRIVATE_BLOB, &client_keypair_blob, sizeof(CRYPTO_ECC25519_BLOB), &client_keypair_blob.keylen, 0) != 0)
		return FALSE;

	//intro_secret_hs_input[161] = EXP(B,x) | AUTH_KEY | X | B | PROTOID
	BYTE intro_secret_hs_input[(CRYPTO_ECC25519_KEY_LEN * 4) + T_PROTOID_SZ];
	memory_copy(intro_secret_hs_input, shared_secret_hs_dk, CRYPTO_ECC25519_KEY_LEN); //EXP(B,x)
	memory_copy(intro_secret_hs_input + (CRYPTO_ECC25519_KEY_LEN * 1), intro_point->auth_key, CRYPTO_ECC25519_KEY_LEN); //AUTH_KEY
	memory_copy(intro_secret_hs_input + (CRYPTO_ECC25519_KEY_LEN * 2), client_keypair_blob.public_key.data, CRYPTO_ECC25519_KEY_LEN); //X
	memory_copy(intro_secret_hs_input + (CRYPTO_ECC25519_KEY_LEN * 3), intro_point->enc_key_ntor, CRYPTO_ECC25519_KEY_LEN); //B
	memory_copy(intro_secret_hs_input + (CRYPTO_ECC25519_KEY_LEN * 4), T_PROTOID, T_PROTOID_SZ); //PROTOID

	//info = m_hsexpand | subcredential
	BYTE info[M_HSEXPAND_SZ + CRYPTO_ECC25519_KEY_LEN] = { 0 };
	memory_copy(info, M_HSEXPAND, M_HSEXPAND_SZ);
	tor_hs3_calc_subcredential(blinded_hs3_service_pubkey, module_header->hsvc_credential, info + M_HSEXPAND_SZ);

	struct {
		BYTE enc_key[CRYPTO_AES256_KEY_LEN]; //ENC_KEY = hs_keys[0:S_KEY_LEN]
		BYTE mac_key[CRYPTO_SHA3_256_HS3_HMAC_LEN]; //MAC_KEY = hs_keys[S_KEY_LEN:S_KEY_LEN + MAC_KEY_LEN]
	} hs_keys;

	/*hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN + MAC_LEN)*/
	CRYPTO_SHA3_CTXT sha3_ctx;
	crypto_shake256_init(&sha3_ctx);
	crypto_shake_update(&sha3_ctx, intro_secret_hs_input, sizeof(intro_secret_hs_input)); //intro_secret_hs_input
	crypto_shake_update(&sha3_ctx, T_HSENC, T_HSENC_SZ); //t_hsenc
	crypto_shake_update(&sha3_ctx, info, sizeof(info)); //info
	crypto_shake_xof(&sha3_ctx);
	crypto_shake_out(&sha3_ctx, &hs_keys, sizeof(hs_keys));

	//TODO: Eventually refactor this and make it generalized for both descriptor decryption and hs3 nTor encryption, it would work in theory because AES ctr is both an enc and dec function in 1.
	//takes the raw buffer and makes enc buffer = CLIENT PK + ENC(data_buffer) + MAC(mac_data + CLIENT_PK & ENCRYPTED_DATA)
	//hs3  * Instantiate MAC(key=k, message=m) with H(k_len | k | m), where k_len is htonll(len(k)).
	///Everything follows a SALT + ENCRYPTED DATA + MAC style. Can we maybe combine sTor_hs3_ntor_generate_data, with hs3 descriptor decryption?

	memory_copy(out_buffer, client_keypair_blob.public_key.data, CRYPTO_ECC25519_KEY_LEN);

	CRYPTO_AES_CTR_CTXT ctr_state;
	if (!crypto_aes_init_state(&ctr_state, hs_keys.enc_key, CRYPTO_AES256_KEY_LEN, NULL))
		return FALSE;
	if (!crypto_aes_crypt_message(&ctr_state, enc_data, enc_data_sz))
		return FALSE;
	if (!crypto_aes_destroy_state(&ctr_state))
		return FALSE;

	crypto_sha3_tor_hs3_hmac(out_buffer + (out_buffer_sz - CRYPTO_SHA3_256_HS3_HMAC_LEN), hs_keys.mac_key, sizeof(hs_keys.mac_key), mac_data, mac_data_sz);
	DEBUG_VERBOSE("Successfully performed encryption and message authentication of the specified ntor data.");
	return TRUE;
}

BOOL tor_hs3_ntor_init_node_crypto_state(TOR_HS3_NTOR_HANDSHAKE_DATA* handshake_data, TOR_HS3_NTOR_CRYPTO_STATE* new_hs3_crypto_state, TOR_HS3_INTRO_POINT* intro_point, BCRYPT_KEY_HANDLE client_keypair) {
	CRYPTO_ECC25519_BLOB client_keypair_blob;
	if (BCryptExportKey(client_keypair, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)&client_keypair_blob, sizeof(CRYPTO_ECC25519_BLOB), &client_keypair_blob.keylen, 0) != 0) //X - Client public key
		return FALSE;

	//rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
	struct {
		BYTE expyx[32]; //EXP(Y,x)
		BYTE expbx[32]; //EXP(B,x)
		BYTE auth_key[32]; //AUTH_KEY
		BYTE B[32]; //B
		BYTE X[32]; //X
		BYTE Y[32]; //Y
		BYTE PROTOID[T_PROTOID_SZ]; //PROTOID
	} rend_secret_hs_input = { 0 };

	BCRYPT_KEY_HANDLE server_pub_key = crypto_ecc25519_import_pubkey(handshake_data->server_pk); //Y - SERVER_PK
	if (server_pub_key == NULL)
		return FALSE;
	if (!crypto_ed25519_derive_shared_secret(rend_secret_hs_input.expyx, server_pub_key, client_keypair)) //EXP(Y,x)
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(server_pub_key)))
		return FALSE;

	BCRYPT_KEY_HANDLE intro_enc_key = crypto_ecc25519_import_pubkey(intro_point->enc_key_ntor); //B - Introduction point enc key.
	if (intro_enc_key == NULL)
		return FALSE;
	if (!crypto_ed25519_derive_shared_secret(rend_secret_hs_input.expbx, intro_enc_key, client_keypair)) //EXP(B,x)
		return FALSE;
	if (!BCRYPT_SUCCESS(BCryptDestroyKey(intro_enc_key)))
		return FALSE;


	memory_copy(rend_secret_hs_input.auth_key, intro_point->auth_key, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(rend_secret_hs_input.B, intro_point->enc_key_ntor, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(rend_secret_hs_input.X, client_keypair_blob.public_key.data, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(rend_secret_hs_input.Y, handshake_data->server_pk, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(rend_secret_hs_input.PROTOID, T_PROTOID, T_PROTOID_SZ);

	// verify = MAC(ntor_secret_input, t_hsverify)
	BYTE verify[CRYPTO_SHA3_256_HS3_HMAC_LEN] = { 0 };
	crypto_sha3_tor_hs3_hmac(verify, &rend_secret_hs_input, sizeof(rend_secret_hs_input), T_HSVERIFY, T_HSVERIFY_SZ); //verify
	//TODO: try to remove all "SOME_ARRAY = {0} / RtlSecureZeroMemory" for all source files.

	// auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
	struct {
		BYTE verify[CRYPTO_SHA3_256_HS3_HMAC_LEN];
		BYTE auth_key[CRYPTO_SHA3_256_HS3_HMAC_LEN];
		BYTE B[CRYPTO_ECC25519_KEY_LEN];
		BYTE Y[CRYPTO_ECC25519_KEY_LEN];
		BYTE X[CRYPTO_ECC25519_KEY_LEN];
		BYTE PROTOID[T_PROTOID_SZ];
		BYTE server_tag[6];
	} auth_input = { 0 };

	memory_copy(auth_input.verify, verify, CRYPTO_SHA3_256_HS3_HMAC_LEN);
	memory_copy(auth_input.auth_key, intro_point->auth_key, CRYPTO_SHA3_256_HS3_HMAC_LEN); //AUTH_KEY
	memory_copy(auth_input.B, intro_point->enc_key_ntor, CRYPTO_ECC25519_KEY_LEN); //B
	memory_copy(auth_input.Y, handshake_data->server_pk, CRYPTO_ECC25519_KEY_LEN); //Y
	memory_copy(auth_input.X, client_keypair_blob.public_key.data, CRYPTO_ECC25519_KEY_LEN); //X
	memory_copy(auth_input.PROTOID, T_PROTOID, T_PROTOID_SZ); //PROTOID
	memory_copy(auth_input.server_tag, "Server", sizeof("Server") - 1); //"Server"

	// AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
	BYTE auth_input_mac[CRYPTO_SHA3_256_HS3_HMAC_LEN] = { 0 };
	crypto_sha3_tor_hs3_hmac(auth_input_mac, &auth_input, sizeof(auth_input), T_HSMAC, T_HSMAC_SZ);

	//Finally the client verifies that the received AUTH field of HANDSHAKE_INFO is equal to the computed AUTH_INPUT_MAC.
	if (nt_memcmp(auth_input_mac, handshake_data->auth_key, CRYPTO_SHA3_256_HS3_HMAC_LEN) != 0)
		return FALSE;

	/* The hidden service and its client need to derive crypto keys from the
   NTOR_KEY_SEED part of the handshake output. To do so, they use the KDF
   construction as follows: */

   /* The first HASH_LEN bytes of K form the forward digest Df; the next HASH_LEN
  bytes form the backward digest Db; the next S_KEY_LEN bytes form Kf, and the
  final S_KEY_LEN bytes form Kb.  Excess bytes from K are discarded.*/
	struct {
		BYTE digest_forward[CRYPTO_SHA3_256_HASH_LEN];
		BYTE digest_backward[CRYPTO_SHA3_256_HASH_LEN];
		BYTE key_forward[CRYPTO_AES256_KEY_LEN];
		BYTE key_backward[CRYPTO_AES256_KEY_LEN];
	} expanded_keys;

	//K = KDF(NTOR_KEY_SEED | m_hsexpand,    HASH_LEN * 2 + S_KEY_LEN * 2)*/
	BYTE NTOR_KEY_SEED[CRYPTO_SHA3_256_HS3_HMAC_LEN] = { 0 };
	crypto_sha3_tor_hs3_hmac(NTOR_KEY_SEED, &rend_secret_hs_input, sizeof(rend_secret_hs_input), T_HSENC, T_HSENC_SZ); //verify

	CRYPTO_SHA3_CTXT sha3_ctx;
	crypto_shake256_init(&sha3_ctx);
	crypto_shake_update(&sha3_ctx, NTOR_KEY_SEED, sizeof(NTOR_KEY_SEED)); //NTOR_KEY_SEED
	crypto_shake_update(&sha3_ctx, M_HSEXPAND, M_HSEXPAND_SZ); //m_hsexpand
	crypto_shake_xof(&sha3_ctx);
	crypto_shake_out(&sha3_ctx, &expanded_keys, sizeof(expanded_keys));

	crypto_sha3_init(&new_hs3_crypto_state->running_hash_f, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&new_hs3_crypto_state->running_hash_f, expanded_keys.digest_forward, CRYPTO_SHA3_256_HASH_LEN);

	crypto_sha3_init(&new_hs3_crypto_state->running_hash_b, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&new_hs3_crypto_state->running_hash_b, expanded_keys.digest_backward, CRYPTO_SHA3_256_HASH_LEN);

	if (!crypto_aes_init_state(&new_hs3_crypto_state->crypto_state_f, expanded_keys.key_forward, CRYPTO_AES256_KEY_LEN, NULL))
		return FALSE;
	if (!crypto_aes_init_state(&new_hs3_crypto_state->crypto_state_b, expanded_keys.key_backward, CRYPTO_AES256_KEY_LEN, NULL))
		return FALSE;

	DEBUG_SUCCESS("Established a valid encryption context with the hs3-nTor response.");
	return TRUE;
}