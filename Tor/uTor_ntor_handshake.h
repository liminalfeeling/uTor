#pragma once
#include "uTor_node_info.h"
#include "../Cryptography/uTor_crypto_aes.h"
#include "../Cryptography/uTor_crypto.h"

#define TOR_HANDSHAKE_ID_TAP_BE 0
#define TOR_HANDSHAKE_ID_RESERVED 0x0001
#define TOR_HANDSHAKE_ID_NTOR_BE 512

typedef struct {
	CRYPTO_AES_CTR_CTXT crypto_state_f;
	CRYPTO_AES_CTR_CTXT crypto_state_b;
	BCRYPT_KEY_HANDLE running_hash_f;
	BCRYPT_KEY_HANDLE running_hash_b;
	BYTE last_running_hash_b[CRYPTO_SHA1_HASH_LEN];
} TOR_NTOR_CRYPTO_STATE;

#pragma pack(push)
#pragma pack(1)
typedef struct {
	UINT16 h_type;
	UINT16 h_len;
	BYTE identity_fp[CRYPTO_SHA1_HASH_LEN]; //Server identity digest  [ID_LENGTH bytes]
	BYTE ntor_onion_key[32];//KEYID(NTOR_ONION_KEY)[H_LENGTH(32) bytes]
	BYTE client_pk_raw[CRYPTO_ECC25519_KEY_LEN]; // CLIENT_PK   X [G_LENGTH bytes]
} TOR_NTOR_HANDSHAKE_DATA;
#pragma pack(pop)

BOOL tor_ntor_gen_handshake_data(TOR_NTOR_HANDSHAKE_DATA* new_handshake_data, TOR_NODE_INFO* target_node, BCRYPT_KEY_HANDLE client_keypair);
BOOL tor_ntor_init_crypto_state(TOR_NTOR_HANDSHAKE_DATA* used_handshake_data, TOR_NTOR_CRYPTO_STATE* new_ntor_crypto_state, BYTE server_pubkey_raw[32], BYTE serv_auth_hash[32], BCRYPT_KEY_HANDLE client_keypair);