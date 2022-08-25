#pragma once
#include "../Cryptography/uTor_crypto_aes.h"
#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Cryptography/uTor_crypto_pk.h"
#include "uTor_hs3_descriptor.h"

typedef struct {
	CRYPTO_AES_CTR_CTXT crypto_state_f;
	CRYPTO_AES_CTR_CTXT crypto_state_b;
	CRYPTO_SHA3_CTXT running_hash_f;
	CRYPTO_SHA3_CTXT running_hash_b;
	BYTE last_running_hash_b[CRYPTO_SHA3_256_HASH_LEN];
} TOR_HS3_NTOR_CRYPTO_STATE;

//Handshake info as specified in rendspec v3.
#pragma pack(push)
#pragma pack(1)
typedef struct {
	BYTE server_pk[CRYPTO_ECC25519_KEY_LEN];
	BYTE auth_key[CRYPTO_SHA3_256_HS3_HMAC_LEN];
} TOR_HS3_NTOR_HANDSHAKE_DATA;
#pragma pack(pop)

//takes the data buffer and makes enc buffer = CLIENT PK + ENC(data_buffer) + MAC(mac_data)
BOOL tor_hs3_ntor_generate_data(BYTE* enc_data, UINT32 enc_data_sz, BYTE* out_buffer, UINT32 out_buffer_sz, BYTE* mac_data, UINT32 mac_data_sz, BCRYPT_KEY_HANDLE client_keypair, TOR_HS3_INTRO_POINT* intro_point, BYTE* blinded_hs3_service_pubkey, MODULE_TORCONN_HEADER* module_header);
BOOL tor_hs3_ntor_init_node_crypto_state(TOR_HS3_NTOR_HANDSHAKE_DATA* handshake_data, TOR_HS3_NTOR_CRYPTO_STATE* new_hs3_crypto_state, TOR_HS3_INTRO_POINT* intro_point, BCRYPT_KEY_HANDLE client_keypair);
