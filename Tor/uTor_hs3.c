#include "uTor_hs3.h"
#include "uTor_hs3_descriptor.h"
#include "../Platform/uTor_debug.h"
#include "../Platform/uTor_memory.h"
#include "uTor_relay.h"
#include "uTor_linkspec.h"
#include "uTor_circuit_extender.h"

enum TOR_HS3_RELAY_COMMANDS {
	TOR_HS3_RELAY_COMMAND_ESTABLISH_INTRO = 32,
	TOR_HS3_RELAY_COMMAND_ESTABLISH_RENDEVOUZ = 33,
	TOR_HS3_RELAY_COMMAND_INTRODUCE1 = 34,
	TOR_HS3_RELAY_COMMAND_INTRODUCE2 = 35,
	TOR_HS3_RELAY_COMMAND_RENDEZVOUS1 = 36,
	TOR_HS3_RELAY_COMMAND_RENDEZVOUS2 = 37,
	TOR_HS3_RELAY_COMMAND_INTRO_ESTABLISHED = 38,
	TOR_HS3_RELAY_COMMAND_RENDEZVOUS_ESTABLISHED = 39,
	TOR_HS3_RELAY_COMMAND_INTRODUCE_ACK = 40
};

#pragma pack(push)
#pragma pack(1)
//TODO: clean this.
struct sTor_hs3_introduce1_enc_data {
	BYTE rendevouz_cookie[TOR_HS3_RENDEVOUZ_COOKIE_LEN]; //RENDEZVOUS_COOKIE [20 bytes]
	BYTE n_extensions; //N_EXTENSIONS [1 byte]
	/* N_EXTENSIONS times:
		  EXT_FIELD_TYPE                         [1 byte]
		  EXT_FIELD_LEN                          [1 byte]
		  EXT_FIELD                              [EXT_FIELD_LEN bytes]*/
	BYTE onion_key_type; //ONION_KEY_TYPE [1 bytes] [01] NTOR: ONION_KEY is 32 bytes long.
	UINT16 onion_key_len; //ONION_KEY_LEN [2 bytes] ntohs(32)
	BYTE onion_key_data[32]; //ONION_KEY [ONION_KEY_LEN bytes]
	BYTE n_spec; //NSPEC (Number of link specifiers) [1 byte] 0x02
	//NSPEC times
	TOR_LINKSPEC_HEADER link_spec_ipv4; //LSTYPE[1], LSLEN[1]
	NETADDR_IPV4 link_spec_ipv4_data; //LSDATA[6]
	TOR_LINKSPEC_HEADER link_spec_legacy_id; //LSTYPE[1], LSLEN[1]
	BYTE link_spec_legacy_id_data[CRYPTO_SHA1_HASH_LEN]; //LSDATA[20]
	TOR_LINKSPEC_HEADER link_spec_ed25519;
	BYTE link_spec_ed25519_id_data[CRYPTO_ECC25519_KEY_LEN];
};

struct sTor_hs3_introduce1_data {
	BYTE legacy_key_id[CRYPTO_SHA1_HASH_LEN]; //In new style INTRODUCE1 cells, LEGACY_KEY_ID is 20 zero bytes
	BYTE auth_key_type; // AUTH_KEY_TYPE for this cell is an Ed25519 public key [02].
	UINT16 auth_key_len; //Bigendian(32)
	BYTE auth_key[CRYPTO_ECC25519_KEY_LEN];
	BYTE n_extensions; //0x00, no extensions exist currently (?)
	struct {
		BYTE client_pk[CRYPTO_ECC25519_KEY_LEN];
		struct sTor_hs3_introduce1_enc_data introduce_data;
		BYTE padding[TOR_MAX_RELAY_PAYLOAD_LEN - (20 + 1 + 2 + 32 + 1 + 32 + sizeof(struct sTor_hs3_introduce1_enc_data) + CRYPTO_SHA3_256_HS3_HMAC_LEN)];
		BYTE mac_key[CRYPTO_SHA3_256_HS3_HMAC_LEN];
	} encrypted;
};
#pragma pack(pop)


BOOL tor_hs3_establish_rendevouz(TOR_CONSENSUS* consensus, TOR_CIRCUIT** new_rendevouz_circuit, BYTE* rendevouz_cookie_out, MODULE_TORCONN_HEADER* module_header) {
	if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, (PUCHAR)rendevouz_cookie_out, TOR_HS3_RENDEVOUZ_COOKIE_LEN, 0)))
		return FALSE;

	TOR_CIRCUIT* hs3_rend_circ = NULL;

	for (INT16 I = 0; I != TOR_HS3_MAX_CONN_ATTEMPTS; I++) {
		DEBUG_VERBOSE("Attempt %hhu to create a hsdir_ret circuit.", I);
		hs3_rend_circ = tor_circuit_define(TOR_HS3_REND_CIRC_SZ, 0, consensus, NULL);
		if (hs3_rend_circ == NULL)
			continue;
		if (tor_circuit_fully_extend(hs3_rend_circ, module_header))
			break;
		if (!tor_circuit_destroy(hs3_rend_circ))
			goto FAILURE;
		hs3_rend_circ = NULL;
	}

	if (hs3_rend_circ == NULL)
		goto FAILURE;;

	if (!tor_relay_send(hs3_rend_circ, 0, TOR_HS3_RELAY_COMMAND_ESTABLISH_RENDEVOUZ, rendevouz_cookie_out, TOR_HS3_RENDEVOUZ_COOKIE_LEN))
		goto FAILURE;

	TOR_RELAY_DATA relay_data;
	if (!tor_relay_recv(hs3_rend_circ, &relay_data))
		goto FAILURE;
	if (relay_data.relay_cmd != TOR_HS3_RELAY_COMMAND_RENDEZVOUS_ESTABLISHED)
		goto FAILURE;

	DEBUG_SUCCESS("Successfully established a rendevouz point.");
	(*new_rendevouz_circuit) = hs3_rend_circ;
	return TRUE;
FAILURE:
	DEBUG_ERROR("An error has occurred, attempting to cleanup then exiting.");
	tor_circuit_destroy(hs3_rend_circ); //TODO: Fix how circuits are destroyed.
	return FALSE;
}

//TODO: clean and double check this code.
BOOL tor_hs3_send_introduce1(BYTE* rendevouz_cookie, BYTE* blinded_hsvc3_key, TOR_NODE_INFO_NTOR* rendevouz_node, TOR_HS3_INTRO_POINT* intro_point, TOR_CONSENSUS* consensus, BCRYPT_KEY_HANDLE client_keypair, MODULE_TORCONN_HEADER* module_header) {
	BOOL ret = FALSE;
	TOR_CIRCUIT* hs3_intro_circ = NULL;

	for (INT16 I = 0; I != TOR_HS3_MAX_CONN_ATTEMPTS; I++) {
		DEBUG_VERBOSE("Attempt %hhu to create a hsdir_ret circuit.", I);
		hs3_intro_circ = tor_circuit_define(TOR_HS3_INTRO_CIRC_SZ, 0, consensus, NULL);
		if (hs3_intro_circ == NULL)
			continue;

		hs3_intro_circ->node_list[hs3_intro_circ->finished_circ_sz - 1].node_info = &intro_point->node_info;
		hs3_intro_circ->node_list[hs3_intro_circ->finished_circ_sz - 1].key_set = TRUE;
		memory_copy(hs3_intro_circ->node_list[hs3_intro_circ->finished_circ_sz - 1].key_data, intro_point->ntor_key, sizeof(intro_point->ntor_key));

		if (tor_circuit_fully_extend(hs3_intro_circ, module_header))
			break;
		if (!tor_circuit_destroy(hs3_intro_circ))
			goto EXIT;
		hs3_intro_circ = NULL;
	}

	if (hs3_intro_circ == NULL)
		goto EXIT;

	//
	struct sTor_hs3_introduce1_data introduce1_data = { 0 };
	introduce1_data.auth_key_len = htons(CRYPTO_ECC25519_KEY_LEN);
	introduce1_data.auth_key_type = 0x02;
	memory_copy(introduce1_data.auth_key, intro_point->auth_key, CRYPTO_ECC25519_KEY_LEN);
	//^ this is correct, otw we would get 2 - Bad message format or 1 - service id unknown.

	struct sTor_hs3_introduce1_enc_data* intro_data = &introduce1_data.encrypted.introduce_data;

	memory_copy(intro_data->rendevouz_cookie, rendevouz_cookie, TOR_HS3_RENDEVOUZ_COOKIE_LEN);
	intro_data->onion_key_type = 0x01; //[01] NTOR: len 32
	intro_data->onion_key_len = ntohs(32);
	memory_copy(intro_data->onion_key_data, rendevouz_node->key_data, CRYPTO_ECC25519_KEY_LEN);

	intro_data->n_spec = 3;
	intro_data->link_spec_ipv4.ls_type = TOR_EXT2_LINKSPEC_TLS_OVER_IPV4;
	intro_data->link_spec_ipv4.ls_len = sizeof(intro_data->link_spec_ipv4_data);
	intro_data->link_spec_ipv4_data = rendevouz_node->node_info->remote_addr;
	intro_data->link_spec_ipv4_data.port_u16 = htons(intro_data->link_spec_ipv4_data.port_u16);
	intro_data->link_spec_legacy_id.ls_type = TOR_EXT2_LINKSPEC_SHA1_IDENTITY;
	intro_data->link_spec_legacy_id.ls_len = sizeof(intro_data->link_spec_legacy_id_data);
	memory_copy(intro_data->link_spec_legacy_id_data, rendevouz_node->node_info->identity_fingerprint, CRYPTO_SHA1_HASH_LEN);
	intro_data->link_spec_ed25519.ls_type = TOR_EXT2_LINKSPEC_ED25519_IDENTITY;
	intro_data->link_spec_ed25519.ls_len = CRYPTO_ECC25519_KEY_LEN;
	memory_copy(intro_data->link_spec_ed25519_id_data, rendevouz_node->node_info->ed25519_identity, CRYPTO_ECC25519_KEY_LEN);

	BYTE* mac_start = &introduce1_data;
	BYTE* mac_end = (((BYTE*)&introduce1_data) + (sizeof(struct sTor_hs3_introduce1_data) - 32));
	INT32 mac_sz = mac_end - mac_start;


	int sz = sizeof(struct sTor_hs3_introduce1_enc_data);
	//MAc entire introduce1_data - 32 bytes.
	if (!tor_hs3_ntor_generate_data(
		&introduce1_data.encrypted.introduce_data, sizeof(struct sTor_hs3_introduce1_enc_data), //+ sizeof(introduce1_data.data.padding)),
		&introduce1_data.encrypted, sizeof(introduce1_data.encrypted),
		mac_start, mac_sz,
		client_keypair, intro_point, blinded_hsvc3_key, module_header))
		goto EXIT;

	if (!tor_relay_send(hs3_intro_circ, 0, TOR_HS3_RELAY_COMMAND_INTRODUCE1, &introduce1_data, sizeof(struct sTor_hs3_introduce1_data)))
		goto EXIT;

	TOR_RELAY_DATA relay_data;
	memory_zero(&relay_data, sizeof(TOR_RELAY_DATA));

	if (!tor_relay_recv(hs3_intro_circ, &relay_data))
		goto EXIT;

	enum TOR_RELAY_CELL_CMD r = relay_data.relay_cmd;
	if (r != TOR_HS3_RELAY_COMMAND_INTRODUCE_ACK) {
		DEBUG_ERROR("Received an unexpected response.");
		goto EXIT;
	}
	if (!(relay_data.data[0] == 0 && relay_data.data[1] == 0)) {
		DEBUG_ERROR("RENDEVOUZ ACK SAYS THERE WAS AN ERROR: %hhu", relay_data.data[1]);
		goto EXIT;
	}

	DEBUG_INFO("Sent an encrypted introduce1 request to HS3 service.");
	ret = TRUE;
EXIT:
	if (!tor_circuit_destroy(hs3_intro_circ))
		return FALSE;
	return ret;
}

//TODO: triple check all functions in here for safety and good cleanup.
BOOL tor_hs3_connect(TOR_HS3_CIRCUIT* circuit_out, TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hs3_dirlist, MODULE_TORCONN_HEADER* module_header) {
	memory_zero(circuit_out, sizeof(TOR_HS3_CIRCUIT));
	TOR_HS3_INTRO_POINT intro_points[TOR_HS3_MAX_NUM_INTRO_POINTS];
	BYTE num_intro_points = 0;

	CONST CRYPTO_ECC25519_KEY* current_blind_key = module_header_get_blinded_hs3_pubkey(module_header, tor_time_calculate_period(consensus->valid_after_posix, consensus->time_period_len));
	if (!tor_hs3_descriptor_download(current_blind_key, consensus, hs3_dirlist, intro_points, &num_intro_points, module_header)) {
		DEBUG_ERROR("Failed to download a valid hs3 descriptor.");
		return FALSE;
	}
		
	BYTE rendevouz_cookie[TOR_HS3_RENDEVOUZ_COOKIE_LEN] = { 0 };
	BOOL rendevouz_success = FALSE;

	BCRYPT_KEY_HANDLE client_keypair = NULL;

	for (INT32 num_attempt = 0; TRUE; num_attempt++) {
		BOOL successful_destroy = tor_circuit_destroy(circuit_out->rend_circuit);
		if(client_keypair != NULL)
			successful_destroy &= BCRYPT_SUCCESS(BCryptDestroyKey(client_keypair));
		if (!successful_destroy) {
			DEBUG_ERROR("Destruction failed in a rendevouz connection attempt.")
			return FALSE;
		}

		circuit_out->rend_circuit = NULL;

		if (num_attempt == TOR_HS3_MAX_CONN_ATTEMPTS)
			break;

		if (!tor_hs3_establish_rendevouz(consensus, &circuit_out->rend_circuit, rendevouz_cookie, module_header)) {
			DEBUG_ERROR("Failed to establish a rendevouz point!");
			circuit_out->rend_circuit = NULL; //Note: Establish rendevouz is guaranteed to destroy the circuit on failure.
			continue; 
		}

		INT32 introduce_node_idx = -1;
		for (BYTE num_curr_intropoint = 0; num_curr_intropoint != num_intro_points; num_curr_intropoint++) {
			client_keypair = crypto_ecc25519_gen_keypair();
			if (client_keypair == NULL)
				continue;
			if(tor_hs3_send_introduce1(rendevouz_cookie, current_blind_key->data, &circuit_out->rend_circuit->node_list[circuit_out->rend_circuit->current_circ_sz - 1], &intro_points[num_curr_intropoint], consensus, client_keypair, module_header)) {
				introduce_node_idx = (INT32)num_curr_intropoint;
				break;
			}
			if (!BCRYPT_SUCCESS(BCryptDestroyKey(client_keypair)))
				goto TERMINATE_ERROR;
			client_keypair = NULL;
		}
		if (introduce_node_idx == -1)
			break;

		TOR_RELAY_DATA relay_data;
		if (tor_relay_recv(circuit_out->rend_circuit, &relay_data, NULL)) {
			enum STOR_RELAY_CELL_CMD r = relay_data.relay_cmd;
			if (r == TOR_HS3_RELAY_COMMAND_RENDEZVOUS2) {
				if (relay_data.data_sz < sizeof(TOR_HS3_NTOR_HANDSHAKE_DATA)) {
					DEBUG_WARNING("Rendevouz2: We have received an invalid response.");
					continue;
				}

				DEBUG_INFO("Rendevouz2: We have received a response containing the server PK and mac.");
				if (tor_hs3_ntor_init_node_crypto_state(relay_data.data, &circuit_out->tor_hs3_crypto_state, &intro_points[introduce_node_idx], client_keypair)) {
					circuit_out->rend_circuit->hs3_crypto_state = &circuit_out->tor_hs3_crypto_state;
					if (!BCRYPT_SUCCESS(BCryptDestroyKey(client_keypair))) {
						client_keypair = NULL;
						goto TERMINATE_ERROR;
					}
					return TRUE;
				}
				else {
					DEBUG_WARNING("Key generation failed, the response from the hs3 service was invalid.");
				}
			}
			else {
				DEBUG_WARNING("Rendevouz2: received an unexpected response.");
			}
		}
		else {
			DEBUG_ERROR("Rendevouz2: Did not receieve a response.");
		}
	}

	TERMINATE_ERROR:
	if (!tor_circuit_destroy(circuit_out->rend_circuit))
		return FALSE;

	if (client_keypair != NULL) {
		if (!BCRYPT_SUCCESS(BCryptDestroyKey(client_keypair)))
			return FALSE;
	}

	DEBUG_ERROR("FAILED TO CONNECT TO THE REQUESTED HS3 SERVICE.");
	return FALSE;
}