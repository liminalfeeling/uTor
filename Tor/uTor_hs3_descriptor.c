#include "uTor_hs3_descriptor.h"
#include "uTor_hs3_calc.h"
#include "../Platform/uTor_time.h"
#include "uTor_linkspec.h"
#include "uTor_cert.h"
#include "../Cryptography/uTor_crypto_aes.h"
#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Platform/uTor_base64.h"
#include "../Networking/uTor_net_parsing.h"
#include "uTor_circuit_extender.h"
#include "uTor_stream.h"
#include "uTor_http.h"

#define TOR_HS3_INTRO_POINT_FLAG_IP_FOUND 1 << 0
#define TOR_HS3_INTRO_POINT_FLAG_LEGACY_IDENT_FOUND 1 << 1
#define TOR_HS3_INTRO_POINT_FLAG_ED25519_FOUND 1 << 2

//TODO: make this neater.
typedef struct {
	BYTE* in_blinded_key;
	BYTE* in_hs3_credential;
	UINT64 out_revision_counter;
	BYTE num_introduction_points;
	TOR_HS3_INTRO_POINT* intro_points; //intro_points[STOR_HS3_MAX_NUM_INTRO_POINTS];
	BYTE layer_data[2][BASE64_ARMORED_MAX_DATA_SZ];
	UINT32 responsible_dir_list[TOR_HSDIR_N_REPLICAS_MAX][TOR_HSDIR_SPREAD_FETCH_MAX];
} TOR_HS3_DESCRIPTOR_PARSE_DATA;

BOOL tor_hs3_descriptor_decrypt_layer(CHAR* current_line, TOR_HS3_DESCRIPTOR_PARSE_DATA* parse_data, CHAR** row_context, BYTE* pre_alloc_data, BYTE* shake_str, UINT16 shake_str_sz) {
	const INT32 decoded_size = base64_decode_armored(row_context, "-----BEGIN MESSAGE-----", 23, "-----END MESSAGE-----", 22, pre_alloc_data, BASE64_ARMORED_MAX_DATA_SZ);
	if (decoded_size < CRYPTO_AES_CTR_IV_LEN + 1 + CRYPTO_SHA3_256_HS3_HMAC_LEN)
		return FALSE;

	BYTE subcredential[CRYPTO_SHA3_256_HASH_LEN];
	tor_hs3_calc_subcredential(parse_data->in_blinded_key, parse_data->in_hs3_credential, subcredential);

	BYTE secret_input[(CRYPTO_SHA3_256_HASH_LEN + sizeof(subcredential) + sizeof(UINT64))];
	memory_copy(secret_input, parse_data->in_blinded_key, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + CRYPTO_ECC25519_KEY_LEN, subcredential, CRYPTO_ECC25519_KEY_LEN);
	memory_copy(secret_input + CRYPTO_ECC25519_KEY_LEN + CRYPTO_ECC25519_KEY_LEN, &parse_data->out_revision_counter, sizeof(UINT64));
	
	//TODO: name this, etc, also we could combine this with the hs3 ntor handshake, make it much more neat.
	struct {
		BYTE secret_key[CRYPTO_AES256_KEY_LEN];
		BYTE secret_iv[CRYPTO_AES_CTR_IV_LEN];
		//BYTE mac_key[STOR_HMAC_SHA256_LEN]; //TODO: Check what the length of this is in the spec.
	} key_res;

	CRYPTO_SHA3_CTXT sha3_ctx;
	crypto_shake256_init(&sha3_ctx);
	crypto_shake_update(&sha3_ctx, secret_input, sizeof(secret_input));
	crypto_shake_update(&sha3_ctx, pre_alloc_data, CRYPTO_AES_CTR_IV_LEN);
	crypto_shake_update(&sha3_ctx, shake_str, shake_str_sz);
	crypto_shake_xof(&sha3_ctx);
	crypto_shake_out(&sha3_ctx, &key_res, sizeof(key_res));

	CRYPTO_AES_CTR_CTXT aes_ctr_state;
	if (!crypto_aes_init_state(&aes_ctr_state, key_res.secret_key, CRYPTO_AES256_KEY_LEN, key_res.secret_iv))
		return FALSE;
	if (!crypto_aes_crypt_message(&aes_ctr_state, pre_alloc_data + CRYPTO_AES_CTR_IV_LEN, (SIZE_T)decoded_size - (SIZE_T)CRYPTO_AES_CTR_IV_LEN))
		return FALSE;
	if (!crypto_aes_destroy_state(&aes_ctr_state))
		return FALSE;
	return TRUE;
}

BOOL tor_hs3_descriptor_parse_second_layer(CHAR* current_line, TOR_HS3_DESCRIPTOR_PARSE_DATA* parse_data, CHAR** row_context) {
	if (parse_data->num_introduction_points == TOR_HS3_MAX_NUM_INTRO_POINTS + 1)
		return TRUE;

	if (nt_strnicmp(current_line, "introduction-point", sizeof("introduction-point") - 1) == 0) {
		BYTE intro_point_data[128];
		if (nt_sscanf_s(current_line, "%*s %128s", intro_point_data, 128) != 1)
			return FALSE;

		const INT32 decoded_sz = base64_decode(intro_point_data, sizeof(intro_point_data), intro_point_data, sizeof(intro_point_data));
		if (decoded_sz < 1)
			return FALSE;

		TOR_HS3_INTRO_POINT* new_intro_point = &parse_data->intro_points[parse_data->num_introduction_points++];
		INT32 bytes_read = 1;

#ifdef _DEBUG
		memory_copy(new_intro_point->node_info.name, "HS3_INTRO_POINT", sizeof("HS3_INTRO_POINT"));
#endif

		for (INT32 I = 0; I != intro_point_data[0]; I++) { //base64_decoded_data[0] = NSPEC
			if ((bytes_read + sizeof(TOR_LINKSPEC_HEADER)) > decoded_sz)
				return FALSE;
			TOR_LINKSPEC_HEADER* current_link = intro_point_data + bytes_read;
			bytes_read += sizeof(TOR_LINKSPEC_HEADER);

			if ((bytes_read + current_link->ls_len) > decoded_sz)
				return FALSE;
			BYTE* ls_data = intro_point_data + bytes_read;
			bytes_read += (current_link->ls_len);

			/*DO SHIT HERE*/
			if (current_link->ls_type == 0) {
				if (current_link->ls_len != 6)
					return FALSE;
				memory_copy(&new_intro_point->node_info.remote_addr, ls_data, 6);
				new_intro_point->node_info.remote_addr.port_u16 = ntohs(new_intro_point->node_info.remote_addr.port_u16);
				new_intro_point->parse_flag |= TOR_HS3_INTRO_POINT_FLAG_IP_FOUND;
			}
			else if (current_link->ls_type == 2) {
				if (current_link->ls_len != sizeof(new_intro_point->node_info.identity_fingerprint))
					return FALSE;
				memory_copy(new_intro_point->node_info.identity_fingerprint, ls_data, sizeof(new_intro_point->node_info.identity_fingerprint));
				new_intro_point->parse_flag |= TOR_HS3_INTRO_POINT_FLAG_LEGACY_IDENT_FOUND;
			}
			else if (current_link->ls_type == 3) {
				/*if (current_link->ls_len != sizeof(new_intro_point->ed25519_node_identity))
					return FALSE;
				memory_copy(new_intro_point->ed25519_node_identity, ls_data, sizeof(new_intro_point->ed25519_node_identity));*/
				new_intro_point->parse_flag |= TOR_HS3_INTRO_POINT_FLAG_ED25519_FOUND;
			}
		}
	}
	else
		if (nt_strnicmp(current_line, "auth-key", sizeof("auth-key") - 1) == 0) {
			if (parse_data->num_introduction_points == 0)
				return FALSE;
			BYTE raw_cert_data[164] = { 0 };
			INT32 decoded_cert_sz = (base64_decode_armored(row_context, "-----BEGIN ED25519 CERT-----", 28, "-----END ED25519 CERT-----", 26, raw_cert_data, sizeof(raw_cert_data)));
			if (!tor_cert_extract(raw_cert_data, decoded_cert_sz, parse_data->intro_points[parse_data->num_introduction_points - 1].auth_key, TOR_CERT_INTRO_AUTH_KEY_SIGNED_WITH_DESC_KEY))
				return FALSE;
		}
		else
			if (nt_strnicmp(current_line, "onion-key ntor", sizeof("onion-key ntor") - 1) == 0) {
				if (parse_data->num_introduction_points == 0)
					return FALSE;

				BYTE b64_buf[48] = { 0 };
				for (BYTE I = 0; I != sizeof(b64_buf) - 1; I++)
					b64_buf[I] = '=';

				if (nt_sscanf_s(current_line, "%*16s %*16s %47s", b64_buf, sizeof(b64_buf) - 1) != 1)
					return FALSE;
				if (base64_decode(b64_buf, BASE64_DECODE_SIZE_ANY, parse_data->intro_points[parse_data->num_introduction_points - 1].ntor_key, CRYPTO_ECC25519_KEY_LEN) != CRYPTO_ECC25519_KEY_LEN)
					return FALSE;
			}
			else
				if (nt_strnicmp(current_line, "enc-key ntor", sizeof("enc-key ntor") - 1) == 0) {
					if (parse_data->num_introduction_points == 0)
						return FALSE;

					BYTE b64_buf[48] = { 0 };
					for (BYTE I = 0; I != sizeof(b64_buf) - 1; I++)
						b64_buf[I] = '=';

					if (nt_sscanf_s(current_line, "%*16s %*16s %47s", b64_buf, sizeof(b64_buf) - 1) != 1)
						return FALSE;
					if (base64_decode(b64_buf, BASE64_DECODE_SIZE_ANY, parse_data->intro_points[parse_data->num_introduction_points - 1].enc_key_ntor, CRYPTO_ECC25519_KEY_LEN) != CRYPTO_ECC25519_KEY_LEN)
						return FALSE;
				}
	return TRUE;
}

BOOL tor_hs3_descriptor_parse_first_layer(CHAR* current_line, TOR_HS3_DESCRIPTOR_PARSE_DATA* parse_data, CHAR** row_context) {
	if (nt_strnicmp(current_line, "encrypted", sizeof("encrypted") - 1) == 0) {
		DEBUG_INFO("Attempting to decrypt the second layer in the descriptor.");
		memory_zero(parse_data->intro_points, sizeof(TOR_HS3_INTRO_POINT) * TOR_HS3_MAX_NUM_INTRO_POINTS);

		if (!tor_hs3_descriptor_decrypt_layer(current_line, parse_data, row_context, parse_data->layer_data[1], "hsdir-encrypted-data", sizeof("hsdir-encrypted-data") - 1))
			return FALSE;
		if (!uTor_http_parse_func_exec(parse_data->layer_data[1] + CRYPTO_AES_CTR_IV_LEN, tor_hs3_descriptor_parse_second_layer, parse_data))
			return FALSE;

		DEBUG_INFO("The descriptor contains information about '%hhu' introduction points.", parse_data->num_introduction_points);

		for (INT32 I = 0; I != parse_data->num_introduction_points; I++) {
			TOR_HS3_INTRO_POINT* intro_point = &parse_data->intro_points[I];
			if (intro_point->parse_flag != (TOR_HS3_INTRO_POINT_FLAG_ED25519_FOUND | TOR_HS3_INTRO_POINT_FLAG_IP_FOUND | TOR_HS3_INTRO_POINT_FLAG_LEGACY_IDENT_FOUND))
				return FALSE;
			DEBUG_VERBOSE("Intro point [%i]: %hhu.%hhu.%hhu.%hhu:%hu", I, intro_point->node_info.remote_addr.addr_octet[0], intro_point->node_info.remote_addr.addr_octet[1], intro_point->node_info.remote_addr.addr_octet[2], intro_point->node_info.remote_addr.addr_octet[3], intro_point->node_info.remote_addr.port_u16);
		}
	}
	return TRUE;
}

BOOL tor_hs3_descriptor_decrypt(CHAR* current_line, TOR_HS3_DESCRIPTOR_PARSE_DATA* parse_data, CHAR** row_context) {
	if (nt_strnicmp(current_line, "revision-counter", sizeof("revision-counter") - 1) == 0) {
		UINT32 tmp_u32 = 0;
		if (nt_sscanf_s(current_line, "%*32s %u", &tmp_u32) != 1)
			return FALSE;

		parse_data->out_revision_counter = htonll((UINT64)tmp_u32);
		DEBUG_VERBOSE("Current revision_counter value: %u", tmp_u32);
	}
	else if (nt_strnicmp(current_line, "superencrypted", sizeof("superencrypted") - 1) == 0) {
		if (parse_data->out_revision_counter == 0xFFFFFFFFFFFFFFFF)
			return FALSE;
		if (!tor_hs3_descriptor_decrypt_layer(current_line, parse_data, row_context, parse_data->layer_data[0], "hsdir-superencrypted-data", sizeof("hsdir-superencrypted-data") - 1))
			return FALSE;
		if (!uTor_http_parse_func_exec(parse_data->layer_data[0] + CRYPTO_AES_CTR_IV_LEN, tor_hs3_descriptor_parse_first_layer, parse_data))
			return FALSE;
	}
	return TRUE;
}

BOOL tor_hs3_descriptor_download(CRYPTO_ECC25519_KEY* blinded_hsvc_pubkey, TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hsdir_list, TOR_HS3_INTRO_POINT* intro_points_out, BYTE* num_intro_points_out, MODULE_TORCONN_HEADER* module_header) {
	DEBUG_INFO("Fetching the hs descriptors data for the pregenerated pubkey.");

	CHAR resource_requested[64] = "/hs/3/";
	DWORD sz = (sizeof(resource_requested)) - (sizeof("/hs/3/") - 1);
	if (!CryptBinaryToStringA(blinded_hsvc_pubkey->data, CRYPTO_ECC25519_KEY_LEN, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, resource_requested + (sizeof("/hs/3/") - 1), &sz))
		return FALSE;

	memory_copy(&resource_requested[sz + (sizeof("/hs/3/") - 1)], ".z\0", 3);

	static TOR_HS3_DESCRIPTOR_PARSE_DATA internal_parse_data;// = memory_alloc(sizeof(TOR_HS3_DESCRIPTOR_PARSE_DATA));
	memory_zero(&internal_parse_data, sizeof(TOR_HS3_DESCRIPTOR_PARSE_DATA)); //In our context (running in an exec, statics are not 0)
	//if (internal_parse_data == NULL)
	//	return FALSE;

	BOOL ret_val = FALSE;

	for (UINT16 replica_num = 0; replica_num != consensus->hsdir_n_replicas; replica_num++) {
		if (!tor_hs3_dirlist_get_responsible_dirs(hsdir_list, consensus, blinded_hsvc_pubkey->data, internal_parse_data.responsible_dir_list, (UINT64)replica_num))
			goto RETURN;

		for (UINT32 curr_fetch_index = 0; curr_fetch_index != consensus->hsdir_spread_fetch; curr_fetch_index++) {
			TOR_CIRCUIT* hs3_ret_circuit = NULL;

			for (INT16 I = 0; I != TOR_HS3_MAX_CONN_ATTEMPTS; I++) {
				DEBUG_VERBOSE("Attempt %hhu to create a hsdir_ret circuit.", I);
				hs3_ret_circuit = tor_circuit_define(TOR_HS3_DESC_FETCH_CIRC_SZ, 0, consensus, hsdir_list->sorted_list[internal_parse_data.responsible_dir_list[replica_num][curr_fetch_index]].node_info);
				if (hs3_ret_circuit == NULL)
					continue;
				if (tor_circuit_fully_extend(hs3_ret_circuit, module_header))
					break;
				if (!tor_circuit_destroy(hs3_ret_circuit)) //Yes, this is called on failure, intentional.
					goto RETURN;
				hs3_ret_circuit = NULL;
			}

			if (hs3_ret_circuit != NULL) {
				TOR_STREAM new_stream;
				BOOL fetch_success = FALSE;

				if (tor_stream_begin(&new_stream, TOR_STREAM_FLAG_OPEN_DIR, hs3_ret_circuit, NULL, 0)) {
					if (new_stream.is_connected) {
						internal_parse_data.out_revision_counter = 0xFFFFFFFFFFFFFFFF;
						internal_parse_data.in_blinded_key = blinded_hsvc_pubkey->data;
						internal_parse_data.in_hs3_credential = module_header->hsvc_credential;
						internal_parse_data.num_introduction_points = 0;
						internal_parse_data.intro_points = intro_points_out;

						NET_HTTP_GET_REQUEST get_request;
						get_request.resource_path = resource_requested;
						get_request.tor_stream = &new_stream;

						fetch_success = net_http_get(NET_HTTP_FLAG_USE_TOR, &get_request, tor_hs3_descriptor_decrypt, &internal_parse_data, TOR_HS3_DESCRIPTOR_MAX_HTTP_DL_SIZE);
						(*num_intro_points_out) = internal_parse_data.num_introduction_points;
					}
					memory_zero(&internal_parse_data, sizeof(TOR_HS3_DESCRIPTOR_PARSE_DATA));
				}

				if (!tor_circuit_destroy(hs3_ret_circuit))
					goto RETURN;

				if (fetch_success) {
					DEBUG_INFO("Successfully fetched the hs3 descriptor data for the remote hsvc.");
					ret_val = TRUE;
					goto RETURN;
				}
			}
			else {
				DEBUG_WARNING("Could not connect to any of the given circuits for this replica.");
			}
		}
	}
RETURN:
	//if (!memory_free(internal_parse_data))
	//	return FALSE;
	return ret_val;
}
