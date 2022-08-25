#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/uTor_time.h"
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_base64.h"
#include "uTor_consensus.h"
#include "uTor_http.h"

typedef struct {
	TOR_CONSENSUS* consensus;
	TOR_NODE_INFO latest_node;
	LARGE_INTEGER li_valid_after;
	LARGE_INTEGER li_fresh_until;
	BOOL params_parsed;
	BOOL shared_current_parsed;
	BOOL shared_previous_parsed;
} TOR_NODEINFO_PARSE_DATA;

VOID tor_parse_calc_disaster_srv(UINT64 period_length, UINT64 period_num, BYTE* output_srv) {  //TODO: Check if this works somehow, then cleanup.
	period_length = htonll(period_length);
	period_num = htonll(period_num);

	CRYPTO_SHA3_CTXT sha3_ctxt;
	crypto_sha3_init(&sha3_ctxt, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&sha3_ctxt, TOR_CONSENSUS_SRV_DISASTER_PREFIX, TOR_CONSENSUS_SRV_DISASTER_PREFIX_SZ);

	BYTE dt[sizeof(UINT64) * 2];
	memory_copy(dt, (const BYTE*)&period_length, sizeof(UINT64));
	memory_copy(dt + sizeof(UINT64), (const BYTE*)&period_num, sizeof(UINT64));

	crypto_sha3_update(&sha3_ctxt, (const BYTE*)&dt, sizeof(UINT64) * 2);
	crypto_sha3_final(output_srv, &sha3_ctxt);
}

BOOL tor_consensus_parse_params(CHAR* current_line, TOR_CONSENSUS* consensus) {
	char* context_tk = NULL;
	char* token_data = nt_strtok_s(current_line, " ", &context_tk);

	token_data = nt_strtok_s(NULL, " ", &context_tk);
	if (token_data == NULL)
		return FALSE;

	while (token_data != NULL) {
		char* param_key = token_data;
		while ((*token_data) != '=') {
			token_data++;
			if ((*token_data) == '\0')
				return FALSE;
		}
		(*token_data) = '\0';
		token_data++;

		UINT8 param_value = 0;
		if (nt_sscanf_s(token_data, "%hu", &param_value) != 1)
			return FALSE;

		if (nt_strnicmp("hsdir_interval", param_key, 14) == 0) {
			DEBUG_VERBOSE("%s -> %i", param_key, param_value);
			consensus->time_period_len = param_value;
			if ((consensus->time_period_len > TOR_TIME_PERIOD_LENGTH_MAX) || (consensus->time_period_len < TOR_TIME_PERIOD_LENGTH_MIN))
				return FALSE;
		}
		if (nt_strnicmp("hsdir_spread_fetch", param_key, 18) == 0) {
			DEBUG_VERBOSE("%s -> %i", param_key, param_value);
			consensus->hsdir_spread_fetch = param_value;
			if ((param_value < TOR_HSDIR_SPREAD_FETCH_MIN) || (param_value > TOR_HSDIR_SPREAD_FETCH_MAX))
				return FALSE;
		}
		if (nt_strnicmp("hsdir_n_replicas", param_key, 16) == 0) {
			DEBUG_VERBOSE("%s -> %i", param_key, param_value);
			consensus->hsdir_n_replicas = param_value;
			if ((param_value < TOR_HSDIR_N_REPLICAS_MIN) || (param_value > TOR_HSDIR_N_REPLICAS_MAX))
				return FALSE;
		}
		if (nt_strnicmp("circwindow", param_key, 16) == 0) {
			DEBUG_VERBOSE("%s -> %i", param_key, param_value);
			consensus->circwindow_default = param_value;
			if (param_value == 0)
				return FALSE;
		}
		token_data = nt_strtok_s(NULL, " ", &context_tk);
	}

	return TRUE;
}

BOOL tor_consensus_parse_func(CHAR* current_line, TOR_NODEINFO_PARSE_DATA* parse_data, CHAR** line_context) {
	if (nt_strnicmp(current_line, "params ", 7) == 0) {
		parse_data->params_parsed = TRUE;
		return tor_consensus_parse_params(current_line, parse_data->consensus);
	}
	else
		if (nt_strnicmp(current_line, "shared-rand-", 12) == 0) {
			BOOL is_current = (nt_strnicmp(current_line + 12, "current-value", 13) == 0);

			if (is_current)
				parse_data->shared_current_parsed = TRUE;
			else parse_data->shared_previous_parsed = TRUE;

			const char val_buf[48] = { 0 };
			if (nt_sscanf_s(current_line, "%*48s %*48s %48s", val_buf, 48) != 1)
				return FALSE;

			if (base64_decode(val_buf, 0, (is_current ? parse_data->consensus->current_srv : parse_data->consensus->prev_srv), 32) != 32)
				return FALSE;
		}
		else
			if (nt_strnicmp(current_line, "valid-after ", 12) == 0) {
				TIME_FIELDS valid_after_dt;
				RtlSecureZeroMemory(&valid_after_dt, sizeof(TIME_FIELDS));

				if (nt_sscanf_s(current_line, "%*32s %hu-%hu-%hu %hu:%hu:%hu", &valid_after_dt.Year, &valid_after_dt.Month, &valid_after_dt.Day, &valid_after_dt.Hour, &valid_after_dt.Minute, &valid_after_dt.Second) != 6)
					return FALSE;
				if (!nt_RtlTimeFieldsToTime(&valid_after_dt, &parse_data->li_valid_after))
					return FALSE;
			}
			else
				if (nt_strnicmp(current_line, "fresh-until ", 12) == 0) {
					TIME_FIELDS fresh_until_dt;
					RtlSecureZeroMemory(&fresh_until_dt, sizeof(TIME_FIELDS));

					if (nt_sscanf_s(current_line, "%*32s %hu-%hu-%hu %hu:%hu:%hu", &fresh_until_dt.Year, &fresh_until_dt.Month, &fresh_until_dt.Day, &fresh_until_dt.Hour, &fresh_until_dt.Minute, &fresh_until_dt.Second) != 6)
						return FALSE;
					if (!nt_RtlTimeFieldsToTime(&fresh_until_dt, &parse_data->li_fresh_until))
						return FALSE;
				}
				else
					if (nt_strnicmp(current_line, "r ", 2) == 0) {
						if (parse_data->latest_node.remote_addr.addr_u32 != 0) //missed s line prevention.
							return FALSE;
						BYTE identity_b64[32] = { 0 };
						BYTE digest_b64[32] = { 0 };
						BYTE digest_b64_out[CRYPTO_SHA1_HASH_LEN] = { 0 };
#if (defined(_DEBUG) || defined(_RELEASE_TEST))
						if (nt_sscanf_s(current_line, "r %32s %32s %32s %*hhu-%*hhu-%*hhu %*hhu:%*hhu:%*hhu %hhu.%hhu.%hhu.%hhu %hu", parse_data->latest_node.name, 32, identity_b64, 32, digest_b64, 32, parse_data->latest_node.remote_addr.addr_octet, parse_data->latest_node.remote_addr.addr_octet + 1, parse_data->latest_node.remote_addr.addr_octet + 2, parse_data->latest_node.remote_addr.addr_octet + 3, &parse_data->latest_node.remote_addr.port_u16) != 8)
							return FALSE;
#else
						if (nt_sscanf_s(current_line, "r %*32s %32s %32s %*hhu-%*hhu-%*hhu %*hhu:%*hhu:%*hhu %hhu.%hhu.%hhu.%hhu %hu", identity_b64, 32, digest_b64, 32, parse_data->latest_node.remote_addr.addr_octet, parse_data->latest_node.remote_addr.addr_octet + 1, parse_data->latest_node.remote_addr.addr_octet + 2, parse_data->latest_node.remote_addr.addr_octet + 3, &parse_data->latest_node.remote_addr.port_u16) != 7)
							return FALSE;
#endif
						if (base64_decode(identity_b64, 0, parse_data->latest_node.identity_fingerprint, 20) != 20)
							return FALSE;
						if (base64_decode(digest_b64, 0, digest_b64_out, sizeof(digest_b64_out)) != CRYPTO_SHA1_HASH_LEN)
							return FALSE;

						DWORD cch = sizeof(parse_data->latest_node.server_desc_digest);
						if (!CryptBinaryToStringA(digest_b64_out, CRYPTO_SHA1_HASH_LEN, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, parse_data->latest_node.server_desc_digest, &cch))
							return FALSE;

					}
					else
						if (nt_strnicmp(current_line, "s ", 2) == 0) {
							if ((parse_data->latest_node.remote_addr.addr_u32 == 0)) //missed r line prevention
								return FALSE;

							char* context_tk = NULL;
							char* token_data = nt_strtok_s(current_line, " ", &context_tk);

							if (token_data == NULL)
								return FALSE;

							while (token_data != NULL) {
								if (nt_strnicmp(token_data, "Exit", 4) == 0)
									parse_data->latest_node.flags |= TOR_NODE_INFO_FLAG_EXIT;
								if (nt_strnicmp(token_data, "Guard", 5) == 0)
									parse_data->latest_node.flags |= TOR_NODE_INFO_FLAG_GUARD;
								if (nt_strnicmp(token_data, "Fast", 4) == 0)
									parse_data->latest_node.flags |= TOR_NODE_INFO_FLAG_FAST;
								if (nt_strnicmp(token_data, "HSDir", 5) == 0) //HSDir flag, but strictly for HSDIRv2(HSv3) support.
									parse_data->latest_node.flags |= TOR_NODE_INFO_FLAG_HSDIR_V2; //HSDIR v2 but that is for HSV3... to keep in mind.
								token_data = nt_strtok_s(NULL, " ", &context_tk);
							}

							parse_data->latest_node.flags |= TOR_NODE_INFO_FLAG_CHECKED;
						}

	if ((parse_data->latest_node.remote_addr.addr_u32 != 0) && (parse_data->latest_node.flags != 0)) {
		parse_data->consensus->node_list[parse_data->consensus->num_nodes++] = parse_data->latest_node;
		RtlSecureZeroMemory(&parse_data->latest_node, sizeof(TOR_NODE_INFO));
	}

	return TRUE;
}

BOOL tor_consensus_download(TOR_CONSENSUS* consensus, MODULE_TORCONN_HEADER* module_header) {
	NET_HTTP_GET_REQUEST get_request;
	get_request.resource_path = "/tor/status-vote/current/consensus.z";

	for (UINT8 curr_da_idx = 0; curr_da_idx != HDR_TORCONN_NUM_STORED_DIR_ADDRS; curr_da_idx++) {
		TOR_NODEINFO_PARSE_DATA parse_data;
		memory_zero((BYTE*)&parse_data, sizeof(TOR_NODEINFO_PARSE_DATA));

		parse_data.consensus = consensus;

		consensus->time_period_len = TOR_TIME_PERIOD_LENGTH_DEFAULT;
		consensus->hsdir_n_replicas = TOR_HSDIR_DEFAULT_N_REPLICAS;
		consensus->hsdir_spread_fetch = TOR_HSDIR_DEFAULT_HSDIR_SPREAD_FETCH;
		consensus->circwindow_default = TOR_CONSENSUS_CIRCWINDOW_DEFAULT;
		consensus->num_nodes = 0;

		get_request.tcp_socket = net_tcp_connect(&module_header->dir_addrs[curr_da_idx]);
		if (get_request.tcp_socket == INVALID_SOCKET)
			continue;

		BOOL parse_ok = net_http_get(0, &get_request, tor_consensus_parse_func, &parse_data, TOR_CONSENSUS_MAX_HTTP_DL_SIZE);
		closesocket(get_request.tcp_socket);

		if (!parse_ok)
			continue;
		if ((parse_data.li_fresh_until.QuadPart == 0) || (parse_data.li_valid_after.QuadPart == 0))
			continue;
		if (!parse_data.params_parsed)
			continue;

		consensus->valid_after_posix = tor_time_convert_nt_to_posix(&parse_data.li_valid_after);
		consensus->fresh_until_posix = tor_time_convert_nt_to_posix(&parse_data.li_fresh_until);

		#ifdef _DEBUG
		if (consensus->time_period_len != 1440)
			DEBUG_WARNING("Time period len is deviating from the normal value!");
		#endif

		if (consensus->valid_after_posix >= consensus->fresh_until_posix)
			continue;

		UINT16 curr_time_period = tor_time_calculate_period(tor_time_convert_nt_to_posix(&parse_data.li_valid_after), consensus->time_period_len);
		DEBUG_INFO("Current time period is: %u.", curr_time_period);

		//TODO: Double check this when possible, can we write a test for this?
		if (!parse_data.shared_current_parsed) { //if both the previous and current shared random aren't set we can assume that something went wrong.
			DEBUG_WARNING("COULD NOT FIND THE CURRENT SHARED RAND VALUE, GENERATING IT!");
			tor_parse_calc_disaster_srv(consensus->time_period_len, curr_time_period, consensus->current_srv);
		}
		if (!parse_data.shared_previous_parsed) { //if both the previous and current shared random aren't set we can assume that something went wrong.
			DEBUG_WARNING("COULD NOT FIND THE PREVIOUS SHARED RAND VALUE, GENERATING IT!");
			tor_parse_calc_disaster_srv(consensus->time_period_len, curr_time_period, consensus->prev_srv);
		}

		DEBUG_SUCCESS("The consensus has been successfully parsed, there are currently %i active nodes!", consensus->num_nodes);
		return TRUE;

	}

	DEBUG_ERROR("Failed when attempting to download the consensus.");
	return FALSE;
}

CONST TOR_NODE_INFO* tor_consensus_get_random_node(CONST TOR_CONSENSUS* consensus, CONST BYTE required_flags) {
	CONST TOR_NODE_INFO* tmp_node = NULL;
	UINT8 rand_index = 0;

	if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, (PUCHAR)&rand_index, sizeof(UINT8), 0)))
		return NULL;

	rand_index = (rand_index % consensus->num_nodes);

	for (UINT32 loop_idx = 0; loop_idx != consensus->num_nodes; loop_idx++) {
		tmp_node = &consensus->node_list[rand_index];
		if ((tmp_node->flags & required_flags) == required_flags)
			return tmp_node;
		rand_index = (rand_index + 1) % consensus->num_nodes;
	}
	return NULL;
}

