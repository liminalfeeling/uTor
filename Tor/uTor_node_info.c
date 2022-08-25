#include "uTor_node_info.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_base64.h"
#include "uTor_http.h"
#include "uTor_cert.h"

typedef TOR_NODE_INFO_NTOR TOR_NODE_INFO_KEY_GENERIC;

typedef struct _TOR_NODEINFO_PARSE_DATA {
	UINT16 num_node_ptrs;
	TOR_NODE_INFO_KEY_GENERIC* node_info_array;
	BYTE flag;
	INT16 current_node_idx;
} TOR_NODEINFO_PARSE_DATA;

BOOL tor_node_info_serverdesc_parse_ntor(CHAR* current_line, TOR_NODEINFO_PARSE_DATA* parse_data, CHAR** line_context) {
	if (nt_strnicmp(current_line, "router ", 7) == 0) {
		NETADDR_IPV4 ipv4 = { 0 };
		INT32 res = nt_sscanf_s(current_line, "router %*32s %hhu.%hhu.%hhu.%hhu %hu %*hu %*hu", &ipv4.addr_octet[0], &ipv4.addr_octet[1], &ipv4.addr_octet[2], &ipv4.addr_octet[3], &ipv4.port_u16);
		if(res != 5)
			return FALSE;

		for (INT16 check_idx = 0; check_idx != parse_data->num_node_ptrs; check_idx++) {
			if (parse_data->node_info_array[check_idx].node_info->remote_addr.addr_u32 == ipv4.addr_u32) {
				if (parse_data->node_info_array[check_idx].node_info->remote_addr.port_u16 == ipv4.port_u16) {
					if(parse_data->node_info_array[check_idx].key_set) {
						DEBUG_ERROR("The descriptor response from the server is malicious - 'Duplicate data'");
						return FALSE;
					}
					parse_data->current_node_idx = check_idx;
					return TRUE;
				}
			}
		}

		DEBUG_ERROR("The descriptor response from the server is malicious - 'No node with provided IP'");
		return FALSE;
	}
	
	if (parse_data->current_node_idx == -1)
		return TRUE;
	
	if (parse_data->flag & TOR_NODE_INFO_DOWNLOAD_DATA_NTOR) {
		if (nt_strnicmp(current_line, "ntor-onion-key ", 15) == 0) {
			CHAR encoded_ntor_onion_key[45];
			if (nt_sscanf_s(current_line, "%*32s %44s", encoded_ntor_onion_key, 45) != 1)
				return FALSE;
			encoded_ntor_onion_key[43] = '=';
			if (base64_decode(encoded_ntor_onion_key, 44, parse_data->node_info_array[parse_data->current_node_idx].key_data, 32) != 32) 
				return FALSE;
			parse_data->node_info_array[parse_data->current_node_idx].key_set = TRUE;
		}
	}
	else if (parse_data->flag & TOR_NODE_INFO_DOWNLOAD_DATA_ED25519_IDENT) {
		if (nt_strnicmp(current_line, "identity-ed25519", 16) == 0) {
			BYTE raw_cert_data[256];
			INT32 decoded_cert_sz = (base64_decode_armored(line_context, "-----BEGIN ED25519 CERT-----", 28, "-----END ED25519 CERT-----", 26, raw_cert_data, sizeof(raw_cert_data)));
			if (!tor_cert_extract(raw_cert_data, decoded_cert_sz, parse_data->node_info_array[parse_data->current_node_idx].key_data, TOR_CERT_SIGNING_KEY_SIGNED_WITH_IDENTITY)) {
				DEBUG_ERROR("The descriptor response from the server is malicious - 'Parse failure.'");
				return FALSE;
			}
			parse_data->node_info_array[parse_data->current_node_idx].key_set = TRUE;
		}
	}
	
	return TRUE;
}

BOOL tor_node_info_download_data(BYTE flag, TOR_NODE_INFO_KEY_GENERIC* ptr_array, UINT32 num_node_ptrs, MODULE_TORCONN_HEADER* module_header) {
	CONST CHAR server_desc_prefix[14] = "/tor/server/d/";
	NET_HTTP_GET_REQUEST get_request;

	CONST SIZE_T req_sz = sizeof(server_desc_prefix) + (2ULL * (num_node_ptrs - 1)) + (40ULL * num_node_ptrs) + 3ULL;
	get_request.resource_path = memory_alloc(req_sz);
	if (get_request.resource_path == NULL)
		return FALSE;
	
	memory_copy(get_request.resource_path, server_desc_prefix, sizeof(server_desc_prefix));
	
	UINT32 ofs = sizeof(server_desc_prefix);
	for (UINT16 I = 0; I != num_node_ptrs; I++) {
		ptr_array[I].key_set = FALSE;
		//else DEBUG_VERBOSE("'%s' - '%s'", ptr_array[I].node_info->name, ptr_array[I].node_info->server_desc_digest);
		if (ofs != sizeof(server_desc_prefix)) {
			memory_copy(get_request.resource_path + ofs, "++", 2);
			ofs += 2;
		}
		memory_copy(get_request.resource_path + ofs, ptr_array[I].node_info->server_desc_digest, sizeof(ptr_array[I].node_info->server_desc_digest) - 1);
		ofs += 40;
	}
	memory_copy(get_request.resource_path + ofs, ".z", 2);

	BOOL sr_flag = FALSE;

	BOOL parse_ok = FALSE;
	for (UINT8 curr_da_idx = 0; curr_da_idx != HDR_TORCONN_NUM_STORED_DIR_ADDRS; curr_da_idx++) {
		get_request.tcp_socket = net_tcp_connect(&module_header->dir_addrs[curr_da_idx]);
		if (get_request.tcp_socket == INVALID_SOCKET)
			continue;

		TOR_NODEINFO_PARSE_DATA parse_data;
		parse_data.node_info_array = ptr_array;
		parse_data.num_node_ptrs = num_node_ptrs;
		parse_data.flag = flag;
		parse_data.current_node_idx = -1;

		parse_ok = net_http_get(0, &get_request, tor_node_info_serverdesc_parse_ntor, &parse_data, TOR_HS3_DESCRIPTOR_MAX_HTTP_DL_SIZE);
		closesocket(get_request.tcp_socket);

		if (parse_ok) {
			for (INT16 check_idx = 0; check_idx != parse_data.num_node_ptrs; check_idx++) {
				if (!parse_data.node_info_array[check_idx].key_set) {
					parse_ok = FALSE;
					DEBUG_ERROR("The descriptor response from the server is malicious - 'Incomplete data'");
					break;
				}
			}
		}
		if (!parse_ok) {
			sr_flag = TRUE;
			for (UINT16 I = 0; I != num_node_ptrs; I++)
				ptr_array[I].key_set = FALSE;
		}
		else {
			break;
		}
	}

	memory_free(get_request.resource_path);

	if (sr_flag) {
		if (!module_header_randomize_das(module_header))
			return FALSE;
	}

	return parse_ok;
}
