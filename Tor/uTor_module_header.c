#include "uTor_module_header.h"
#include "memory.h"

BOOL module_header_is_blinded_key_available(MODULE_TORCONN_HEADER* module_header, const UINT16 for_time_period_num) {
	CONST INT32 diff = (INT32)for_time_period_num - (INT32)(module_header->start_tp);
	CONST INT32 num_available_keys = HDR_TORCONN_NUM_KEYBLINDS;
	DEBUG_VERBOSE("start_tp: '%zu', num_available_keys: '%i' - diff: '%i'", module_header->start_tp, num_available_keys, diff);
	return !((diff < 0) || (diff >= num_available_keys));
}

CONST CRYPTO_ECC25519_KEY* module_header_get_blinded_hs3_pubkey(MODULE_TORCONN_HEADER* module_header, const UINT16 for_time_period_num) {
	CONST INT32 diff = (INT32)for_time_period_num - (INT32)(module_header->start_tp);
	DEBUG_INFO("Using pregenerated key '%i' out of '%i' available.", diff, HDR_TORCONN_NUM_KEYBLINDS);
	return module_header->blinded_keys[diff];
}

BOOL module_header_randomize_das(MODULE_TORCONN_HEADER* module_header) {
	for (DWORD da_index = 0; da_index != HDR_TORCONN_NUM_STORED_DIR_ADDRS; da_index++) {
		BYTE rand_val = 0;
		if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, &rand_val, 1, 0)))
			return FALSE;
		rand_val %= HDR_TORCONN_NUM_STORED_DIR_ADDRS;

		NETADDR_IPV4 tmp = module_header->dir_addrs[rand_val];
		module_header->dir_addrs[rand_val] = module_header->dir_addrs[da_index];
		module_header->dir_addrs[da_index] = tmp;
	}
	DEBUG_VERBOSE("Randomized the directory authority list.");
	return TRUE;
}

//TODO: implement DA shuffling.

/*
typedef struct {
	NETADDR_IPV4 ipv4;
	INT16 ping;
} DA_PING_DATA;

BOOL module_header_sort_das_by_ping(MODULE_TORCONN_HEADER* module_header) {
	DA_PING_DATA* arr = memory_alloc(HDR_TORCONN_NUM_STORED_DIR_ADDRS * sizeof(DA_PING_DATA));
	if (arr == NULL)
		return FALSE;

	UINT16 available_dirs = 0;
	for (UINT32 I = 0; I != HDR_TORCONN_NUM_STORED_DIR_ADDRS; I++) {
		INT32 res = net_tcp_ping(&module_header->dir_addrs[I]);
		if (res != -1) {
			arr[available_dirs].ipv4 = module_header->dir_addrs[I];
			arr[available_dirs++].ping = res;
			DEBUG_INFO("Ping response(%u/%i): '%i'", I + 1, HDR_TORCONN_NUM_STORED_DIR_ADDRS, res);
		}
	}

	if (available_dirs == 0) {
		DEBUG_ERROR("We do not seem to have an internet connection at the moment.");
		memory_free(arr);
		return FALSE;
	}

	DEBUG_INFO("Ping tests done, directories sorted, blocked connections removed.");
	DEBUG_INFO("Directories available: '%i/%u'", available_dirs, HDR_TORCONN_NUM_STORED_DIR_ADDRS);

	for (INT32 first_idx = available_dirs - 1; first_idx != 0; first_idx--) {
		for (INT32 second_idx = 0; second_idx != first_idx; second_idx++) {
			if (arr[second_idx].ping > arr[first_idx].ping) {
				DA_PING_DATA tmp;
				memory_copy((BYTE*)&tmp, (const BYTE*)&arr[second_idx], sizeof(DA_PING_DATA));
				memory_copy((BYTE*)&arr[second_idx], (const BYTE*)&arr[first_idx], sizeof(DA_PING_DATA));
				memory_copy((BYTE*)&arr[first_idx], (const BYTE*)&tmp, sizeof(DA_PING_DATA));
			}
		}
	}

	for (INT32 a_dir_idx = 0; a_dir_idx != available_dirs; a_dir_idx++) {
		DEBUG_VERBOSE("%hhu.%hhu.%hhu.%hhu - %hu ms", arr[a_dir_idx].ipv4.addr_octet[0], arr[a_dir_idx].ipv4.addr_octet[1], arr[a_dir_idx].ipv4.addr_octet[2], arr[a_dir_idx].ipv4.addr_octet[3], arr[a_dir_idx].ping);
		module_header->dir_addrs[a_dir_idx] = arr[a_dir_idx].ipv4;
	}

	if (!memory_free(arr))
		return FALSE;
	return TRUE;
}*/