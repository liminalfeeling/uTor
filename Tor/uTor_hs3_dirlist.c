#include "uTor_hs3_dirlist.h"
#include "uTor_hs3_calc.h"
#include "../Platform/uTor_time.h"
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/uTor_base64.h"
#include "uTor_cert.h"
#include "uTor_http.h"

typedef struct {
	TOR_CONSENSUS* consensus;
	TOR_HS3_DIRLIST* hsdir_list;
	TOR_NODE_INFO* latest_node;
	BOOL parsed_cert;
} TOR_HS3_DIRLIST_PARSE_DATA;

VOID tor_hs3_dirlist_sort(TOR_HS3_DIRLIST* hs3_dirlist) {
	for (INT32 first_idx = hs3_dirlist->num_hsdirs - 1; first_idx != 0; first_idx--) {
		for (INT32 second_idx = 0; second_idx != first_idx; second_idx++) {
			INT32 cmp_result = nt_memcmp(hs3_dirlist->sorted_list[second_idx].key_data, hs3_dirlist->sorted_list[first_idx].key_data, sizeof(hs3_dirlist->sorted_list[first_idx].key_data));
			if (cmp_result == 0)
				continue;
			if (cmp_result > 0) {
				TOR_HS3_NODE_INFO_HSDIR hsdir_info;
				memory_copy((BYTE*)&hsdir_info, (const BYTE*)&hs3_dirlist->sorted_list[second_idx], sizeof(TOR_HS3_NODE_INFO_HSDIR));
				memory_copy((BYTE*)&hs3_dirlist->sorted_list[second_idx], (const BYTE*)&hs3_dirlist->sorted_list[first_idx], sizeof(TOR_HS3_NODE_INFO_HSDIR));
				memory_copy((BYTE*)&hs3_dirlist->sorted_list[first_idx], (const BYTE*)&hsdir_info, sizeof(TOR_HS3_NODE_INFO_HSDIR));
			}
		}
	}
}

//TODO: add caching, that would be really cool... imagine having an encrypted cached file, and working with diffs like the real tor does :))
BOOL tor_hs3_dirlist_download(TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hs3_dirlist, CONST MODULE_TORCONN_HEADER* module_header) {
	UINT32 dirs_remaining = 0;
	for (SIZE_T node_idx = 0; node_idx != consensus->num_nodes; node_idx++) {
		if (consensus->node_list[node_idx].flags & TOR_NODE_INFO_FLAG_HSDIR_V2) {
			hs3_dirlist->sorted_list[dirs_remaining++].node_info = &consensus->node_list[node_idx];
		}
	}

	CONST BYTE* curr_shared_rand_val = (tor_hs3_calc_is_period_between_tp_and_srv(consensus) ? consensus->current_srv : consensus->prev_srv);
	CONST UINT64 curr_time_period = tor_time_calculate_period(consensus->valid_after_posix, consensus->time_period_len);
	CONST UINT32 dirs_at_start = dirs_remaining;

	DEBUG_INFO("There are allegedly '%u' hidden service directories active..", dirs_at_start);

	while (dirs_remaining > 0) {
		UINT32 num_in_batch = dirs_remaining;

		if (num_in_batch > TOR_HS3_DIRLIST_MAX_PER_DL_BATCH)
			num_in_batch = TOR_HS3_DIRLIST_MAX_PER_DL_BATCH;

		for (INT I = 0; I != num_in_batch; I++)
			hs3_dirlist->sorted_list[(dirs_at_start - dirs_remaining) + I].key_set = FALSE;

		if (!tor_node_info_download_data(TOR_NODE_INFO_DOWNLOAD_DATA_ED25519_IDENT, &hs3_dirlist->sorted_list[(dirs_at_start - dirs_remaining)], num_in_batch, module_header)) {
			DEBUG_ERROR("There was an error when downloading the data.");
			return FALSE;
		}

		DEBUG_INFO("Calculated data for batch '%u/%u'.", dirs_at_start - dirs_remaining, dirs_at_start);

		for (INT I = 0; I != num_in_batch; I++) {
			TOR_HS3_NODE_INFO_HSDIR* new_hsdir_info = &hs3_dirlist->sorted_list[hs3_dirlist->num_hsdirs++];
			tor_hs3_calc_directory_index(consensus->time_period_len, curr_time_period, curr_shared_rand_val, hs3_dirlist->sorted_list[(dirs_at_start - dirs_remaining) + I].key_data, new_hsdir_info->key_data);
		}
		dirs_remaining -= num_in_batch;
	}

	tor_hs3_dirlist_sort(hs3_dirlist);
	DEBUG_SUCCESS("Successfully downloaded and sorted the hs3 directory list.");

	return TRUE;
}

//NOTE: IN THE CALC_COMPARISON_INDEX replica_num goes from 1 and upwards NOT 0, but we PASS the replica_num argument from 0-..., SEE THE TOR REND V3 SPEC.
BOOL tor_hs3_dirlist_get_responsible_dirs(TOR_HS3_DIRLIST* hs3_dirlist, TOR_CONSENSUS* consensus, BYTE* blinded_hsvc_pubkey, UINT32 (*responsible_dirs)[TOR_HSDIR_SPREAD_FETCH_MAX], UINT64 replica_num) {
	DEBUG_INFO("Attempting to fetch responsible descriptors.");
	if ((consensus->hsdir_spread_fetch < 1) || (consensus->hsdir_n_replicas < 1))
		return FALSE;

	BYTE hs3_comparison_index[32];
	tor_hs3_calc_comparison_index(consensus->time_period_len, tor_time_calculate_period(consensus->valid_after_posix, consensus->time_period_len), replica_num + 1ULL, blinded_hsvc_pubkey, hs3_comparison_index);

	UINT32 found_index = 0;
	while (found_index != hs3_dirlist->num_hsdirs) {
		if (nt_memcmp(hs3_dirlist->sorted_list[found_index].key_data, hs3_comparison_index, sizeof(hs3_comparison_index)) > 0)
			break;
		found_index++;
	}

	UINT32 selected_index = 0;
	for (UINT32 ofs = 0, I = 0; I != consensus->hsdir_spread_fetch; I++) {
		rs_label:
		selected_index = (found_index + ofs) % hs3_dirlist->num_hsdirs;

		//We skip over nodes that have already been selected in previous lists.
		for (DWORD I = 0; I != replica_num; I++) {
			for (DWORD X = 0; X != TOR_HSDIR_SPREAD_FETCH_MAX; X++) {
				if (selected_index == responsible_dirs[I][X]) {
					found_index = (found_index + 1) % hs3_dirlist->num_hsdirs;
					goto rs_label;
				}
			}
		}
		responsible_dirs[replica_num][I] = selected_index;
		ofs++;
	}

	//randomize the list.
	for (INT16 I = 0; I != consensus->hsdir_spread_fetch; I++) {
		BYTE rnd_val = 0;
		if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, &rnd_val, sizeof(BYTE), 0)))
			return FALSE;
		rnd_val = rnd_val % consensus->hsdir_spread_fetch;
		UINT32 tmp = responsible_dirs[replica_num][rnd_val];
		responsible_dirs[replica_num][rnd_val] = responsible_dirs[replica_num][I];
		responsible_dirs[replica_num][I] = tmp;
	}

	DEBUG_INFO("Generated '%hu' num descriptors for replica '%zu'.", consensus->hsdir_spread_fetch, replica_num);
#ifdef _DEBUG
	for (INT16 I = 0; I != consensus->hsdir_spread_fetch; I++) {
		INT32 node_idx = responsible_dirs[replica_num][I];
		TOR_HS3_NODE_INFO_HSDIR* current_hsdir_info = &hs3_dirlist->sorted_list[node_idx];
		DEBUG_VERBOSE("Selected directory no. '%i' -> '%s'", I + 1, current_hsdir_info->node_info->name);
	}
#endif
	return TRUE;
}