#pragma once
#include "uTor_consensus.h"
#include "uTor_node_info.h"

typedef struct {
    UINT32 num_hsdirs;
    TOR_HS3_NODE_INFO_HSDIR sorted_list[TOR_CONSENSUS_MAX_NODELIST_SZ];
} TOR_HS3_DIRLIST;

//(NOTE: Due to squid proxy url limitations at most 96 fingerprints can be retrieved in a single request.)
#define TOR_HS3_DIRLIST_MAX_PER_DL_BATCH 80 //Defines the maximum amount of descriptors that are downloaded per http get request in 'tor_hs3_dirlist_download()'
#define TOR_HS3_DIRLIST_MAX_HTTP_DL_SIZE (32 * 1024 * 1024) //32 - The maximum download size of the hs3 directory list.

BOOL tor_hs3_dirlist_download(TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hs3_dirlist, CONST MODULE_TORCONN_HEADER* module_header);
BOOL tor_hs3_dirlist_get_responsible_dirs(TOR_HS3_DIRLIST* hs3_dirlist, TOR_CONSENSUS* consensus, BYTE* blinded_hsvc_pubkey, UINT32(*responsible_dirs)[TOR_HSDIR_SPREAD_FETCH_MAX], UINT64 replica_num);