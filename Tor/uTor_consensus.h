#pragma once
#include "uTor_node_info.h"
#include "uTor_module_header.h"

//Taken from the tor source code.
#define TOR_HSDIR_DEFAULT_HSDIR_SPREAD_FETCH 3
#define TOR_HSDIR_SPREAD_FETCH_MAX 128
#define TOR_HSDIR_SPREAD_FETCH_MIN 1

#define TOR_HSDIR_DEFAULT_N_REPLICAS 2
#define TOR_HSDIR_N_REPLICAS_MAX 16
#define TOR_HSDIR_N_REPLICAS_MIN 1

#define TOR_CONSENSUS_CIRCWINDOW_DEFAULT 1000 //why is this in consensus?
#define TOR_CONSENSUS_SRV_DISASTER_PREFIX  "shared-random-disaster"
#define TOR_CONSENSUS_SRV_DISASTER_PREFIX_SZ (sizeof(TOR_CONSENSUS_SRV_DISASTER_PREFIX) - 1)

#define TOR_CONSENSUS_MAX_HTTP_DL_SIZE (8 * 1024 * 1024) //8mb - The maximum download size of the consensus.
#define TOR_CONSENSUS_MAX_NODELIST_SZ 8192 //Defines the maximum amount of nodes that can be stored by the consensus.

typedef struct {
	INT32 valid_after_posix;
	INT32 fresh_until_posix;
	BYTE current_srv[32];
	BYTE prev_srv[32];
	UINT16 hsdir_spread_fetch;
	UINT16 hsdir_n_replicas;
	UINT16 circwindow_default;
	UINT16 time_period_len;
	UINT32 num_nodes;
	TOR_NODE_INFO node_list[TOR_CONSENSUS_MAX_NODELIST_SZ];
} TOR_CONSENSUS;

BOOL tor_consensus_download(TOR_CONSENSUS* consensus, MODULE_TORCONN_HEADER* pg_header);
CONST TOR_NODE_INFO* tor_consensus_get_random_node(CONST TOR_CONSENSUS* consensus, CONST BYTE required_flags);