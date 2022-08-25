#pragma once
#include "../Networking/uTor_net_tcp.h"
#include "../Cryptography/uTor_crypto_pk.h"
#include "../Platform/uTor_debug.h"
#include "uTor_module_header.h"

#define TOR_HS3_DESCRIPTOR_MAX_HTTP_DL_SIZE (512 * 1024) //512kb

enum tor_node_info_flag {
	TOR_NODE_INFO_FLAG_GUARD = 1 << 0,
	TOR_NODE_INFO_FLAG_FAST = 1 << 1,
	TOR_NODE_INFO_FLAG_EXIT = 1 << 2,
	TOR_NODE_INFO_FLAG_HSDIR_V2 = 1 << 3,
	TOR_NODE_INFO_FLAG_CHECKED = 1 << 4
};

enum TOR_NODE_INFO_DOWNLOAD_DATA_TYPE {
	TOR_NODE_INFO_DOWNLOAD_DATA_NTOR = 1 << 0,
	TOR_NODE_INFO_DOWNLOAD_DATA_ED25519_IDENT = 1 << 1
};

typedef struct {
#if (defined(_DEBUG) || defined(_RELEASE_TEST))
	BYTE name[32];
#endif
	NETADDR_IPV4 remote_addr;
	BYTE ed25519_identity[32]; //The new ed25519 identity
	BYTE server_desc_digest[41]; //The server descriptor digest.
	BYTE identity_fingerprint[20]; //The old identity fingerprint.
	BYTE flags; //one of the above tor_node_info_flags
} TOR_NODE_INFO;

typedef struct {
	TOR_NODE_INFO* node_info;
	BOOL key_set;
	BYTE key_data[32]; //the public key used for NTOR connections.
} TOR_NODE_INFO_KEY_GENERIC, TOR_NODE_INFO_NTOR, TOR_NODE_INFO_ED25519_IDENT, TOR_HS3_NODE_INFO_HSDIR;

BOOL tor_node_info_download_data(BYTE flag, TOR_NODE_INFO_KEY_GENERIC* ptr_array, UINT32 num_node_ptrs, MODULE_TORCONN_HEADER* module_header);