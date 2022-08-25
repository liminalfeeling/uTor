#pragma once
//TODO: Remove the need for this, split it into 2 for Tor and Tor hsvc.
#pragma once
#include "../Networking/uTor_net_tcp.h"
#include "../Cryptography/uTor_crypto_pk.h"
#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Platform/uTor_debug.h"

#define HDR_TORCONN_NUM_STORED_DIR_ADDRS 12
#define HDR_TORCONN_NUM_KEYBLINDS 14 //2 weeks.

#pragma pack(push)
#pragma pack(1)

typedef struct {
	UINT16 start_tp;
	BYTE hsvc_credential[32];
	BYTE blinded_keys[HDR_TORCONN_NUM_KEYBLINDS][32];
	NETADDR_IPV4 dir_addrs[HDR_TORCONN_NUM_STORED_DIR_ADDRS];
} MODULE_TORCONN_HEADER;
#pragma pack(pop)

//* Checks if there even is a blinded key available for a connection attempt to occur.
//* We call this as soon as the consensus is downloaded, if a key doesn't exist we abort the connection.
BOOL module_header_is_blinded_key_available(MODULE_TORCONN_HEADER* module_header, const UINT16 for_time_period_num);

//* Retreives a blinded public key from the "MODULE_TORCONN_HEADER" for the time period specified.
//* DOES NOT HAVE SAFETY CHECKS, PERFORM 'module_header_is_blinded_key_available(...)' BEFORE USE.
CONST CRYPTO_ECC25519_KEY* module_header_get_blinded_hs3_pubkey(MODULE_TORCONN_HEADER* module_header, const UINT16 for_time_period_num);

//* Sends a ping packet to all dir auths in the module header and sorts them from lowest to highest ping.
//* Returns false if all directory authorities are down or a memory error occured.
//BOOL module_header_sort_das_by_ping(MODULE_TORCONN_HEADER* module_header);

//* Randomizes the DA list in the MODULE_TORCONN_HEADER
BOOL module_header_randomize_das(MODULE_TORCONN_HEADER* module_header);