#pragma once
#include "uTor_cell_io.h"
#include "uTor_consensus.h"
#include "uTor_hs3_dirlist.h"
#include "uTor_node_info.h"

#define TOR_HS3_DIRLIST_MAX_HTTP_DL_SIZE (32 * 1024 * 1024) //32 - The maximum download size of the hs3 directory list.
#define TOR_HS3_DESCRIPTOR_MAX_HTTP_DL_SIZE (512 * 1024) //512kb
#define TOR_HS3_MAX_CONN_ATTEMPTS 3 //Defines the maximum amount of attempts to build a circuit in the various sTor_hs3 functions.
#define TOR_HS3_DESC_FETCH_CIRC_SZ 3 //Defines the size of a desc fetch circ
#define TOR_HS3_REND_CIRC_SZ 3 //Defines the size of a rendevouz circ
#define TOR_HS3_INTRO_CIRC_SZ 3 //Defines the size of a introduce circ
#define TOR_HS3_MAX_NUM_INTRO_POINTS 3 //Defines the maximum amount of introduction points that can be grabbed from a directory

typedef struct {
	TOR_NODE_INFO node_info;
	BYTE ntor_key[32]; //TODO: Switch all of these out to their respective structs.
	//BYTE ed25519_node_identity[CRYPTO_ECC25519_KEY_LEN]; //ED25519
	BYTE auth_key[CRYPTO_ECC25519_KEY_LEN]; //ED25519
	BYTE enc_key_ntor[CRYPTO_ECC25519_KEY_LEN]; //ED25519
	BYTE parse_flag; //TODO: get rid of this parse flag if possible, maybe memory_zero could be useful.
} TOR_HS3_INTRO_POINT;

BOOL tor_hs3_descriptor_download(CRYPTO_ECC25519_KEY* blinded_hsvc_pubkey, TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hsdir_list, TOR_HS3_INTRO_POINT* intro_points_out, BYTE* num_intro_points_out, MODULE_TORCONN_HEADER* module_header);