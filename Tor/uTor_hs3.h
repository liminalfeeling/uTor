#pragma once
#define TOR_HS3_RENDEVOUZ_COOKIE_LEN 20
#include "uTor_hs3_ntor_handshake.h"
#include "uTor_circuit.h"
#include "../Platform/uTor_time.h"

typedef struct {
	TOR_CIRCUIT* rend_circuit;
	TOR_HS3_NTOR_CRYPTO_STATE tor_hs3_crypto_state;
} TOR_HS3_CIRCUIT;

#define TOR_HS3_DIRLIST_MAX_HTTP_DL_SIZE (32 * 1024 * 1024) //32 - The maximum download size of the hs3 directory list.
#define TOR_HS3_DESCRIPTOR_MAX_HTTP_DL_SIZE (512 * 1024) //512kb
#define TOR_HS3_MAX_CONN_ATTEMPTS 3 //Defines the maximum amount of attempts to build a circuit in the various sTor_hs3 functions.
#define TOR_HS3_DESC_FETCH_CIRC_SZ 3 //Defines the size of a desc fetch circ
#define TOR_HS3_REND_CIRC_SZ 3 //Defines the size of a rendevouz circ
#define TOR_HS3_INTRO_CIRC_SZ 3 //Defines the size of a introduce circ
#define TOR_HS3_MAX_NUM_INTRO_POINTS 3 //Defines the maximum amount of introduction points that can be grabbed from a directory

//* Connects to the hidden service using the data from the "MODULE_TORCONN_HEADER"
//* Expects a downloaded hs3 directory list & a downloaded consensus.
BOOL tor_hs3_connect(TOR_HS3_CIRCUIT* circuit_out, TOR_CONSENSUS* consensus, TOR_HS3_DIRLIST* hs3_dirlist, MODULE_TORCONN_HEADER* module_header);
