#pragma once
#include "uTor_consensus.h"
#include "uTor_guard_node.h"
#include "uTor_ntor_handshake.h"
#include "uTor_hs3_ntor_handshake.h"

#define TOR_CIRCUIT_FLAG_HS3_SVC 1 << 0
#define TOR_CIRCUIT_IS_HS3_SVC(X) (X->flags & TOR_CIRCUIT_FLAG_HS3_SVC)

#define TOR_CIRCUIT_MAX_NUM_NODES 3 //Defines the maximum size of any circuit (num nodes in circ)

typedef struct {
	INT32 package_window_curr; //Used when packaging the cell for sending to any stream.
	INT32 deliver_window_curr;
} TOR_FLOWCTL_DATA;

//REFACTOR, who manages flow control, this or the circuit_stream? also.. does the circuit_stream design even make sense?
typedef struct {
	TOR_CELL_IO_CONTEXT cell_io_context;
	TOR_NODE_INFO_NTOR node_list[TOR_CIRCUIT_MAX_NUM_NODES];
	TOR_NTOR_CRYPTO_STATE node_crypto_state[TOR_CIRCUIT_MAX_NUM_NODES]; //key for each node.
	TOR_FLOWCTL_DATA flowcontrol_data;
	TOR_HS3_NTOR_CRYPTO_STATE* hs3_crypto_state;
	UINT32 circuit_id;
	BYTE finished_circ_sz; //requested size of the circuit
	BYTE current_circ_sz; //the current size of the circuit
} TOR_CIRCUIT;

TOR_CIRCUIT* tor_circuit_define(CONST BYTE requested_size, CONST BYTE required_node_flags, CONST TOR_CONSENSUS* consensus, TOR_NODE_INFO* target);
BOOL tor_circuit_destroy(TOR_CIRCUIT* active_circuit);