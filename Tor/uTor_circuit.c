//Any functions that listed here that are not in circuit.h are internal, the circuit must be destroyed on failure!!
#include "uTor_circuit.h"
#include "uTor_consensus.h"
#include "../Platform/uTor_memory.h"

TOR_CIRCUIT* tor_circuit_define(CONST BYTE requested_size, CONST BYTE required_node_flags, CONST TOR_CONSENSUS* consensus, TOR_NODE_INFO* circuit_target) {
	__analysis_assume(requested_size > 0);

	TOR_CIRCUIT* new_circuit = memory_alloc(sizeof(TOR_CIRCUIT));
	if (new_circuit == NULL)
		return NULL;

	static UINT32 new_circ_id = 0;
	new_circuit->circuit_id = (++new_circ_id) | 0x80000000;
	new_circuit->finished_circ_sz = requested_size;

	INT32 attempts = 0;
	CONST INT16 num_rand_nodes = (new_circuit->finished_circ_sz - ((circuit_target == NULL) ? 0 : 1));

	for (INT8 idx = 0; idx != num_rand_nodes; idx++) {
		if (attempts == 7)
			goto FAILURE;

		TOR_NODE_INFO* selected_node = tor_consensus_get_random_node(consensus, required_node_flags);
		if (selected_node == NULL)
			goto FAILURE;

		BOOL match = FALSE;
		for (BYTE C = 0; C != new_circuit->finished_circ_sz; C++) {
			if (selected_node == new_circuit->node_list[C].node_info) {
				match = TRUE;
			}
		}

		if (!match)
			new_circuit->node_list[idx].node_info = selected_node;
		else {
			idx--;
			attempts++;
			continue;
		}
	}

	if (circuit_target != NULL)
		new_circuit->node_list[requested_size - 1].node_info = circuit_target;

	if (!net_ssl_create_stream(&new_circuit->cell_io_context.ssl_stream))
		goto FAILURE;
	if (!tor_guard_node_connect(&new_circuit->cell_io_context, new_circuit->node_list[0].node_info))
		goto FAILURE;

	new_circuit->flowcontrol_data.deliver_window_curr = consensus->circwindow_default;
	new_circuit->flowcontrol_data.package_window_curr = consensus->circwindow_default;

	DEBUG_SUCCESS("A circuit (id: '%u' | sz: '%hhu') has been successfully defined, dw: '%i' pw:'%i'", new_circ_id, new_circuit->finished_circ_sz, consensus->circwindow_default, consensus->circwindow_default);
	return new_circuit;
FAILURE:
	DEBUG_ERROR("Failed when defining a circuit (id: '%hhu').", requested_size);
	if (new_circuit != NULL) {
		net_ssl_destroy_stream(&new_circuit->cell_io_context.ssl_stream);
		memory_free(new_circuit);
	}
	return NULL;
}

BOOL tor_circuit_destroy(TOR_CIRCUIT* active_circuit) {
	if (active_circuit == NULL)
		return TRUE;

	BOOL something_failed = FALSE;
	for (INT8 I = 0; I != active_circuit->current_circ_sz; I++) {
		if (active_circuit->node_crypto_state[I].crypto_state_f.h_key != 0)
			something_failed |= (!crypto_aes_destroy_state(&active_circuit->node_crypto_state[I].crypto_state_f));
		if (active_circuit->node_crypto_state[I].crypto_state_b.h_key != 0)
			something_failed |= (!crypto_aes_destroy_state(&active_circuit->node_crypto_state[I].crypto_state_b));

		if (active_circuit->node_crypto_state[I].running_hash_f != 0) {
			something_failed |= (!BCRYPT_SUCCESS(BCryptDestroyHash(active_circuit->node_crypto_state[I].running_hash_f)));
			active_circuit->node_crypto_state[I].running_hash_f = 0;
		}
		if (active_circuit->node_crypto_state[I].running_hash_b != 0) {
			something_failed |= (!BCRYPT_SUCCESS(BCryptDestroyHash(active_circuit->node_crypto_state[I].running_hash_b)));
			active_circuit->node_crypto_state[I].running_hash_b = 0;
		}
		DEBUG_VERBOSE("Destroyed the cryptographic state of node: %hhu", I + 1);
	}

	//something_failed |= (!tor_guard_node_disconnect(&active_circuit->cell_io_context)); //We don't do this because SSL disconnect gets called in net_ssl_destroy_stream, and this gets freed below.
	something_failed |= (!net_ssl_destroy_stream(&active_circuit->cell_io_context.ssl_stream));

	if (!something_failed)
		DEBUG_WARNING("A circuit (id: '%u') has been destroyed.", (active_circuit->circuit_id ^ 0x80000000));
	something_failed |= (!memory_free(active_circuit));
	return (!something_failed);
}

//TODO: Who frees the hs circuit data on failure?