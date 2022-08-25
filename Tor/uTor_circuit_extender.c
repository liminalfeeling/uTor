#include "uTor_circuit_extender.h"
#include "uTor_linkspec.h"
#include "../Platform/uTor_memory.h"

#pragma pack(push)
#pragma pack(1)
typedef struct {
	UINT16 h_len;
	BYTE server_pubkey[32];
	BYTE server_auth[32];
} TOR_CELL_CREATED2_DATA, TOR_CELL_EXTENDED2_DATA;
#pragma pack(pop)

BOOL tor_circuit_extend(BCRYPT_KEY_HANDLE client_public_key, TOR_CIRCUIT* active_circuit, const UINT8 node_n) { //internal use only.
	TOR_NODE_INFO_NTOR* extend_node = &active_circuit->node_list[node_n];
	struct sTor_extend2_header {
		BYTE num_lspec;
		TOR_LINKSPEC_HEADER ipv4_hdr;
		NETADDR_IPV4 ipv4_data;
		TOR_LINKSPEC_HEADER lgcidt_hdr;
		BYTE lgcidt_data[CRYPTO_SHA1_HASH_LEN];
	};

	BYTE extend2_data[sizeof(struct sTor_extend2_header) + sizeof(TOR_NTOR_HANDSHAKE_DATA)] = { 0 };
	struct sTor_extend2_header* extend2 = extend2_data;

	extend2->num_lspec = 2;
	extend2->ipv4_hdr.ls_type = TOR_EXT2_LINKSPEC_TLS_OVER_IPV4;
	extend2->ipv4_hdr.ls_len = sizeof(extend2->ipv4_data);
	extend2->ipv4_data = extend_node->node_info->remote_addr;
	extend2->ipv4_data.port_u16 = htons(extend2->ipv4_data.port_u16);

	extend2->lgcidt_hdr.ls_type = TOR_EXT2_LINKSPEC_SHA1_IDENTITY;
	extend2->lgcidt_hdr.ls_len = sizeof(extend2->lgcidt_data);
	memory_copy(extend2->lgcidt_data, extend_node->node_info->identity_fingerprint, CRYPTO_SHA1_HASH_LEN);

	TOR_NTOR_HANDSHAKE_DATA new_handshake;
	if (!tor_ntor_gen_handshake_data(&new_handshake, extend_node, client_public_key))
		return FALSE;

	memory_copy(extend2_data + sizeof(struct sTor_extend2_header), (const BYTE*)&new_handshake, sizeof(TOR_NTOR_HANDSHAKE_DATA));

	DEBUG_INFO("Attempting to extend to node %hhu ('%s')", node_n + 1, extend_node->node_info->name);
	if (!tor_relay_send(active_circuit, 0, TOR_RELAYCMD_EXTEND2, extend2_data, sizeof(extend2_data)))
		return FALSE;

	TOR_RELAY_DATA relay_data;
	if (!tor_relay_recv(active_circuit, &relay_data))
		return FALSE;
	if (relay_data.relay_cmd != TOR_RELAYCMD_EXTENDED2)
		return FALSE;

	TOR_CELL_EXTENDED2_DATA* cell_extended2 = relay_data.data;
	if ((cell_extended2->h_len != htons(64)))
		return FALSE;
	if (!tor_ntor_init_crypto_state(&new_handshake, &active_circuit->node_crypto_state[node_n], cell_extended2->server_pubkey, cell_extended2->server_auth, client_public_key))
		return FALSE;

	active_circuit->current_circ_sz++;
	DEBUG_INFO("Extension performed, current_circ_sz: %hhu", active_circuit->current_circ_sz);
	return TRUE;
}

BOOL tor_circuit_fully_extend(TOR_CIRCUIT* active_circuit, MODULE_TORCONN_HEADER* module_header) {
	if (!tor_node_info_download_data(TOR_NODE_INFO_DOWNLOAD_DATA_NTOR, active_circuit->node_list, (active_circuit->node_list[active_circuit->finished_circ_sz - 1].key_set ? (active_circuit->finished_circ_sz - 1) : active_circuit->finished_circ_sz), module_header))
		return FALSE;

	static UINT32 new_circ_id = 0;
	active_circuit->current_circ_sz = 1;
	
	BCRYPT_KEY_HANDLE client_keypair = crypto_ecc25519_gen_keypair();
	if (client_keypair == NULL)
		return FALSE;

	TOR_NTOR_HANDSHAKE_DATA handshake_data;
	if (!tor_ntor_gen_handshake_data(&handshake_data, &active_circuit->node_list[0], client_keypair))
		return FALSE;

	if (!TOR_CELL_IO_SEND(&active_circuit->cell_io_context, active_circuit->circuit_id, TOR_CELL_CMD_CREATE2, (BYTE*)&handshake_data))
		return FALSE;

	TOR_CELL_HEADER header;
	BYTE created2_data[509];

	if (!TOR_CELL_IO_RECV(&active_circuit->cell_io_context, &header, &created2_data, sizeof(created2_data)))
		return FALSE;
	if (header.cmd != TOR_CELL_CMD_CREATED2)
		return FALSE;

	TOR_CELL_CREATED2_DATA* created2_cell = created2_data;
	if (created2_cell->h_len != htons(64))
		return FALSE;

	DEBUG_VERBOSE("Server has responded with a valid create2 cell.");
	if (!tor_ntor_init_crypto_state(&handshake_data, &active_circuit->node_crypto_state[0], created2_cell->server_pubkey, created2_cell->server_auth, client_keypair))
		return FALSE;

	for (BYTE I = active_circuit->current_circ_sz; I != active_circuit->finished_circ_sz; I++) {
		if (!tor_circuit_extend(client_keypair, active_circuit, I))
			return FALSE;
	}

	DEBUG_SUCCESS("A circuit (id: '%u') has been fully extended.", (active_circuit->circuit_id ^ 0x80000000));
	return TRUE;
}
