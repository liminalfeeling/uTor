#include "uTor_relay.h"
#include "uTor_hs3.h"
#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Cryptography/uTor_crypto.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/uTor_string.h"
#include "uTor_cell_io.h"

BOOL tor_relay_send(TOR_CIRCUIT* active_circuit, const UINT16 stream_id, const BYTE relay_cmd, const BYTE* relay_payload, const UINT16 relay_payload_sz) {
	TOR_RELAY_DATA relay_data;

	//1. Construct the payload (randomize is for padding)
	if (BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, relay_data.data, TOR_MAX_RELAY_PAYLOAD_LEN, 0) != 0)
		return FALSE;

	relay_data.relay_cmd = relay_cmd;
	relay_data.stream_id = htons(stream_id);
	relay_data.data_sz = htons(relay_payload_sz);
	RtlSecureZeroMemory(relay_data.running_digest, 4);
	relay_data.quickhash_check = 0;

	if (relay_payload)
		memory_copy(relay_data.data, relay_payload, relay_payload_sz);

	BYTE digest_full[CRYPTO_SHA3_256_HASH_LEN];
	if (active_circuit->hs3_crypto_state == NULL) {
		//Calculate the digest and insert into relay payload.
		if (!BCRYPT_SUCCESS(BCryptHashData(active_circuit->node_crypto_state[active_circuit->current_circ_sz - 1].running_hash_f, (PUCHAR)&relay_data, sizeof(TOR_RELAY_DATA), 0)))
			return FALSE;
		if (!crypto_bcrypt_hash_copied_handle(active_circuit->node_crypto_state[active_circuit->current_circ_sz - 1].running_hash_f, NULL, 0, digest_full, CRYPTO_SHA1_HASH_LEN))
			return FALSE;
	}
	else {
		crypto_sha3_update(&active_circuit->hs3_crypto_state->running_hash_f, &relay_data, sizeof(TOR_RELAY_DATA));

		CRYPTO_SHA3_CTXT tmp_ctx = active_circuit->hs3_crypto_state->running_hash_f;
		crypto_sha3_final(digest_full, &tmp_ctx);
	}

	memory_copy(relay_data.running_digest, digest_full, sizeof(relay_data.running_digest));

	if (active_circuit->hs3_crypto_state != NULL) {
		if (!crypto_aes_crypt_message(&active_circuit->hs3_crypto_state->crypto_state_f, (BYTE*)&relay_data, sizeof(TOR_RELAY_DATA)))
			return FALSE;
	}

	for (BYTE X = 0; X != (active_circuit->current_circ_sz); X++) {
		if (!crypto_aes_crypt_message(&active_circuit->node_crypto_state[X].crypto_state_f, (BYTE*)&relay_data, sizeof(TOR_RELAY_DATA)))
			return FALSE;
	}

	return TOR_CELL_IO_SEND(&active_circuit->cell_io_context, active_circuit->circuit_id, (relay_cmd == TOR_RELAYCMD_EXTEND2) ? TOR_CELL_CMD_RELAY_EARLY : TOR_CELL_CMD_RELAY, &relay_data);
}

BOOL tor_relay_recv(TOR_CIRCUIT* active_circuit, TOR_RELAY_DATA* relay_data) {
	TOR_CELL_HEADER header;
	if (!TOR_CELL_IO_RECV(&active_circuit->cell_io_context, &header, relay_data, sizeof(TOR_RELAY_DATA)))
		return FALSE;

	if (!((header.cmd == TOR_CELL_CMD_RELAY) || (header.cmd == TOR_CELL_CMD_RELAY_EARLY))) //We expect a relay / relay early cell.
		return FALSE;

	BOOL decryption_successful = FALSE;
	for (BYTE I = 0; I != active_circuit->current_circ_sz; I++) {
		if (!crypto_aes_crypt_message(&active_circuit->node_crypto_state[I].crypto_state_b, (BYTE*)relay_data, sizeof(TOR_RELAY_DATA)))
			return FALSE;

		if ((relay_data->quickhash_check == 0)) { //RECOGNIZED optimization.. if 0 means that dec was probably successful, however we must confirm the data is as it should be with digest:
			BYTE hash_recvd[4];
			memory_copy(hash_recvd, (const BYTE*)relay_data->running_digest, 4); //copy the has to a tmp avlue
			memory_zero(relay_data->running_digest, 4);
			if (!crypto_bcrypt_hash_copied_handle(active_circuit->node_crypto_state[I].running_hash_b, relay_data, sizeof(TOR_RELAY_DATA), active_circuit->node_crypto_state[I].last_running_hash_b, CRYPTO_SHA1_HASH_LEN))
				return FALSE;

			if (nt_memcmp(active_circuit->node_crypto_state[I].last_running_hash_b, hash_recvd, 4) == 0) {
				if (!BCRYPT_SUCCESS(BCryptHashData(active_circuit->node_crypto_state[I].running_hash_b, (PUCHAR)relay_data, sizeof(TOR_RELAY_DATA), 0)))
					return FALSE;
				decryption_successful = TRUE;
				break;
			}
			else memory_copy(relay_data->running_digest, hash_recvd, 4);
			//Means a false positive. ^
			//Last active_circuit->node_crypto_state[I].last_running_hash_b is now set to an invalid value, but this doesn't matter since we dont process invalid packets.
			//IT may however matter if we ever add parsing multiple relays at a time.
		}
	}

	if (!decryption_successful) { //the message couldn't be decrypted.
		if (active_circuit->hs3_crypto_state != NULL) {
			if (!crypto_aes_crypt_message(&active_circuit->hs3_crypto_state->crypto_state_b, (BYTE*)relay_data, sizeof(TOR_RELAY_DATA)))
				return FALSE;

			if ((relay_data->quickhash_check == 0)) {
				BYTE hash_recvd[4];
				memory_copy(hash_recvd, (const BYTE*)relay_data->running_digest, 4); //copy the has to a tmp avlue
				RtlSecureZeroMemory(relay_data->running_digest, 4);

				crypto_sha3_update(&active_circuit->hs3_crypto_state->running_hash_b, relay_data, sizeof(TOR_RELAY_DATA));
				CRYPTO_SHA3_CTXT tmp_ctx = active_circuit->hs3_crypto_state->running_hash_b;
				crypto_sha3_final(active_circuit->hs3_crypto_state->last_running_hash_b, &tmp_ctx);

				if (nt_memcmp(active_circuit->hs3_crypto_state->last_running_hash_b, hash_recvd, 4) != 0) {
					DEBUG_ERROR("HS3 decryption: Error when verifying the relay hash against the known backwards running hash.");
					return FALSE;
				}
			}
		}
		else return FALSE;
	}

	relay_data->data_sz = htons(relay_data->data_sz);
	relay_data->stream_id = htons(relay_data->stream_id);
	return TRUE;
}
