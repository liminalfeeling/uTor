#include "uTor_stream.h"
#include "memory.h"

BOOL tor_stream_begin(TOR_STREAM* active_stream, BYTE flags, TOR_CIRCUIT* target_circ, CHAR* zt_addr, BYTE zt_addr_sz) {
	memory_zero(active_stream, sizeof(TOR_STREAM));

	static UINT16 stream_val = 0;
	active_stream->stream_id = ++stream_val;
	active_stream->circuit = target_circ;

	if (flags & TOR_STREAM_FLAG_OPEN_DIR) { //We want a directory.
		if (!tor_relay_send(target_circ, active_stream->stream_id, TOR_RELAYCMD_BEGIN_DIR, active_stream->recv_buffer, TOR_MAX_RELAY_PAYLOAD_LEN)) //active_stream->recv_buffer = 0
			return FALSE;
	}
	else { //Normal stream open.
		//For non directory streams, tor states this as the structure:
		/*   ADDRPORT [nul-terminated string]
			 FLAGS    [4 bytes]:
					bit   --  meaning
					1     --  IPv6 okay.  We support learning about IPv6 addresses and connecting to IPv6 addresses.
					2     --  IPv4 not okay.  We don't want to learn about IPv4 addresses or connect to them.
					3     --  IPv6 preferred.  If there are both IPv4 and IPv6 addresses, we want to connect to the IPv6 one.  (By default, we connect to the IPv4 address.)
					4..32 --  Reserved. Current clients MUST NOT set these. Servers MUST ignore them.

		*/
		BYTE pld_max[20] = { 0 };
		memory_copy(pld_max, zt_addr, zt_addr_sz);
		if (!tor_relay_send(target_circ, active_stream->stream_id, TOR_RELAYCMD_BEGIN, pld_max, zt_addr_sz + 4))
			return FALSE;
	}

	TOR_RELAY_DATA relay_data;
	if (!tor_relay_recv(target_circ, &relay_data))
		return TRUE; //True because it isnt an error, but we are not connected, remote violation.
	if (relay_data.stream_id != active_stream->stream_id)
		return TRUE; //True because it isnt an error, but we are not connected, remote violation.
	if (relay_data.relay_cmd != TOR_RELAYCMD_CONNECTED)
		return TRUE; //True because it isnt an error, but we are not connected, remote violation.

	active_stream->is_connected = TRUE;
	active_stream->stream_flowcontrol_data.deliver_window_curr = 500;
	active_stream->stream_flowcontrol_data.package_window_curr = 500;
	DEBUG_INFO("%s", flags & TOR_STREAM_FLAG_OPEN_DIR ? "Created a new directory stream" : "Created a new stream");
	return TRUE;
}

BOOL tor_stream_recvnextcell(TOR_STREAM* stream, BOOL retat_sendme) { //receives cells, returns at data or sendme.
	TOR_RELAY_DATA relay_data = { 0 };

	TOR_CIRCUIT* circ = stream->circuit;

	while (relay_data.relay_cmd != (retat_sendme ? TOR_RELAYCMD_SENDME : TOR_RELAYCMD_DATA)) {
		if (!tor_relay_recv(circ, &relay_data))
			return FALSE;

		if (relay_data.stream_id == 0) {
			if (relay_data.relay_cmd == TOR_RELAYCMD_TRUNCATED) {
				DEBUG_VERBOSE("Received a relaycmd truncated: %i, oct: %hhu", relay_data.relay_cmd, relay_data.data[0]);
				return FALSE;
			}
		}
		else if (relay_data.stream_id != stream->stream_id) {
			DEBUG_ERROR("Receieved a cell for an invalid stream ID");
			return FALSE;
		}
		else {
			//NOTE: MAY NOT USE SWITCHES DUE TO sRDI!
			if (relay_data.relay_cmd == TOR_RELAYCMD_SENDME) {
				DEBUG_VERBOSE("RECEIVED STOR_RELAYCMD_SENDME");
				//active_circuit->flowcontrol_data.package_window_curr += 100;
			}
			else
				if (relay_data.relay_cmd == TOR_RELAYCMD_DATA) {
					if ((stream->num_recvd_bytes + relay_data.data_sz) > TOR_MAX_RELAY_PAYLOAD_LEN) {
						DEBUG_ERROR("WE EXCEEDED THE ALLOWED RECV BUFFER SZ!");
						return FALSE;
					}

					circ->flowcontrol_data.deliver_window_curr--;
					stream->stream_flowcontrol_data.deliver_window_curr--;

					if (circ->flowcontrol_data.deliver_window_curr < 0) //This happens if the server keeps sending us shit (floods us) without waiting for our sendme (tor lumps multiple cells in msg keep in mind)
						return FALSE; //Tor protocol violation.
					if (stream->stream_flowcontrol_data.deliver_window_curr < 0) //This happens if the server keeps sending us shit (floods us) without waiting for our sendme (tor lumps multiple cells in msg keep in mind)
						return FALSE; //Tor protocol violation.

					if (((stream->stream_flowcontrol_data.deliver_window_curr) % 50) == 0) {
						if (!tor_relay_send(circ, stream->stream_id, TOR_RELAYCMD_SENDME, NULL, 0))
							return FALSE;
						stream->stream_flowcontrol_data.deliver_window_curr += 50;
					}

					if (((circ->flowcontrol_data.deliver_window_curr) % 100) == 0) {
						BYTE sendme_data[23] = { 0 };
						UINT16 sendmelen = htons(20);
						sendme_data[0] = 0x01;
						memory_copy(&sendme_data[1], &sendmelen, sizeof(UINT16));

						if (circ->hs3_crypto_state != NULL) { //TODO: change this line to some macro for clarity, and remove any similar lines in the relay send/recv functions.
							TOR_HS3_NTOR_CRYPTO_STATE* hs3_crypto = stream->circuit->hs3_crypto_state;
							memory_copy(&sendme_data[3], hs3_crypto->last_running_hash_b, CRYPTO_SHA1_HASH_LEN);
						}
						else memory_copy(&sendme_data[3], circ->node_crypto_state[stream->circuit->finished_circ_sz - 1].last_running_hash_b, CRYPTO_SHA1_HASH_LEN);

						if (!tor_relay_send(circ, 0, TOR_RELAYCMD_SENDME, sendme_data, 23))
							return FALSE;

						circ->flowcontrol_data.deliver_window_curr += 100;
						//send a sendme.
					}

					memory_copy(&stream->recv_buffer[stream->num_recvd_bytes], relay_data.data, relay_data.data_sz);
					stream->num_recvd_bytes += relay_data.data_sz;
				}
				else
					if (relay_data.relay_cmd == TOR_RELAYCMD_END) {
						stream->is_connected = FALSE;
						stream->num_recvd_bytes = 0;
						//STOR_DEBUG_WARNING("RECEIVED STOR_RELAYCMD_END - STREAM IS NOW MARKED AS DISCONNECTED");
						break;
					}
					else {
						DEBUG_ERROR("RECEIVED A RELAYCMD WE COULD NOT UNDERSTAND.");
						return FALSE;
					}
		}
	}

	return TRUE;
}

BOOL tor_stream_send(TOR_STREAM* active_stream, BYTE* data, INT32 data_sz) { //send a sendme if needed and data.
	while (data_sz != 0) {
		/*
		TODO: WE DONT REALLY CARE ABOUT THIS PART YET.

		active_circuit->flowcontrol_data.package_window_curr--;
		if (active_circuit->flowcontrol_data.package_window_curr == 0) {
			//should wait for a sendme.
			if (!sTor_circuit_stream_recvnextcell(active_circuit, TRUE))
				return FALSE;
		}
		*/
		BYTE relay_data[TOR_MAX_RELAY_PAYLOAD_LEN];
		memory_zero(relay_data, TOR_MAX_RELAY_PAYLOAD_LEN);

		INT32 curr_cycle_bytes = data_sz;
		if (curr_cycle_bytes > TOR_MAX_RELAY_PAYLOAD_LEN)
			curr_cycle_bytes = TOR_MAX_RELAY_PAYLOAD_LEN;

		memory_copy(relay_data, data, curr_cycle_bytes);
		data += curr_cycle_bytes;

		if (!tor_relay_send(active_stream->circuit, active_stream->stream_id, TOR_RELAYCMD_DATA, relay_data, curr_cycle_bytes))
			return FALSE;

		DEBUG_VERBOSE("Sent relay data of size: %i", curr_cycle_bytes);
		data_sz -= curr_cycle_bytes;
	}
	return TRUE;
}

BOOL tor_stream_recv(TOR_STREAM* active_stream, BYTE* data_out, INT32 bytes_max) { //returns available data for a stream and if none is available we do recvuntil relay_data.
	if (active_stream->num_recvd_bytes == 0) { //if we dont have data to read.
		if (!tor_stream_recvnextcell(active_stream, FALSE)) //wait for next read.
			return -1;
	}

	INT32 tmp = active_stream->num_recvd_bytes;
	if (tmp > TOR_MAX_RELAY_PAYLOAD_LEN)
		tmp = TOR_MAX_RELAY_PAYLOAD_LEN;

	active_stream->num_recvd_bytes -= tmp;
	memory_copy(data_out, active_stream->recv_buffer, tmp);
	return tmp;
}