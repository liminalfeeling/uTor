#include "uTor_cell_io.h"
#include "memory.h"

BOOL tor_cell_io_transmit_data(BOOL writing, TOR_CELL_IO_CONTEXT* context, BYTE* data, UINT32 data_sz) {
	if (writing) {
		memory_copy(context->ssl_stream.iobuf_send + context->ssl_stream.stream_szs.cbHeader + context->send_current_data_index, data, data_sz);
		context->send_current_data_index += data_sz;
	}
	else {
		while (1) {
			const UINT32 remaining_in_buf = context->recv_total_available_bytes - context->recv_current_data_index;
			if (remaining_in_buf < data_sz) { //2. If there are insufficient bytes available.
				if (data != NULL) // < Used for data we dont handle / care about; / as a skip.
					memory_copy(data, context->ssl_stream.iobuf_recv + context->recv_current_data_index, remaining_in_buf); //3. Write the ones we currently have.
				data += remaining_in_buf; //Shift the data forward to the r half.
				data_sz -= remaining_in_buf; //bytes remaining decreased by the bytes we managed to fit in.
				if (!net_ssl_recv(&context->ssl_stream, &context->recv_total_available_bytes)) //4. Ask for the remaining bytes
					return FALSE;
				if (context->recv_total_available_bytes == 0) //disconnected.
					return FALSE;
				context->recv_current_data_index = 0; //Reset the index.
			}
			else {
				if (data != NULL)
					memory_copy(data, context->ssl_stream.iobuf_recv + context->recv_current_data_index, data_sz);
				context->recv_current_data_index += data_sz;
				break;
			}
		}
	}
	return TRUE;
}

BOOL tor_cell_io_send(TOR_CELL_IO_CONTEXT* context, CONST UINT32 circuit_id, CONST enum TOR_CELL_CMD cell_command, CONST BYTE* data, CONST UINT16 data_len) {
	TOR_CELL_HEADER be_header;
	be_header.cmd = cell_command;
	be_header.circuit_id = htonl(circuit_id);

	if (!tor_cell_io_transmit_data(TRUE, context, (BYTE*)&be_header.circuit_id, ((context->tor_protocol_ver > 3) ? 4 : 2)))
		return FALSE;
	if (!tor_cell_io_transmit_data(TRUE, context, &be_header.cmd, sizeof(be_header.cmd)))
		return FALSE;

	if (TOR_IS_CELL_VARIABLE(cell_command)) {
		be_header.cell_len = ntohs(data_len);
		if (!tor_cell_io_transmit_data(TRUE, context, (BYTE*)&be_header.cell_len, sizeof(be_header.cell_len)))
			return FALSE;
	}

	if (!tor_cell_io_transmit_data(TRUE, context, (BYTE*)data, data_len))
		return FALSE;
	if (!net_ssl_send(&context->ssl_stream, context->send_current_data_index))
		return FALSE;

	context->send_current_data_index = 0;
	return TRUE;
}

BOOL tor_cell_io_recv(TOR_CELL_IO_CONTEXT* context, TOR_CELL_HEADER* cell_header, BYTE* data, CONST UINT16 max_data_len) {
	if (!tor_cell_io_transmit_data(FALSE, context, (BYTE*)&cell_header->circuit_id, ((context->tor_protocol_ver > 3) ? 4 : 2)))
		return FALSE;
	if (!tor_cell_io_transmit_data(FALSE, context, (BYTE*)&cell_header->cmd, sizeof(cell_header->cmd)))
		return FALSE;

	cell_header->cell_len = TOR_FIXED_CELL_DATA_LEN;

	if (TOR_IS_CELL_VARIABLE(cell_header->cmd)) {
		if (!tor_cell_io_transmit_data(FALSE, context, (BYTE*)&cell_header->cell_len, sizeof(cell_header->cell_len)))
			return FALSE;
		cell_header->cell_len = ntohs(cell_header->cell_len);
	}
	if (cell_header->cell_len > max_data_len)
		return FALSE;

	cell_header->circuit_id = ntohl(cell_header->circuit_id);
	return tor_cell_io_transmit_data(FALSE, context, data, cell_header->cell_len);
}
