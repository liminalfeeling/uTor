#include "uTor_guard_node.h"
#include "uTor_linkspec.h"
#include "../Platform/uTor_debug.h"
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_memory.h"

BOOL tor_guard_node_exchange_netinfo(TOR_CELL_IO_CONTEXT* cell_io_context, TOR_NODE_INFO* target_node) {
	TOR_CELL_HEADER header;
	BYTE netinfo_data[TOR_FIXED_CELL_DATA_LEN] = { 0 };

	if (!TOR_CELL_IO_RECV(cell_io_context, &header, netinfo_data, TOR_FIXED_CELL_DATA_LEN))
		return FALSE;
	if (header.cmd != TOR_CELL_CMD_NETINFO)
		return FALSE;

	UINT32 netinfo_timestamp = *((UINT32*)netinfo_data);
	TOR_LINKSPEC_HEADER* local_ls_hdr = (netinfo_data + sizeof(UINT32));

	if (!((local_ls_hdr->ls_type == 4) && (local_ls_hdr->ls_len == 4)))
		return FALSE;

	BYTE* local_addr_data = ((BYTE*)local_ls_hdr + sizeof(TOR_LINKSPEC_HEADER));

	BYTE num_remote_specs = *(local_addr_data + local_ls_hdr->ls_len);
	if (num_remote_specs > 2)
		return FALSE;

	TOR_LINKSPEC_HEADER* remote_addr_hdr = (local_addr_data + local_ls_hdr->ls_len + 1);
	BYTE* remote_addr_data = NULL;

	for (INT32 I = 0; I != num_remote_specs; I++) {
		if (remote_addr_hdr->ls_type == 4) {
			if (remote_addr_hdr->ls_len != 4)
				return FALSE;
			remote_addr_data = ((BYTE*)remote_addr_hdr) + sizeof(TOR_LINKSPEC_HEADER);
			break; //we only really care about ipv4.
		}
		else
			if (remote_addr_hdr->ls_type == 6) {
				if (remote_addr_hdr->ls_len != 16)
					return FALSE;
			}
			else return FALSE; //invalid link spec.
		remote_addr_hdr = (((BYTE*)remote_addr_hdr) + sizeof(TOR_LINKSPEC_HEADER) + remote_addr_hdr->ls_len);
	}

	if (remote_addr_data == NULL)
		return FALSE;

	if (nt_memcmp(remote_addr_data, &target_node->remote_addr.addr_u32, 4) != 0) {
		DEBUG_ERROR("The connection to the first node was not through its cannonical address!");
		return FALSE;
	}

	DEBUG_VERBOSE("Received netinfo says our ipv4 address is: %hhu.%hhu.%hhu.%hhu", local_addr_data[0], local_addr_data[1], local_addr_data[2], local_addr_data[3]);
	DEBUG_VERBOSE("Received netinfo says its address is: %hhu.%hhu.%hhu.%hhu", remote_addr_data[0], remote_addr_data[1], remote_addr_data[2], remote_addr_data[3]);
	DEBUG_VERBOSE("Verified that the connection is to the cannonical address of the node.");

	memory_copy(cell_io_context->local_address.addr_octet, local_addr_data, sizeof(cell_io_context->local_address.addr_octet));

	BYTE remote_addr[4]; //OUR ADDRESS
	BYTE local_ip[4]; //THEIR ADDRESS
	BYTE* netinfo_start = netinfo_data + (sizeof(UINT32) + sizeof(TOR_LINKSPEC_HEADER));

	memory_copy(remote_addr, local_addr_data, 4);
	memory_copy(local_ip, remote_addr_data, 4);

	memory_zero(netinfo_start, TOR_FIXED_CELL_DATA_LEN - (sizeof(UINT32) + sizeof(TOR_LINKSPEC_HEADER)));

	memory_copy(netinfo_start, remote_addr, 4);
	netinfo_start[4] = 1;  netinfo_start[5] = 4; netinfo_start[6] = 4;
	memory_copy(&netinfo_start[7], local_ip, 4);

	return TOR_CELL_IO_SEND(cell_io_context, 0, TOR_CELL_CMD_NETINFO, &netinfo_data);
}

BOOL tor_guard_node_connect(TOR_CELL_IO_CONTEXT* cell_io_context, TOR_NODE_INFO* target_node) {
	DEBUG_INFO("Attempting to connect to guard node '%s'", target_node->name);
	if (!net_ssl_connect(&cell_io_context->ssl_stream, &target_node->remote_addr))
		return FALSE;

	//Send our versions cell:
	cell_io_context->tor_protocol_ver = 0;

	TOR_CELL_HEADER header = { 0, TOR_CELL_CMD_VERSIONS, 2 };
	SHORT vers[10] = { ntohs(4) };

	if (!tor_cell_io_send(cell_io_context, 0, TOR_CELL_CMD_VERSIONS, vers, sizeof(SHORT)))
		goto EXIT;
	if (!tor_cell_io_recv(cell_io_context, &header, vers, sizeof(SHORT) * 10))
		goto EXIT;

	if (header.cmd != TOR_CELL_CMD_VERSIONS)
		goto EXIT;
	if (((header.cell_len % 2) != 0) || (header.cell_len == 0) || (header.cell_len > sizeof(UINT16) * 6)) //there are only 5 versions, support for an extra reserved..
		goto EXIT;

	for (UINT32 I = 0; I != (header.cell_len / 2); I++) {
		vers[I] = ntohs(vers[I]);
		if ((vers[I] > cell_io_context->tor_protocol_ver) && (vers[I] <= 4))
			cell_io_context->tor_protocol_ver = (UINT8)vers[I]; //This conversion isnt a problem, the reason it is a U16 in the first place is for the bswap. the value wont ever exceed 0xFF
	}

	if (cell_io_context->tor_protocol_ver < 4)
		goto EXIT;

	DEBUG_VERBOSE("The active Tor link protocol has version: %hhu", cell_io_context->tor_protocol_ver);

	for (BYTE X = 0; X != 2; X++) {
		header.cell_len = 3768;
		if (!tor_cell_io_recv(cell_io_context, &header, NULL, 3768))
			goto EXIT;
		if (!((header.cmd == TOR_CELL_CMD_CERTS) || (header.cmd == TOR_CELL_CMD_AUTH_CHALLENGE)))
			goto EXIT;
	}

	if (tor_guard_node_exchange_netinfo(cell_io_context, target_node))
		return TRUE;
EXIT:
	tor_guard_node_disconnect(cell_io_context);
	return FALSE;
}

BOOL tor_guard_node_disconnect(TOR_CELL_IO_CONTEXT* context) {
	if (!net_ssl_disconnect(&context->ssl_stream))
		return FALSE;

	context->tor_protocol_ver = 0; //protocol ver, negotiated in versions 1-5
	context->recv_total_available_bytes = 0;
	context->recv_current_data_index = 0;
	context->send_current_data_index = 0;
	DEBUG_VERBOSE("A guard node has been disconnected.");
	return TRUE;
}