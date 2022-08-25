#include "uTor_http.h"
#include "../Platform/uTor_debug.h"
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/tinf.h"


static BYTE* recvd_data = NULL;
static BYTE* uncompressed_data = NULL;

BOOL net_http_init() {
	recvd_data = memory_alloc(NET_HTTP_DECOMP_BUFFER_SZ);
	if (recvd_data == NULL)
		return FALSE;
	uncompressed_data = memory_alloc(NET_HTTP_DECOMP_BUFFER_SZ); //NOTE: We can change this but it probably isn't necessary.
	if (uncompressed_data == NULL)
		return FALSE;
	DEBUG_VERBOSE("HTTP functionality has been initialized!");
	return TRUE;
}

VOID net_http_free() {
	memory_free(uncompressed_data);
	memory_free(recvd_data);
}

BOOL net_http_get(CONST BYTE flags, CONST NET_HTTP_GET_REQUEST* request_data, PARSE_FUNC_TYPE parse_func, VOID* parse_data, CONST UINT32 MAX_ALLOWED_SZ) {
	BOOL ret_val = FALSE;
#ifdef _DEBUG
	if (MAX_ALLOWED_SZ < 6)
		return FALSE;
	if (MAX_ALLOWED_SZ > NET_HTTP_RECV_BUFFER_SZ)
		return FALSE;
#endif
	BYTE internal_buffer[NET_HTTP_BLOCK_RECV_AMNT];
	memory_zero(internal_buffer, NET_HTTP_BLOCK_RECV_AMNT);

	INT32 total_request_sz = nt_sprintf_s(internal_buffer, NET_HTTP_BLOCK_RECV_AMNT, "GET %s HTTP/1.0\r\nConnection: close\r\n\r\n", request_data->resource_path);
	if (total_request_sz == -1)
		return FALSE;

	if (flags & NET_HTTP_FLAG_USE_TOR) {
		DEBUG_INFO("Requesting: 'TOR_CIRCUIT: %u%s'", request_data->tor_stream->circuit->circuit_id, request_data->resource_path);
		if (!tor_stream_send(request_data->tor_stream, internal_buffer, total_request_sz))
			goto FAILURE;
	}
	else {
		//DEBUG_INFO("Requesting: '%s' from socket '%zu'.", request_data->resource_path, request_data->tcp_socket);
		if (send(request_data->tcp_socket, internal_buffer, total_request_sz, 0) != total_request_sz)
			goto FAILURE;
	}

	INT32 recvd_bytes = 0;
	if (flags & NET_HTTP_FLAG_USE_TOR)
		recvd_bytes = tor_stream_recv(request_data->tor_stream, internal_buffer, NET_HTTP_BLOCK_RECV_AMNT);
	else recvd_bytes = recv(request_data->tcp_socket, internal_buffer, NET_HTTP_BLOCK_RECV_AMNT, 0);

	if (recvd_bytes < 5)
		goto FAILURE;

	UINT16 response_code = 0;
	if (nt_sscanf_s(internal_buffer, "HTTP/%*hhu.%*hhu %hu %*32s\r\n", &response_code) != 1) {
		DEBUG_ERROR("The website gave us a malformed response.");
		goto FAILURE;
	}

	if (response_code != 200) {
		DEBUG_ERROR("Website responded with error code: %hu", response_code);
		goto FAILURE;
	}

	BYTE* data_start = nt_strstr(internal_buffer, "\r\n\r\n");
	if (data_start == NULL)
		goto FAILURE;

	data_start += 4;
	if (data_start >= (internal_buffer + NET_HTTP_BLOCK_RECV_AMNT))
		goto FAILURE;

	INT32 rem = (data_start - internal_buffer);
	INT32 total_recvd = (recvd_bytes - rem);

	memory_copy(recvd_data, data_start, total_recvd);
	memory_zero(recvd_data + total_recvd, rem);

	CONST UINT64 time_start = GetTickCount64();

	while (1) {
		if ((GetTickCount64() - time_start) > NET_HTTP_TIMEOUT_S)
			goto FAILURE;
		memory_zero(internal_buffer, NET_HTTP_BLOCK_RECV_AMNT);

		if (flags & NET_HTTP_FLAG_USE_TOR)
			recvd_bytes = tor_stream_recv(request_data->tor_stream, internal_buffer, NET_HTTP_BLOCK_RECV_AMNT);
		else recvd_bytes = recv(request_data->tcp_socket, internal_buffer, NET_HTTP_BLOCK_RECV_AMNT, 0);

		if (recvd_bytes < 0)
			goto FAILURE;
		if (recvd_bytes == 0)
			break;
		if ((total_recvd + recvd_bytes) >= MAX_ALLOWED_SZ)
			goto FAILURE;
		memory_copy(recvd_data + total_recvd, internal_buffer, recvd_bytes);
		total_recvd += recvd_bytes;
	}
	DEBUG_VERBOSE("Downloaded %u bytes of data from the remote server  - Took: '%zu' ms", total_recvd, GetTickCount64() - time_start);

	if (!(flags & NET_HTTP_FLAG_USE_TOR)) {

		UINT32 len = NET_HTTP_DECOMP_BUFFER_SZ;
		INT32 res = tinf_zlib_uncompress(uncompressed_data, &len, recvd_data, total_recvd);

		if (res != TINF_OK) {
			DEBUG_ERROR("Inflating the data failed!");
			goto FAILURE;
		}
	}

	if (parse_func != NULL) {
		if (uTor_http_parse_func_exec((flags & NET_HTTP_FLAG_USE_TOR) ? recvd_data : uncompressed_data, parse_func, parse_data)) //Remote violation, local error and etc detection.
			ret_val = TRUE;
		else {
			DEBUG_ERROR("Failed to parse the http resource.");
		}
	}
	else {
		ret_val = TRUE;
	}
FAILURE:
	return ret_val;
}
