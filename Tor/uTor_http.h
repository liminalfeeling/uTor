#pragma once
#include "../Networking/uTor_net_tcp.h"
#include "../Networking/uTor_net_parsing.h"
#include "uTor_stream.h"

#define NET_HTTP_FLAG_USE_TOR 1ULL << 0ULL

#define NET_HTTP_MAX_DECOMP_SZ 40 * 1024 * 1024 //Defines the max decompressable amount of data in a net_http_get() call.
#define NET_HTTP_BLOCK_RECV_AMNT 3768 //For each recv call in sTor_http_parse_get(), how much do we receive?
#define NET_HTTP_RECV_BUFFER_SZ 8 * 1024 * 1024 //absolute maximum size of a file.
#define NET_HTTP_DECOMP_BUFFER_SZ 8 * 1024 * 1024

#define NET_HTTP_TIMEOUT_S 25000 //25s is the maximum allowed time for a download.

typedef struct {
	union {
		SOCKET tcp_socket; //UINT_PTR, these 2 are same size.
		TOR_STREAM* tor_stream;
	};
	CONST CHAR* resource_path;
} NET_HTTP_GET_REQUEST;

BOOL net_http_init();
VOID net_http_free();
BOOL net_http_get(CONST BYTE flags, CONST NET_HTTP_GET_REQUEST* request_data, PARSE_FUNC_TYPE parse_func, VOID* parse_data, CONST UINT32 MAX_ALLOWED_SZ);
