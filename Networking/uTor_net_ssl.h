#pragma once
#define SECURITY_WIN32

//TODO: Rearrange includes.
#include "uTor_net_tcp.h"
#include <sspi.h>
#include <schannel.h>

#define SEC_SUCCESS(Status) ((Status) >= SEC_E_OK)
#define STOR_SSL_SSPI_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_STREAM)
#define NET_SSL_MAX_MSG_LEN 0x10000 //Defines the maximum buffer size of the IO buffers in the SSL implementation

typedef struct {
	BYTE iobuf_send[NET_SSL_MAX_MSG_LEN];
	BYTE iobuf_recv[NET_SSL_MAX_MSG_LEN];

	BYTE* extra_ptr;
	INT32 extra_recv_bytes;

	SecPkgContext_StreamSizes stream_szs;
	CtxtHandle context_handle;
	CtxtHandle cred_handle;
	SOCKET socket_tcp;
} NET_SSL_STREAM;

BOOL net_ssl_create_stream(NET_SSL_STREAM* ssl_socket);
BOOL net_ssl_destroy_stream(NET_SSL_STREAM* ssl_socket);

BOOL net_ssl_connect(NET_SSL_STREAM* ssl_socket, NETADDR_IPV4* remote_address);
BOOL net_ssl_disconnect(NET_SSL_STREAM* ssl_socket);

BOOL net_ssl_recv(NET_SSL_STREAM* ssl_socket, DWORD* data_size);
BOOL net_ssl_send(NET_SSL_STREAM* ssl_socket, const DWORD data_sz);