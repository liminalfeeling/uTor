#include "uTor_net_ssl.h"
#include "../Platform/uTor_debug.h"
#include "../Platform/uTor_memory.h"

BOOL net_ssl_create_stream(NET_SSL_STREAM* ssl_socket) {
	SCHANNEL_CRED schannel_creds = { SCHANNEL_CRED_VERSION, 0, NULL, NULL, NULL, NULL, NULL, NULL, SP_PROT_TLS1_X_CLIENT, NULL, NULL, NULL, SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION, NULL };
	ssl_socket->socket_tcp = 0;
	return (AcquireCredentialsHandleA(NULL, "Microsoft Unified Security Protocol Provider", SECPKG_CRED_OUTBOUND, NULL, &schannel_creds, NULL, NULL, &ssl_socket->cred_handle, NULL) == SEC_E_OK);
}

BOOL net_ssl_destroy_stream(NET_SSL_STREAM* ssl_socket) {
	if (ssl_socket->socket_tcp != 0) { //If we haven't already disconnected.
		if (!net_ssl_disconnect(ssl_socket))
			return FALSE;
	}

	if ((ssl_socket->cred_handle.dwUpper != 0) || (ssl_socket->cred_handle.dwLower != 0)) {
		if (!(FreeCredentialsHandle(&ssl_socket->cred_handle) == SEC_E_OK))
			return FALSE;
	}

	RtlSecureZeroMemory(ssl_socket, sizeof(NET_SSL_STREAM));
	return TRUE;
}

BOOL net_ssl_disconnect(NET_SSL_STREAM* ssl_socket) {
	if (ssl_socket->socket_tcp != 0) {
		closesocket(ssl_socket->socket_tcp);
		ssl_socket->extra_recv_bytes = 0;
		ssl_socket->socket_tcp = 0;
		DEBUG_VERBOSE("The ssl socket has now been closed!");
		return (DeleteSecurityContext(&ssl_socket->context_handle) == SEC_E_OK);
	}
	return TRUE;
}

BOOL sTor_ssl_handshake(NET_SSL_STREAM* socket_ssl) {
	INT32 recvd_bytes = 0;
	SECURITY_STATUS sec_status = SEC_I_CONTINUE_NEEDED;

	while ((sec_status == SEC_E_INCOMPLETE_MESSAGE) || (sec_status == SEC_I_CONTINUE_NEEDED)) {
		recvd_bytes = recv(socket_ssl->socket_tcp, socket_ssl->iobuf_recv, NET_SSL_MAX_MSG_LEN, 0);
		if (recvd_bytes < 0) {
			DEBUG_VERBOSE("sTor_ssl_handshake(): receive failed with error: %#010x", WSAGetLastError());
			return FALSE;
		}

		UINT32 flags_sspi = STOR_SSL_SSPI_FLAGS;
		SecBuffer recv_buffers[2] = { { recvd_bytes, SECBUFFER_TOKEN, socket_ssl->iobuf_recv }, { 0, SECBUFFER_EMPTY, NULL } };
		SecBuffer send_buffer = { NET_SSL_MAX_MSG_LEN, SECBUFFER_TOKEN, socket_ssl->iobuf_send };
		SecBufferDesc recv_buffer_dsc = { SECBUFFER_VERSION, 2, recv_buffers };
		SecBufferDesc send_buffer_dsc = { SECBUFFER_VERSION, 1, &send_buffer };

		sec_status = InitializeSecurityContextA(&socket_ssl->cred_handle, &socket_ssl->context_handle, NULL, STOR_SSL_SSPI_FLAGS, 0, SECURITY_NATIVE_DREP, &recv_buffer_dsc, 0, NULL, &send_buffer_dsc, &flags_sspi, NULL);

		if ((send_buffer.cbBuffer != 0)) {
			if (send(socket_ssl->socket_tcp, send_buffer.pvBuffer, send_buffer.cbBuffer, 0) != send_buffer.cbBuffer)
				return FALSE;
		}
	}

	return (sec_status == SEC_E_OK);
}

BOOL net_ssl_connect(NET_SSL_STREAM* ssl_socket, NETADDR_IPV4* remote_address) {
#if (defined(_DEBUG) || defined(_RELEASE_TEST))
	if (ssl_socket->socket_tcp != 0) {
		DEBUG_ERROR("CANNOT CONNECT WHEN THE SSL SOCKET IS ALREADY CONNNECTED");
		return FALSE;
	}
#endif;
	ssl_socket->socket_tcp = net_tcp_connect(remote_address);
	if (ssl_socket->socket_tcp == INVALID_SOCKET)
		goto EXIT;

	SecBuffer send_buffer = { NET_SSL_MAX_MSG_LEN, SECBUFFER_TOKEN, ssl_socket->iobuf_send };
	SecBufferDesc send_buffer_dsc = { SECBUFFER_VERSION, 1, &send_buffer };
	UINT32 flags_out = 0;

	if (InitializeSecurityContextA(&ssl_socket->cred_handle, NULL, NULL, STOR_SSL_SSPI_FLAGS, 0, SECURITY_NATIVE_DREP, NULL, 0, &ssl_socket->context_handle, &send_buffer_dsc, &flags_out, NULL) != SEC_I_CONTINUE_NEEDED)
		goto EXIT;
	if (send_buffer.cbBuffer == 0)
		goto EXIT;
	if (send(ssl_socket->socket_tcp, send_buffer.pvBuffer, send_buffer.cbBuffer, 0) != send_buffer.cbBuffer)
		goto EXIT;

	if (sTor_ssl_handshake(ssl_socket)) {
		SECURITY_STATUS s = QueryContextAttributesA(&ssl_socket->context_handle, SECPKG_ATTR_STREAM_SIZES, &ssl_socket->stream_szs);
		if (s == SEC_E_OK) {
			if ((ssl_socket->stream_szs.cbMaximumMessage + ssl_socket->stream_szs.cbHeader + ssl_socket->stream_szs.cbTrailer) <= NET_SSL_MAX_MSG_LEN) { //most probably.. 99%... not needed, who knows.. better safe than sorry right?
				return TRUE;
			}
		}
	}

EXIT:
	net_ssl_disconnect(ssl_socket);
	return FALSE;
}

BOOL net_ssl_send(NET_SSL_STREAM* ssl_socket, const DWORD data_sz) {
	SecBuffer sec_buffers[4] = {
		{ ssl_socket->stream_szs.cbHeader, SECBUFFER_STREAM_HEADER, ssl_socket->iobuf_send },
		{ data_sz, SECBUFFER_DATA, ssl_socket->iobuf_send + (INT64)ssl_socket->stream_szs.cbHeader },
		{ ssl_socket->stream_szs.cbTrailer, SECBUFFER_STREAM_TRAILER, ssl_socket->iobuf_send + (INT64)ssl_socket->stream_szs.cbHeader + data_sz },
		{ 0 }
	};

	SecBufferDesc secure_msg = { SECBUFFER_VERSION, 4, sec_buffers };
	if (FAILED(EncryptMessage(&ssl_socket->context_handle, 0, &secure_msg, 0))) {
		DEBUG_ERROR("sTor_ssl_send(): error during encryption.");
		return FALSE;
	}

	const DWORD len = (sec_buffers[0].cbBuffer + sec_buffers[1].cbBuffer + sec_buffers[2].cbBuffer);
	return (send(ssl_socket->socket_tcp, ssl_socket->iobuf_send, len, 0) == len);
}


BOOL net_ssl_recv(NET_SSL_STREAM* ssl_socket, DWORD* data_size) {
	SECURITY_STATUS security_status = SEC_E_INCOMPLETE_MESSAGE;
	DWORD requested_sz = ssl_socket->stream_szs.cbHeader + ssl_socket->stream_szs.cbMaximumMessage + ssl_socket->stream_szs.cbTrailer; //This is checked in the connect call, so that we dont exceed the socket_ssl iorb.
	DWORD totalBytes = 0;

	while (1) {
		if ((security_status == SEC_E_INCOMPLETE_MESSAGE)) {
			INT32 curr_bytes_recvd = 0;
			if (ssl_socket->extra_recv_bytes != 0) {
				memory_copy(ssl_socket->iobuf_recv, ssl_socket->extra_ptr, ssl_socket->extra_recv_bytes);
				curr_bytes_recvd = ssl_socket->extra_recv_bytes;
				ssl_socket->extra_recv_bytes = 0;
			}
			else {
				curr_bytes_recvd = recv(ssl_socket->socket_tcp, ssl_socket->iobuf_recv + (INT64)totalBytes, requested_sz - totalBytes, 0);
				if (curr_bytes_recvd == -1)
					return FALSE;
				if (curr_bytes_recvd == 0) {
					DEBUG_WARNING("sTor_ssl_recv(): remote end closed connection (curr_bytes_recvd == 0)");
					(*data_size) = 0;
					return FALSE;
				}
			}
			totalBytes += curr_bytes_recvd;
		}

		SecBuffer sec_buffers[4] = { { totalBytes, SECBUFFER_DATA, ssl_socket->iobuf_recv }, { 0 }, { 0 }, { 0 } };
		SecBufferDesc secure_msg = { SECBUFFER_VERSION, 4, sec_buffers };

		security_status = DecryptMessage(&ssl_socket->context_handle, &secure_msg, 0, NULL);
		if (security_status != SEC_E_OK) {
			if (security_status == SEC_E_INCOMPLETE_MESSAGE)
				continue;
			if ((security_status == SEC_I_CONTEXT_EXPIRED) || (security_status == SEC_I_RENEGOTIATE)) {
				DEBUG_WARNING("sTor_ssl_recv(): remote end closed connection (SEC_I_RENEGOTIATE || SEC_I_CONTEXT_EXPIRED).");
				return FALSE;
			}
			DEBUG_ERROR("sTor_ssl_recv(): TLS error occured when attempting to receive data");
			return FALSE;
		}

		for (BYTE I = 1; I != 4; I++) {
			if (sec_buffers[I].BufferType == SECBUFFER_DATA) {
				if ((sec_buffers[I].cbBuffer != 0) && (sec_buffers[I].pvBuffer != NULL)) {
					(*data_size) = sec_buffers[I].cbBuffer;
					memory_copy(ssl_socket->iobuf_recv, sec_buffers[I].pvBuffer, sec_buffers[I].cbBuffer);
				}
			}
			if (sec_buffers[I].BufferType == SECBUFFER_EXTRA) {
				if (ssl_socket->extra_recv_bytes != 0) {
					DEBUG_ERROR("EXTRA DATA BUFFER FOUND WHEN WE ALREADY HAVE ONE TO HANDLE!");
					return FALSE;
				}
				ssl_socket->extra_recv_bytes = sec_buffers[I].cbBuffer;
				ssl_socket->extra_ptr = sec_buffers[I].pvBuffer;
			}
		}
		return TRUE;
	}
}
