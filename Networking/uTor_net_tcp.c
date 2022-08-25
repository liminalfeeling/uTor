//#include "constants.h"
#include "uTor_net_tcp.h"
#include "../Platform/uTor_memory.h"
#include "../Platform/uTor_time.h"
#include "../Platform/uTor_debug.h"
#include <MSWSock.h>
#include <WS2tcpip.h>

const SOCKET net_tcp_connect(const NETADDR_IPV4* remote_addr) {
    //DEBUG_INFO("Establishing a TCP connection to: %hhu.%hhu.%hhu.%hhu:%hu", remote_addr->addr_octet[0], remote_addr->addr_octet[1], remote_addr->addr_octet[2], remote_addr->addr_octet[3], remote_addr->port_u16);

    CONST SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return INVALID_SOCKET;

    SOCKADDR_IN sockaddr;
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(remote_addr->port_u16);
    sockaddr.sin_addr.s_addr = remote_addr->addr_u32;
    memory_zero(sockaddr.sin_zero, sizeof(sockaddr.sin_zero));

    // put socked in non-blocking mode...
    u_long block = 1;
    if (ioctlsocket(sock, FIONBIO, &block) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    if (connect(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sock);
            DEBUG_ERROR("An error occured when attempting to establish a TCP connection.");
            return INVALID_SOCKET;
        }

        // connection pending
        fd_set setW, setE;
        FD_ZERO(&setW);
        FD_SET(sock, &setW);
        FD_ZERO(&setE);
        FD_SET(sock, &setE);

        TIMEVAL time_out = { 0 };
        time_out.tv_sec = NET_TCP_CONNTIMEOUT;
        time_out.tv_usec = 0;

        int ret = select(0, NULL, &setW, &setE, &time_out);
        if (ret <= 0) {
            // select() failed or connection timed out
            closesocket(sock);
            if (ret == 0)
                WSASetLastError(WSAETIMEDOUT);
            DEBUG_ERROR("An error has occured when attempting to establish a TCP connection.");
            return INVALID_SOCKET;
        }

        if (FD_ISSET(sock, &setE)) {
            // connection failed
            DEBUG_ERROR("An error has occured when attempting to establish a TCP connection.");
            closesocket(sock);
            return INVALID_SOCKET;
        }
    }

    block = 0;
    if (ioctlsocket(sock, FIONBIO, &block) == SOCKET_ERROR) {
        closesocket(&sock);
        DEBUG_ERROR("There was a failure when setting a TCP socket to block.");
        return INVALID_SOCKET;
    }


    INT32 iTimeout = NET_TCP_IO_TIMEOUT;
    if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &iTimeout, sizeof(iTimeout)) == SOCKET_ERROR) ||
        (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)) {
        closesocket(sock);
        DEBUG_ERROR("There was a failure when setting a TCP socket's IO timeout values.");
        return INVALID_SOCKET;
    }

    //  DEBUG_VERBOSE("TCP connection successfully established.");
    return sock;
}

INT32 net_tcp_ping(NETADDR_IPV4* remote_addr) {
    const ULONGLONG last = GetTickCount64();
    SOCKET tcp_socket = net_tcp_connect(remote_addr);
    if (tcp_socket == INVALID_SOCKET)
        return -1;

    closesocket(tcp_socket);
    const ULONGLONG res = GetTickCount64() - last;
    return res;
}
