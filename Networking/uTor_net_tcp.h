#pragma once
#include <winsock2.h>

#define NET_TCP_CONNTIMEOUT 3 //seconds
#define NET_TCP_IO_TIMEOUT 10000 //milliseconds, Defines the time for a receive or send timeout to occur in a socket.

#pragma pack(push)
#pragma pack(1)
typedef struct {
	union {
		BYTE addr_octet[4];
		DWORD addr_u32;
	};
	UINT16 port_u16;
} NETADDR_IPV4;
#pragma pack(pop)

const SOCKET net_tcp_connect(const NETADDR_IPV4* remote_addr);
INT32 net_tcp_ping(NETADDR_IPV4* remote_addr);
