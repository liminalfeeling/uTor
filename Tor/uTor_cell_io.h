#pragma once
#include "../Networking/uTor_net_ssl.h"

enum TOR_CELL_CMD {
	TOR_CELL_CMD_PADDING = 0,
	TOR_CELL_CMD_CREATE = 1,
	TOR_CELL_CMD_CREATED = 2,
	TOR_CELL_CMD_RELAY = 3,
	TOR_CELL_CMD_DESTROY = 4,
	TOR_CELL_CMD_CREATE_FAST = 5,
	TOR_CELL_CMD_CREATED_FAST = 6,
	TOR_CELL_CMD_VERSIONS = 7, //Variable
	TOR_CELL_CMD_NETINFO = 8,
	TOR_CELL_CMD_RELAY_EARLY = 9,
	TOR_CELL_CMD_CREATE2 = 10,
	TOR_CELL_CMD_CREATED2 = 11,
	TOR_CELL_CMD_VPADDING = 128,//Variable
	TOR_CELL_CMD_CERTS = 129,//Variable
	TOR_CELL_CMD_AUTH_CHALLENGE = 130,//Variable
	TOR_CELL_CMD_AUTHENTICATE = 131//Variable
};

#define TOR_IS_CELL_VARIABLE(X) ((X == TOR_CELL_CMD_VERSIONS) || (X > 127))
#define TOR_FIXED_CELL_DATA_LEN 509

typedef struct {
	NET_SSL_STREAM ssl_stream; //ssl socket you are using.
	UINT8 tor_protocol_ver; //protocol ver, negotiated in versions 1-5
	UINT32 recv_total_available_bytes;
	UINT32 recv_current_data_index;
	UINT32 send_current_data_index;
	NETADDR_IPV4 local_address; //our ipv4 address
} TOR_CELL_IO_CONTEXT;

#pragma pack(push)
#pragma pack(1)
typedef struct {
	UINT32 circuit_id; //CIRCID_LEN = 4 for ver 4 and over, otw 2
	UINT8 cmd;
	UINT16 cell_len;
} TOR_CELL_HEADER;
#pragma pack(pop)

BOOL tor_cell_io_send(TOR_CELL_IO_CONTEXT* context, CONST UINT32 circid, CONST enum TOR_CELL_CMD cell_command, CONST BYTE* data, CONST UINT16 data_len);
BOOL tor_cell_io_recv(TOR_CELL_IO_CONTEXT* context, TOR_CELL_HEADER* cell_header, BYTE* data, CONST UINT16 max_data_len);

#define TOR_CELL_IO_SEND(context, circuit_id, cell_command, data) tor_cell_io_send(context, circuit_id, cell_command, data, TOR_FIXED_CELL_DATA_LEN)
#define TOR_CELL_IO_RECV(context, cell_header, data, max_data_len) tor_cell_io_recv(context, cell_header, data, max_data_len)
