#pragma once
#include "uTor_circuit.h"

#define TOR_MAX_RELAY_PAYLOAD_LEN 498

#pragma pack(push)
#pragma pack(1)
typedef struct {
    BYTE relay_cmd;
    UINT16 quickhash_check;
    UINT16 stream_id;
    BYTE running_digest[4];
    UINT16 data_sz;
    BYTE data[TOR_MAX_RELAY_PAYLOAD_LEN];
} TOR_RELAY_DATA;
#pragma pack(pop)

enum TOR_RELAY_CELL_CMD {
    TOR_RELAYCMD_BEGIN = 1,
    TOR_RELAYCMD_DATA,
    TOR_RELAYCMD_END,
    TOR_RELAYCMD_CONNECTED,
    TOR_RELAYCMD_SENDME,
    TOR_RELAYCMD_EXTEND,
    TOR_RELAYCMD_EXTENDED,
    TOR_RELAYCMD_TRUNCATE,
    TOR_RELAYCMD_TRUNCATED,
    TOR_RELAYCMD_DROP,
    TOR_RELAYCMD_RESOLVE,
    TOR_RELAYCMD_RESOLVED,
    TOR_RELAYCMD_BEGIN_DIR,
    TOR_RELAYCMD_EXTEND2,
    TOR_RELAYCMD_EXTENDED2
};

BOOL tor_relay_send(TOR_CIRCUIT* active_circuit, const UINT16 stream_id, const BYTE relay_cmd, const BYTE* relay_payload, const UINT16 relay_payload_sz);
BOOL tor_relay_recv(TOR_CIRCUIT* active_circuit, TOR_RELAY_DATA* relay_data);