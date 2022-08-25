#pragma once
#include "uTor_relay.h"

typedef struct {
    UINT16 stream_id;
    UINT32 num_recvd_bytes; //the total amount of bytes currently available to be read.
    BYTE recv_buffer[TOR_MAX_RELAY_PAYLOAD_LEN];
    BOOL is_connected;
    TOR_CIRCUIT* circuit;
    TOR_FLOWCTL_DATA stream_flowcontrol_data;
} TOR_STREAM;

/*
*
   package_window_curr - default start val $circwindow for circuits, 500 for streams.
   Used when a cell is to be sent to a stream.
   If package window >== 0< pause transmission (recv & send) until we receive a sendme (this would eventually result in a timeout).
   When a sendme is recvd we increase this by 100.

   deliver_window_curr - default start val $circwindow for circuits, 500 for streams.
   If a deliver window goes >below< 0, the circuit should be torn down. << Dont really understand this, when can this actually happen..?
   For every 100 the deliver window gets decreased, we send a sendme.
   Used when a cell has been delivered to us for any stream.
*/
//Hashes for sendme cell.

#define TOR_STREAM_FLAG_OPEN_DIR 1 << 0 //opens the directory of the end node in the circuit.

BOOL tor_stream_begin(TOR_STREAM* active_stream, BYTE flags, TOR_CIRCUIT* target_circ, CHAR* zt_addr, BYTE zt_addr_sz); //begins new stream, net_addr null if directory
BOOL tor_stream_send(TOR_STREAM* active_stream, BYTE* data, INT32 data_sz); //send a sendme if needed and data.
BOOL tor_stream_recv(TOR_STREAM* active_stream, BYTE* data_out, INT32 bytes_max); //returns available data for a stream and if none is available we do recvuntil relay_data.