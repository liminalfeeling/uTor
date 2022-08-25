#pragma once
#include "uTor_cell_io.h"
#include "uTor_node_info.h"

BOOL tor_guard_node_connect(TOR_CELL_IO_CONTEXT* new_context, TOR_NODE_INFO* target_node); //Extends the connection to the specified node.
BOOL tor_guard_node_disconnect(TOR_CELL_IO_CONTEXT* context);