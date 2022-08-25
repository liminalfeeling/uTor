#pragma once
#include "uTor_circuit.h"
#include "uTor_relay.h"

BOOL tor_circuit_fully_extend(TOR_CIRCUIT* active_circuit, MODULE_TORCONN_HEADER* module_header);