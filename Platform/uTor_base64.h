#pragma once
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#include "uTor_memory.h"
#include "uTor_string.h"

#define BASE64_DECODE_SIZE_ANY 0

#define BASE64_ARMORED_MAX_DATA_SZ (128 * 1024) //(32kb) Defines the max base64 data size that can be decoded by the sTor_parse_base64_armored() function

CONST UINT32 base64_decode(CONST BYTE* raw_data, CONST INT32 raw_data_sz, BYTE* decoded_data, CONST UINT32 max_unpacked_sz);

CONST UINT32 base64_decode_armored(BYTE** row_context, CONST BYTE* start_bracket, CONST UINT32 start_bracket_sz, CONST BYTE* end_bracket, CONST UINT32 end_bracket_sz, BYTE* decoded_data, CONST UINT32 max_unpacked_sz);