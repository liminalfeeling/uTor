#pragma once
//TODO: Make cross platform.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "uTor_debug.h"

BYTE* memory_alloc(SIZE_T sz);
BOOL memory_free(BYTE* mem_addr);
VOID memory_copy(BYTE* target, BYTE* source, SIZE_T sz); //returns source + sz
VOID memory_zero(BYTE* target, SIZE_T sz);
BOOL memory_is_zero(BYTE* target, SIZE_T sz);

#if (defined(_RELEASE_TEST) || defined(_DEBUG))
	BOOL memory_dbg_is_all_freed();
	INT64 memory_dbg_get_malc_count();
#endif