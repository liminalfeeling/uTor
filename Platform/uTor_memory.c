#include "uTor_memory.h"

#if (defined(_RELEASE_TEST) || defined(_DEBUG))
	INT64 malc_count = 0;

	BOOL memory_dbg_is_all_freed() {
		return (malc_count == 0);
	}

	INT64 memory_dbg_get_malc_count() {
		return malc_count;
	}
#endif

BYTE* memory_alloc(SIZE_T sz) {
#if (defined(_RELEASE_TEST) || defined(_DEBUG))
	malc_count++;
#endif
	DEBUG_VERBOSE("Allocating memory of size %zu", sz);
	BYTE* memory_new = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
	DEBUG_VERBOSE("-> %p", memory_new);
	return memory_new;
}

BOOL memory_free(BYTE* mem_addr) {
	if (mem_addr == NULL)
		return TRUE;

#if (defined(_RELEASE_TEST) || defined(_DEBUG))
	malc_count--;
	if (malc_count < 0)
		return FALSE;
#endif
	DEBUG_VERBOSE("Freed memory at %p", mem_addr);
	return HeapFree(GetProcessHeap(), 0, mem_addr);
}

VOID memory_copy(BYTE* target, BYTE* source, SIZE_T sz) {
	for (SIZE_T I = 0; I != sz; I++)
		target[I] = source[I];
	return (source + sz);
}

VOID memory_zero(BYTE* target, SIZE_T sz) {
	RtlSecureZeroMemory(target, sz);
}

BOOL memory_is_zero(BYTE* target, SIZE_T sz) {
	for (SIZE_T X = 0; X != sz; X++) {
		if (target[X] != 0)
			return FALSE;
	}
}
