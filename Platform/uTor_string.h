#pragma once
#define _AMD64_
#include <windef.h>

INT32(*nt_sprintf_s)(CHAR* buffer, SIZE_T sizeOfBuffer, CONST CHAR* format, ...);
CHAR*(*nt_strstr)(CHAR* str, CONST CHAR* strSearch);
CHAR*(*nt_strtok_s)(CHAR* str, CONST CHAR* delimiters, CHAR** context);
INT32(*nt_strnicmp)(CONST CHAR* string1, CONST CHAR* string2, SIZE_T count);
INT32(*nt_memcmp)(BYTE* a, BYTE* B, size_t count);
INT32(*nt_sscanf_s)(CONST CHAR* buffer, CONST CHAR* format, ...);

BOOL string_init();