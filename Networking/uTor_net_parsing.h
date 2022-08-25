#pragma once
#include "../Platform/uTor_string.h"
#include "../Platform/uTor_debug.h"

typedef BOOL(*PARSE_FUNC_TYPE)(CHAR* curr_line, VOID* parse_data, CHAR** line_context);

BOOL uTor_http_parse_func_exec(BYTE* data, PARSE_FUNC_TYPE parse_func, VOID* user_data);