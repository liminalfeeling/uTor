#include "uTor_net_parsing.h"

BOOL uTor_http_parse_func_exec(BYTE* data, PARSE_FUNC_TYPE parse_func, VOID* user_data) {
	CHAR* context_row = NULL;
	CHAR* curr_row = nt_strtok_s(data, "\n", &context_row);

	while (curr_row != NULL) {
		if (!parse_func(curr_row, user_data, &context_row)) {
			DEBUG_WARNING("Failed to parse resource.");
			return FALSE;
		}
		if (curr_row != NULL)
			curr_row = nt_strtok_s(NULL, "\n", &context_row);
	}

	return TRUE;
}
