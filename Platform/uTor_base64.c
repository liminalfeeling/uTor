#include "uTor_base64.h"

const UINT32 base64_decode(const BYTE* raw_data, const INT32 raw_data_sz, BYTE* decoded_data, const UINT32 max_unpacked_sz) {
	DWORD max_unpacked_sz_arg = max_unpacked_sz;
	if (!CryptStringToBinaryA(raw_data, raw_data_sz, CRYPT_STRING_BASE64_ANY, decoded_data, &max_unpacked_sz_arg, NULL, NULL))
		return 0;
	return max_unpacked_sz_arg;
}

CONST UINT32 base64_decode_armored(BYTE** row_context, const BYTE* start_bracket, const UINT32 start_bracket_sz, const BYTE* end_bracket, const UINT32 end_bracket_sz, BYTE* decoded_data, const UINT32 max_unpacked_sz) {
	static BYTE encoded_data[BASE64_ARMORED_MAX_DATA_SZ]; //TODO: Fix this, make it neat, maybe we need some kind of memory management shit?
	BYTE* row_data = nt_strtok_s(NULL, "\n", row_context);

	if (row_data == NULL)
		return 0;
	if (nt_strnicmp(row_data, start_bracket, start_bracket_sz) != 0)
		return 0;

	/*
	if (encoded_data == NULL)
		return 0;
	*/
	
	INT32 encoded_data_sz = 0;
	INT32 ret = FALSE;

	row_data = nt_strtok_s(NULL, "\n", row_context);
	while (row_data != NULL) {
		if (nt_strnicmp(row_data, end_bracket, end_bracket_sz) == 0) {
			ret = base64_decode(encoded_data, encoded_data_sz, decoded_data, max_unpacked_sz);
			break;
		}
		else {
			INT32 b64_data_row_sz = 0;
			for (b64_data_row_sz = 0; row_data[b64_data_row_sz] != '\0'; b64_data_row_sz++); //strlen

			if ((encoded_data_sz + b64_data_row_sz) >= BASE64_ARMORED_MAX_DATA_SZ)
				break;

			memory_copy(encoded_data + encoded_data_sz, row_data, b64_data_row_sz);
			encoded_data_sz += b64_data_row_sz;
		}
		row_data = nt_strtok_s(NULL, "\n", row_context);
	}

	return ret;
	//return (memory_free(encoded_data) ? ret : 0);
}
