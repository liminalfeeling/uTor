#include "uTor_string.h"
#include <Windows.h>

BOOL string_init() {
	CONST HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return FALSE;

	nt_sprintf_s = GetProcAddress(ntdll, "sprintf_s");
	if (nt_sprintf_s == NULL)
		return FALSE;
	nt_strstr = GetProcAddress(ntdll, "strstr");
	if (nt_strstr == NULL)
		return FALSE;
	nt_strtok_s = GetProcAddress(ntdll, "strtok_s");
	if (nt_strtok_s == NULL)
		return FALSE;
	nt_strnicmp = GetProcAddress(ntdll, "_strnicmp");
	if (nt_strnicmp == NULL)
		return FALSE;
	nt_sscanf_s = GetProcAddress(ntdll, "sscanf_s");
	if (nt_sscanf_s == NULL)
		return FALSE;
	nt_memcmp = GetProcAddress(ntdll, "memcmp");
	if (nt_memcmp == NULL)
		return FALSE;

	return TRUE;
}
