#include "uTor_time.h"

#define WINDOWS_TICK 10000000ULL
#define SEC_TO_UNIX_EPOCH 11644473600LL

CONST UINT32 tor_time_convert_nt_to_posix(PLARGE_INTEGER time) {
	return (UINT32)((time->QuadPart / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH);
}

CONST UINT16 tor_time_calculate_period(INT32 time_posix, CONST UINT16 current_period_len) {
	time_posix /= 60;
	time_posix -= (12 * 60);
	time_posix /= current_period_len;
	return (UINT16)time_posix; //TODO: Make this a one liner.
}

BOOL tor_time_init() {
	const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return FALSE;

	nt_RtlTimeFieldsToTime = GetProcAddress(ntdll, "RtlTimeFieldsToTime"); //TODO: Find out if there is an alternative, perferably in kernel32.dll
	if (nt_RtlTimeFieldsToTime == NULL)
		return FALSE;

	return TRUE;
}