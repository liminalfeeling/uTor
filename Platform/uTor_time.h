#pragma once
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>

#define TOR_TIME_PERIOD_LENGTH_DEFAULT 1440 /* 1440 minutes == one day */
#define TOR_TIME_PERIOD_LENGTH_MIN 30 /* The minimum time period length (in minutes) as seen in prop224 section [TIME-PERIODS] */
#define TOR_TIME_PERIOD_LENGTH_MAX (60 * 24 * 10) /* 10 days or 14400 minutes */ /* The maximum time period length (in minutes) as seen in prop224 section [TIME-PERIODS] */

typedef struct {
	USHORT Year;
	USHORT Month;
	USHORT Day;
	USHORT Hour;
	USHORT Minute;
	USHORT Second;
	USHORT Milliseconds;
	USHORT Weekday;
} TIME_FIELDS, *PTIME_FIELDS;

//TODO: remove the need for this call, make everything in here cross platform.
BOOL(NTAPI* nt_RtlTimeFieldsToTime)(IN PTIME_FIELDS TimeFields, OUT PLARGE_INTEGER Time);

//TODO: Move this to the tor Project.
CONST UINT32 tor_time_convert_nt_to_posix(PLARGE_INTEGER time); //Converts windows filetime to posix time.
CONST UINT16 tor_time_calculate_period(INT32 time_posix, CONST UINT16 current_period_len); //calculates the time period.
BOOL tor_time_init();