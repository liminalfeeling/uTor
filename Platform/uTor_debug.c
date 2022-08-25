#define _CRT_SECURE_NO_WARNINGS
#include "uTor_debug.h"


#ifdef _DEBUG
LARGE_INTEGER getFILETIMEoffset() {
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;
    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

DWORD get_ticks(struct timeval* tv) {
    LARGE_INTEGER           t;
    FILETIME            f;
    static LARGE_INTEGER offset;
    static double frequencyToMicroseconds;
    static int initialized = 0;
    static BOOL usePerformanceCounter = 0;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
        }
        else {
            offset = getFILETIMEoffset();
            frequencyToMicroseconds = 10.;
        }
    }
    if (usePerformanceCounter) QueryPerformanceCounter(&t);
    else {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    t.QuadPart = ((long double)t.QuadPart / frequencyToMicroseconds);
    tv->tv_sec = t.QuadPart / (LONGLONG)1000000;
    tv->tv_usec = t.QuadPart % 1000000;
    return (0);
}

VOID debug_setcolor(BYTE colorID) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, colorID);
}

VOID debug_dispheader(const char* func, BYTE color) {
    struct timeval t;
    get_ticks(&t);
    debug_setcolor(9);
    printf("[ ");
    debug_setcolor(3);
    printf("%.3f", t.tv_sec + (long double)(t.tv_usec / 1000000.0));
    debug_setcolor(9);
    printf(" ] ");
    debug_setcolor(color);
    printf("%s(): ", func);
}

VOID debug_prevline() {
    HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };

    GetConsoleScreenBufferInfo(hConsoleOutput, &csbi);
    csbi.dwCursorPosition.Y -= 1;

    SetConsoleCursorPosition(hConsoleOutput, csbi.dwCursorPosition);
}
#endif