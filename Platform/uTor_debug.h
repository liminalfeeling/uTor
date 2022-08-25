#pragma once
//TODO: make cross platform.

#define DEBUG_VERBOSE_ON 1

#ifdef UTOR_DEBUG
#define _AMD64_
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <stdio.h>
#include <time.h>
#include <conio.h>
#include <FCNTL.H>
#include <io.h>

DWORD get_ticks(struct timeval* tv);

VOID debug_setcolor(BYTE colorID);
VOID debug_dispheader(const char* func, BYTE color);
VOID debug_prevline();

#if(DEBUG_VERBOSE_ON)
#define DEBUG_VERBOSE(X, ...) { debug_dispheader( __func__, 9); debug_setcolor(8); printf(X"\n", __VA_ARGS__);}
#else
#define DEBUG_VERBOSE(X, ...) {}
#endif
#define DEBUG_INFO(X, ...)  { debug_dispheader(__func__, 11); debug_setcolor(15); printf(X"\n", __VA_ARGS__);}
#define DEBUG_WARNING(X, ...)  { debug_dispheader(__func__, 14); debug_setcolor(15); printf(X"\n", __VA_ARGS__);}
#define DEBUG_ERROR(X, ...)  { debug_dispheader(__func__, 12); debug_setcolor(15); printf(X"\n", __VA_ARGS__);}
#define DEBUG_SUCCESS(X, ...) { debug_dispheader(__func__, 10); debug_setcolor(15); printf(X"\n", __VA_ARGS__);}
#define DEBUG_PREVLINE() debug_prevline()
#endif 

#ifndef UTOR_DEBUG
#include <Windows.h>
#include "string.h"
#include "uTor_string.h"

#if defined(_RELEASE_TEST)
char _INT_DBG_BUF[256];
#define DEBUG_OUT(X, ...) { nt_sprintf_s(_INT_DBG_BUF, sizeof(_INT_DBG_BUF), X, __VA_ARGS__); OutputDebugStringA(_INT_DBG_BUF);}

#define DEBUG_INIT() { DEBUG_OUT("RELEASE TEST EXECUTABLE RUNNING."); }
#define DEBUG_VERBOSE(X, ...) { DEBUG_OUT("[VRB]: " X "\n", __VA_ARGS__); }
#define DEBUG_INFO(X, ...)  { DEBUG_OUT("[INF]: " X "\n", __VA_ARGS__);}
#define DEBUG_WARNING(X, ...)  {DEBUG_OUT("[WRN]: " X "\n", __VA_ARGS__); }
#define DEBUG_ERROR(X, ...)  { DEBUG_OUT("[ERR]: " X "\n", __VA_ARGS__); }
#define DEBUG_SUCCESS(X, ...) { DEBUG_OUT("[SXS]: " X "\n", __VA_ARGS__); }
#define DEBUG_ASSERT(OP, X, ...) {}
#define DEBUG_PREVLINE() {}
#else
#define DEBUG_INIT() {}
#define DEBUG_VERBOSE(X, ...) {}
#define DEBUG_INFO(X, ...)  {}
#define DEBUG_WARNING(X, ...)  {}
#define DEBUG_ERROR(X, ...)  {}
#define DEBUG_SUCCESS(X, ...) {}
#define DEBUG_ASSERT(OP, X, ...) {}
#define DEBUG_PREVLINE() {}
#endif

#endif
