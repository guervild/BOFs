#pragma once

#include <windows.h>
#include <wincred.h>
#include "beacon.h"

// KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI void *WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$GetDateFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
WINBASEAPI int WINAPI KERNEL32$GetTimeFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME *lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime);

// MSVCRT
WINBASEAPI size_t MSVCRT$wcslen(const wchar_t *str);

// ADVAPI32
WINBASEAPI BOOL WINAPI ADVAPI32$CredEnumerateW(LPCWSTR Filter, DWORD Flags, DWORD *Count, PCREDENTIALW **Credential);
WINBASEAPI VOID WINAPI ADVAPI32$CredFree(PVOID Buffer);