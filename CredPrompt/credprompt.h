#pragma once
#include <windows.h>
#include <wincred.h>
#include "beacon.h"

#define SECURITY_WIN32
#include <security.h>

//KERNEL32
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

//MSVCRT
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscat(wchar_t * __restrict__ _Dest,const wchar_t * __restrict__ _Source);

//SECUR32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExW(int NameFormat, LPWSTR lpNameBuffer, PULONG nSize);

//CREDUI
DECLSPEC_IMPORT DWORD WINAPI CREDUI$CredUIPromptForWindowsCredentialsW(
  PCREDUI_INFOW pUiInfo,
  DWORD         dwAuthError,
  ULONG         *pulAuthPackage,
  LPCVOID       pvInAuthBuffer,
  ULONG         ulInAuthBufferSize,
  LPVOID        *ppvOutAuthBuffer,
  ULONG         *pulOutAuthBufferSize,
  BOOL          *pfSave,
  DWORD         dwFlags
);


DECLSPEC_IMPORT BOOLEAN WINAPI CREDUI$CredUnPackAuthenticationBufferW(
  DWORD  dwFlags,
  PVOID  pAuthBuffer,
  DWORD  cbAuthBuffer,
  LPWSTR pszUserName,
  DWORD  *pcchMaxUserName,
  LPWSTR pszDomainName,
  DWORD  *pcchMaxDomainName,
  LPWSTR pszPassword,
  DWORD  *pcchMaxPassword
);