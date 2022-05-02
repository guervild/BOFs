#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <wchar.h>

#include "beacon.h"

#define STATUS_SUCCESS 0

// KERNEL32
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI void *WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI int WINAPI KERNEL32$GetDateFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
WINBASEAPI int WINAPI KERNEL32$GetTimeFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME *lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime);

// MSVCRT
WINBASEAPI int MSVCRT$_wcsicmp(const wchar_t *string1, const wchar_t *string2);

// Utils
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef CONST UNICODE_STRING *PCUNICODE_STRING;

// Vault
typedef enum _VAULT_ELEMENT_TYPE
{
	ElementType_Boolean = 0,
	ElementType_Short = 1,
	ElementType_UnsignedShort = 2,
	ElementType_Integer = 3,
	ElementType_UnsignedInteger = 4,
	ElementType_Double = 5,
	ElementType_Guid = 6,
	ElementType_String = 7,
	ElementType_ByteArray = 8,
	ElementType_TimeStamp = 9,
	ElementType_ProtectedArray = 0xA,
	ElementType_Attribute = 0xB,
	ElementType_Sid = 0xC,
	ElementType_Last = 0xD,
	ElementType_Undefined = 0xFFFFFFFF
} VAULT_ELEMENT_TYPE,
	*PVAULT_ELEMENT_TYPE;

typedef struct _VAULT_BYTE_BUFFER
{
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, *PVAULT_BYTE_BUFFER;

typedef struct _VAULT_CREDENTIAL_ATTRIBUTEW
{
	LPWSTR Keyword;
	DWORD Flags;
	DWORD ValueSize;
	LPBYTE Value;
} VAULT_CREDENTIAL_ATTRIBUTEW, *PVAULT_CREDENTIAL_ATTRIBUTEW;

typedef struct _VAULT_ITEM_DATA
{
	DWORD SchemaElementId;
	DWORD unk0;
	VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union
	{
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		PVAULT_CREDENTIAL_ATTRIBUTEW Attribute;
		PSID Sid;
	} data;
} VAULT_ITEM_DATA, *PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_8
{
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_8, *PVAULT_ITEM_8;

typedef struct _VAULT_ITEM_7
{
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Resource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_7, *PVAULT_ITEM_7;

typedef NTSTATUS(WINAPI *_RtlStringFromGUID)(REFGUID Guid, PUNICODE_STRING GuidString);
typedef VOID(WINAPI *_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);

typedef DWORD(WINAPI *_VaultEnumerateVaults)(DWORD flags, PDWORD count, GUID **guids);
typedef DWORD(WINAPI *_VaultEnumerateItems)(HANDLE handle, DWORD flags, PDWORD count, PVOID *items);
typedef DWORD(WINAPI *_VaultOpenVault)(GUID *id, DWORD flags, HANDLE *handle);
typedef DWORD(WINAPI *_VaultCloseVault)(HANDLE vault);
typedef DWORD(WINAPI *_VaultFree)(PVOID memory);
typedef NTSTATUS(WINAPI *_VaultGetItem7)(HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, HWND hWnd, DWORD Flags, PVAULT_ITEM_7 *pItem);
typedef NTSTATUS(WINAPI *_VaultGetItem8)(HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM_8 *pItem);