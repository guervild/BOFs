# CVE-2021-36934 - SeriousSam

Dirty C# implementation to exploit [CVE-2021-36934](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934) local privilege escalation.

The implemention use native api call to access and read shadow copy files. It creates a zip in memory (that contains SAM, SYSTEM and SECURITY files) and download it using BOF.NET's DownloadFile API.

## Usage
First, you must compile [BOF.NET](https://github.com/CCob/BOF.NET) from @CCob and load the bofnet.cna.

A bofnet.dll is added to the project but you can replace it with the one you compiled.

Once you compiled the SeriousSam project, you can execute as follows:
```
bofnet_init
bofnet_load /path/to/SeriousSam.exe
bofnet_execute SeriousSam.Execute <LIMIT>
```

LIMIT is optional and is set to 10 by default.

## References
This CVE has been disclosed by [@jonasLyk](https://twitter.com/jonasLyk).

Nim implementation [ShadowSteal](https://github.com/HuskyHacks/ShadowSteal)

C++ implementation [HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)