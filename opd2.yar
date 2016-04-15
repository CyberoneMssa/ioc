
rule Operation_D2_malware01
{
    meta:
        description = "Operation Double Dragon Malware - tserver"
        author = "Steve Kim"
        date = "08-Apr-16"
        filetype = "EXE"
        hash = "949D226CDB3B7E1934B49372AD202C5B"

   strings:
        $s_1 = ".vmp0" wide ascii
        $s_2 = ".vmp1" wide ascii
        $s_3 = "ExitProcess" wide ascii
        $s_4 = "cracked by ximo" wide ascii
        $s_5 = "GetModuleFileName" wide ascii
        $s_6 = "KERNEL32.dll" wide ascii
        $s_7 = "GetModuleHandle" wide ascii
        $s_8 = "LoadLibrary" wide ascii
        $s_9 = "GetModuleFileName" wide ascii

    condition:
        all of them
}

rule Operation_D2_malware02
{
    meta:
        description = "Operation Double Dragon Malware - v3pscan"
        author = "Steve Kim"
        date = "08-Apr-16"
        filetype = "EXE"
        hash = "AFDE3CACF85E1794E5ADAD1C77CBF4AD"

   strings:
        $sa_1 = ".idata" wide ascii
        $sa_2 = "iyyklimt" wide ascii
        $sa_3 = "dhsgwzat" wide ascii
        $sa_4 = "lstrcp" wide ascii
        $sa_5 = "InitCommonControls" wide ascii
        $sa_6 = "kernel32.dll" wide ascii
        $sa_7 = "comctl32.dll" wide ascii

    condition:
        all of them
}

rule Operation_D2_malware03
{
    meta:
        description = "Operation Double Dragon Malware - ChangeTime"
        author = "Steve Kim"
        date = "08-Apr-16"
        filetype = "EXE"
        hash = "D7869AABE9055995C2F16614E7D5AC6B"

   strings:
        $s_1 = "PDBOpenValidate5" wide ascii
        $s_2 = "SystemFunction036" wide ascii
        $s_3 = "GetProcessWindowStation" wide ascii
        $s_4 = "GetUserObjectInformation" wide ascii
        $s_5 = "GetLastActivePopup" wide ascii
        $s_6 = "SetFileTime" wide ascii
        $s_7 = "GetCommandLine" wide ascii
        $s_8 = "HeapSetInformation" wide ascii
        $s_9 = "RaiseException" wide ascii
        $s_10 = "IsDebuggerPresent" wide ascii
        $s_11 = "SetUnhandledExceptionFilter" wide ascii
        $s_12 = "GetModuleHandle" wide ascii
        $s_13 = "DecodePointer" wide ascii
        $s_14 = "FreeEnvironmentStrings" wide ascii
        $s_15 = "GetEnvironmentStrings" wide ascii
        $s_16 = "GetFileType" wide ascii
        $s_17 = "GetStartupInfo" wide ascii
        $s_18 = "EncodePointer" wide ascii
        $s_19 = "QueryPerformanceCounter" wide ascii
        $s_20 = "GetTickCount" wide ascii
        $s_21 = "GetCurrentProcessId" wide ascii
        $s_22 = "GetProcessHeap" wide ascii
        $s_23 = "FatalAppExit" wide ascii
        $s_24 = "SetConsoleCtrlHandler" wide ascii
        $s_25 = "UnhandledExceptionFilter" wide ascii
        $s_26 = "GetOEMCP" wide ascii
        $s_27 = "IsProcessorFeaturePresent" wide ascii

    condition:
        all of them
}
