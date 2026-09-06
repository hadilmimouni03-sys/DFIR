
/* ====================================================================
   EXECUTION AND OBFUSCATION
   ==================================================================== */

rule MDY_Encoded_PowerShell
{
    meta:
        severity = "high"
        score    = 50
        attack   = "T1059.001,T1027"
        description = "PowerShell decoding or downloading in memory. -enc takes base64, and there is no benign reason to hide a command from the person reading the log."

    strings:
        $enc1 = "FromBase64String"    nocase wide ascii
        $enc2 = "-EncodedCommand"     nocase wide ascii
        $enc3 = " -enc "              nocase wide ascii
        $enc4 = "[System.Convert]::"  nocase wide ascii
        $dl1  = "DownloadString"      nocase wide ascii
        $dl2  = "DownloadFile"        nocase wide ascii
        $dl3  = "Net.WebClient"       nocase wide ascii
        $dl4  = "Invoke-WebRequest"   nocase wide ascii
        $ex1  = "Invoke-Expression"   nocase wide ascii
        $ex2  = "IEX("                nocase wide ascii
        $hide = "-WindowStyle Hidden" nocase wide ascii
        $byp  = "-ExecutionPolicy Bypass" nocase wide ascii

    condition:
        2 of them
}


rule MDY_AMSI_Or_ETW_Bypass
{
    meta:
        severity = "critical"
        score    = 80
        attack   = "T1562.001"
        description = "Patching the Antimalware Scan Interface or Event Tracing for Windows. No legitimate reason exists for a process to disable the host's own security instrumentation."

    strings:
        $a1 = "AmsiScanBuffer"        nocase wide ascii
        $a2 = "amsiInitFailed"        nocase wide ascii
        $a3 = "AmsiUtils"             nocase wide ascii
        $e1 = "EtwEventWrite"         nocase wide ascii
        $e2 = "EtwNotificationRegister" nocase wide ascii
        $p1 = "VirtualProtect"        nocase wide ascii
        $p2 = "WriteProcessMemory"    nocase wide ascii

    condition:
        (1 of ($a*) or 1 of ($e*)) and 1 of ($p*)
}


rule MDY_DotNet_Assembly_Load_In_Memory
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1620"
        description = "Loading a .NET assembly straight from memory, the execute-assembly technique. Nothing is written to disk, so no file artifact exists."

    strings:
        $a1 = "System.Reflection.Assembly" nocase wide ascii
        $a2 = "[Reflection.Assembly]::Load" nocase wide ascii
        $a3 = "Assembly.Load("        nocase wide ascii
        $a4 = "GetDelegateForFunctionPointer" nocase wide ascii
        $a5 = "DynamicInvoke"         nocase wide ascii

    condition:
        2 of them
}


rule MDY_Script_Obfuscation
{
    meta:
        severity = "medium"
        score    = 40
        attack   = "T1027"
        description = "String-reversal, char-code assembly and format-operator tricks used to hide commands from log review."

    strings:
        $o1 = "-join[char[]]"         nocase wide ascii
        $o2 = "[char]0x"              nocase wide ascii
        $o3 = "::Reverse("            nocase wide ascii
        $o4 = "[System.Text.Encoding]::Unicode.GetString" nocase wide ascii
        $o5 = "SecureStringToBSTR"    nocase wide ascii

    condition:
        2 of them
}


/* ====================================================================
   INJECTION AND EVASION
   ==================================================================== */

rule MDY_Reflective_PE_In_Memory
{
    meta:
        severity = "critical"
        score    = 70
        attack   = "T1055.002"
        description = "A complete PE mapped into memory. Pairs with malfind: malfind finds the executable private region, this confirms a whole executable was written there rather than shellcode."

    strings:
        $dos_stub = "This program cannot be run in DOS mode"
        $pe_sig   = { 50 45 00 00 }

    condition:
        uint16(0) == 0x5A4D and $pe_sig and $dos_stub
}


rule MDY_Process_Injection_API_Set
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1055"
        description = "The API sequence used to inject into another process. Individually ordinary Windows calls; three together in one region is the injection recipe."

    strings:
        $a1 = "OpenProcess"           ascii wide
        $a2 = "VirtualAllocEx"        ascii wide
        $a3 = "WriteProcessMemory"    ascii wide
        $a4 = "CreateRemoteThread"    ascii wide
        $a5 = "NtUnmapViewOfSection"  ascii wide
        $a6 = "SetThreadContext"      ascii wide
        $a7 = "QueueUserAPC"          ascii wide
        $a8 = "NtWriteVirtualMemory"  ascii wide

    condition:
        3 of them
}


rule MDY_Reflective_Loader_Marker
{
    meta:
        severity = "critical"
        score    = 75
        attack   = "T1055.001,T1620"
        description = "The reflective DLL loading pattern used by most post-exploitation frameworks to load a payload without LoadLibrary."

    strings:
        $r1 = "ReflectiveLoader"      ascii wide
        $r2 = "_ReflectiveLoader@4"   ascii wide
        $r3 = "ReflectiveDll"         ascii wide nocase

    condition:
        any of them
}


rule MDY_Named_Pipe_C2_Pattern
{
    meta:
        severity = "high"
        score    = 65
        attack   = "T1071,T1090"
        description = "Named pipes used for beacon-to-beacon relay by post-exploitation frameworks. Legitimate software uses named pipes too, so a generic pipe path must be paired with an impersonation call."

    strings:
        $p1 = "\\\\.\\pipe\\"         ascii wide
        $p2 = "\\\\.\\pipe\\msagent_" ascii wide nocase
        $p3 = "\\\\.\\pipe\\postex_"  ascii wide nocase
        $p4 = "\\\\.\\pipe\\status_"  ascii wide nocase
        $i1 = "ImpersonateNamedPipeClient" ascii wide
        $i2 = "CreateNamedPipeA"      ascii wide

    condition:
        (1 of ($p2, $p3, $p4)) or ($p1 and 1 of ($i*))
}


/* ====================================================================
   CREDENTIAL ACCESS
   ==================================================================== */

rule MDY_Credential_Dumping_Tooling
{
    meta:
        severity = "critical"
        score    = 85
        attack   = "T1003.001"
        description = "Strings characteristic of credential-dumping tools resident in memory. Distinctive enough that a single match is meaningful."

    strings:
        $a = "sekurlsa::logonpasswords" nocase wide ascii
        $b = "privilege::debug"        nocase wide ascii
        $c = "lsadump::sam"            nocase wide ascii
        $d = "lsadump::dcsync"         nocase wide ascii
        $e = "gentilkiwi"              nocase wide ascii
        $f = "mimikatz"                nocase wide ascii
        $g = "kerberos::golden"        nocase wide ascii

    condition:
        any of them
}


rule MDY_LSASS_Access_Pattern
{
    meta:
        severity = "critical"
        score    = 80
        attack   = "T1003.001"
        description = "Reading LSASS memory or writing a process dump of it. comsvcs.dll MiniDump is the living-off-the-land variant that needs no external tool."

    strings:
        $l1 = "lsass.exe"             nocase wide ascii
        $d1 = "MiniDumpWriteDump"     ascii wide
        $d2 = "comsvcs.dll, MiniDump" nocase wide ascii
        $d3 = "comsvcs.dll MiniDump"  nocase wide ascii
        $d4 = "procdump"              nocase wide ascii
        $d5 = "-ma lsass"             nocase wide ascii

    condition:
        ($l1 and 1 of ($d*)) or $d2 or $d3
}


rule MDY_Credential_File_Targets
{
    meta:
        severity = "high"
        score    = 65
        attack   = "T1003.002,T1003.003,T1552.001"
        description = "Paths to credential stores held in memory: the SAM and SECURITY hives, the Active Directory database, and unattended-install answer files that often contain plaintext passwords."

    strings:
        $a = "ntds.dit"               nocase wide ascii
        $b = "\\config\\SAM"          nocase wide ascii
        $c = "\\config\\SECURITY"     nocase wide ascii
        $d = "unattend.xml"           nocase wide ascii
        $e = "sysprep.inf"            nocase wide ascii
        $f = "vaultcmd"               nocase wide ascii
        $g = "\\.ssh\\id_rsa"         nocase wide ascii
        $h = "/etc/shadow"            nocase wide ascii

    condition:
        any of them
}


/* ====================================================================
   PERSISTENCE
   ==================================================================== */

rule MDY_Persistence_Commands
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1547.001,T1053.005,T1543.003"
        description = "Persistence being established from a command line held in memory. Requires the mechanism AND a suspicious target path, since administrators run these legitimately."

    strings:
        $m1 = "schtasks /create"      nocase wide ascii
        $m2 = "schtasks.exe /create"  nocase wide ascii
        $m3 = "sc create"             nocase wide ascii
        $m4 = "sc.exe create"         nocase wide ascii
        $m5 = "reg add"               nocase wide ascii
        $m6 = "New-ScheduledTask"     nocase wide ascii

        $t1 = "CurrentVersion\\Run"   nocase wide ascii
        $t2 = "\\AppData\\"           nocase wide ascii
        $t3 = "\\Temp\\"              nocase wide ascii
        $t4 = "\\ProgramData\\"       nocase wide ascii
        $t5 = "\\Users\\Public\\"     nocase wide ascii

    condition:
        1 of ($m*) and 1 of ($t*)
}


rule MDY_WMI_Event_Subscription
{
    meta:
        severity = "critical"
        score    = 75
        attack   = "T1546.003"
        description = "WMI permanent event subscription: fileless persistence that survives reboots and leaves no file on disk."

    strings:
        $a = "__EventFilter"          nocase wide ascii
        $b = "CommandLineEventConsumer" nocase wide ascii
        $c = "ActiveScriptEventConsumer" nocase wide ascii
        $d = "__FilterToConsumerBinding" nocase wide ascii
        $e = "root\\subscription"     nocase wide ascii

    condition:
        2 of them
}


/* ====================================================================
   COMMAND AND CONTROL
   ==================================================================== */

rule MDY_Reverse_Shell_Indicators
{
    meta:
        severity = "critical"
        score    = 75
        attack   = "T1059.004,T1071.001"
        description = "Interactive shell patterns held in memory."

    strings:
        $n1 = "nc -e /bin/sh"         nocase wide ascii
        $n2 = "ncat -e"               nocase wide ascii
        $n3 = "/dev/tcp/"             nocase wide ascii
        $p1 = "System.Net.Sockets.TCPClient" nocase wide ascii
        $p2 = "cmd.exe /c powershell" nocase wide ascii
        $s1 = "bash -i >&"            nocase wide ascii
        $s2 = "sh -i >&"              nocase wide ascii

    condition:
        any of them
}


rule MDY_LOLBin_With_Remote_Payload
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1218.011,T1218.010,T1105"
        description = "A signed Microsoft binary pointed at a remote resource. The binary is never the signal; the argument is."

    strings:
        $b1 = "rundll32"   nocase wide ascii
        $b2 = "regsvr32"   nocase wide ascii
        $b3 = "mshta"      nocase wide ascii
        $b4 = "certutil"   nocase wide ascii
        $b5 = "bitsadmin"  nocase wide ascii

        $u1 = "http://"    nocase wide ascii
        $u2 = "https://"   nocase wide ascii
        $u3 = "scrobj.dll" nocase wide ascii
        $u4 = "-urlcache"  nocase wide ascii
        $u5 = "javascript:" nocase wide ascii

    condition:
        1 of ($b*) and 1 of ($u*)
}


rule MDY_Tunneling_Or_Proxy_Tooling
{
    meta:
        severity = "high"
        score    = 65
        attack   = "T1572,T1090"
        description = "Tunnelling utilities used to reach internal services from outside. Legitimate in some environments; verify against the asset's expected role."

    strings:
        $a = "chisel"                 nocase wide ascii
        $b = "ngrok"                  nocase wide ascii
        $c = "plink.exe -R"           nocase wide ascii
        $d = "netsh interface portproxy" nocase wide ascii
        $e = "socat TCP-LISTEN"       nocase wide ascii
        $f = "frpc.ini"               nocase wide ascii

    condition:
        any of them
}


/* ====================================================================
   DISCOVERY AND LATERAL MOVEMENT
   ==================================================================== */

rule MDY_Discovery_Commands
{
    meta:
        severity = "medium"
        score    = 35
        attack   = "T1087.002,T1482,T1018"
        description = "Domain reconnaissance run from one process. Individually ordinary; three together in one memory region is the enumeration phase of an intrusion. Scored medium, administrators run these too."

    strings:
        $a = "net group \"domain admins\"" nocase wide ascii
        $b = "net localgroup administrators" nocase wide ascii
        $c = "nltest /domain_trusts"  nocase wide ascii
        $d = "Get-ADComputer"         nocase wide ascii
        $e = "Get-DomainUser"         nocase wide ascii
        $f = "adfind.exe"             nocase wide ascii
        $g = "whoami /all"            nocase wide ascii

    condition:
        3 of them
}


rule MDY_Lateral_Movement_Tooling
{
    meta:
        severity = "high"
        score    = 65
        attack   = "T1021.002,T1021.006,T1569.002"
        description = "Remote execution against another host. Legitimate for administration, so the finding is WHICH process holds it and whether that fits the asset's role."

    strings:
        $a = "psexec"                 nocase wide ascii
        $b = "paexec"                 nocase wide ascii
        $c = "wmic /node:"            nocase wide ascii
        $d = "Invoke-WmiMethod"       nocase wide ascii
        $e = "Enter-PSSession"        nocase wide ascii
        $f = "Invoke-Command -ComputerName" nocase wide ascii
        $g = "\\\\ADMIN$"             nocase wide ascii

    condition:
        2 of them
}


/* ====================================================================
   IMPACT AND ANTI-FORENSICS
   ==================================================================== */

rule MDY_Shadow_Copy_Or_Recovery_Destruction
{
    meta:
        severity = "critical"
        score    = 90
        attack   = "T1490"
        description = "Deleting shadow copies or disabling Windows recovery. The ransomware pre-encryption step, with essentially no benign use on an endpoint. The highest-confidence rule in this file."

    strings:
        $a = "vssadmin delete shadows" nocase wide ascii
        $b = "vssadmin.exe delete shadows" nocase wide ascii
        $c = "Win32_ShadowCopy"       nocase wide ascii
        $d = "recoveryenabled no"     nocase wide ascii
        $e = "bootstatuspolicy ignoreallfailures" nocase wide ascii
        $f = "wbadmin delete catalog" nocase wide ascii
        $g = "wmic shadowcopy delete" nocase wide ascii

    condition:
        any of them
}


rule MDY_Log_Clearing
{
    meta:
        severity = "critical"
        score    = 80
        attack   = "T1070.001,T1070.003"
        description = "Clearing event logs or shell history. Not an error condition, an action someone chose to take."

    strings:
        $a = "wevtutil cl"            nocase wide ascii
        $b = "wevtutil.exe cl"        nocase wide ascii
        $c = "Clear-EventLog"         nocase wide ascii
        $d = "Remove-EventLog"        nocase wide ascii
        $e = "history -c"             nocase wide ascii
        $f = "unset HISTFILE"         nocase wide ascii

    condition:
        any of them
}


rule MDY_Defender_Tampering
{
    meta:
        severity = "critical"
        score    = 85
        attack   = "T1562.001"
        description = "Disabling Microsoft Defender or adding a broad exclusion. An exclusion for an entire drive is not a configuration choice."

    strings:
        $a = "DisableRealtimeMonitoring" nocase wide ascii
        $b = "Add-MpPreference -ExclusionPath" nocase wide ascii
        $c = "DisableAntiSpyware"     nocase wide ascii
        $d = "DisableBehaviorMonitoring" nocase wide ascii
        $e = "sc stop WinDefend"      nocase wide ascii
        $f = "MpCmdRun.exe -RemoveDefinitions" nocase wide ascii

    condition:
        any of them
}


rule MDY_Exfil_Staging_Archive
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1560.001"
        description = "Building a password-protected or split archive. Legitimate for backups; suspicious when it targets a user profile or a staging directory."

    strings:
        $c1 = "rar.exe a -"           nocase wide ascii
        $c2 = "7z.exe a -p"           nocase wide ascii
        $c3 = "7za a -p"              nocase wide ascii
        $c4 = "Compress-Archive"      nocase wide ascii

        $t1 = "\\Users\\"             nocase wide ascii
        $t2 = "\\Documents\\"         nocase wide ascii
        $t3 = "\\Temp\\"              nocase wide ascii
        $t4 = "\\ProgramData\\"       nocase wide ascii

    condition:
        1 of ($c*) and 1 of ($t*)
}


/* ====================================================================
   CONTEXT -- low scored, strengthens other findings
   ==================================================================== */

rule MDY_Staging_Path_Execution
{
    meta:
        severity = "medium"
        score    = 30
        attack   = "T1204.002"
        description = "Execution paths under Temp, ProgramData or public directories. Scored low: context that strengthens other findings, not an alert on its own. Expect it to fire on installers."

    strings:
        $p1 = "\\AppData\\Local\\Temp\\" nocase wide ascii
        $p2 = "\\Windows\\Temp\\"     nocase wide ascii
        $p3 = "\\ProgramData\\"       nocase wide ascii
        $p4 = "\\Users\\Public\\"     nocase wide ascii
        $p5 = "\\PerfLogs\\"          nocase wide ascii

        $x1 = ".exe" nocase wide ascii
        $x2 = ".dll" nocase wide ascii
        $x3 = ".ps1" nocase wide ascii
        $x4 = ".bat" nocase wide ascii
        $x5 = ".scr" nocase wide ascii

    condition:
        1 of ($p*) and 1 of ($x*)
}


rule MDY_Admin_Tool_Usage
{
    meta:
        severity = "low"
        score    = 20
        attack   = "T1588.002"
        description = "Dual-use administration and security tooling. Entirely normal on an analyst or admin workstation, which is why it is scored low. Useful as corroboration on a machine where it does NOT belong."

    strings:
        $a = "PsExec"    nocase wide ascii
        $b = "procdump"  nocase wide ascii
        $c = "nmap"      nocase wide ascii
        $d = "netcat"    nocase wide ascii
        $e = "Wireshark" nocase wide ascii

    condition:
        2 of them
}


/* ====================================================================
   LINUX
   ==================================================================== */

rule MDY_Linux_Persistence_In_Memory
{
    meta:
        severity = "high"
        score    = 60
        attack   = "T1543.002,T1546.004,T1574.006"
        description = "Linux persistence paths in process memory. Use with linux.vmayarascan.VmaYaraScan."

    strings:
        $a = "/etc/ld.so.preload"     wide ascii
        $b = "/etc/cron.d/"           wide ascii
        $c = "authorized_keys"        wide ascii
        $d = "/etc/systemd/system/"   wide ascii
        $e = "LD_PRELOAD"             wide ascii
        $f = "/etc/rc.local"          wide ascii

    condition:
        2 of them
}


rule MDY_Linux_Anti_Forensics
{
    meta:
        severity = "critical"
        score    = 75
        attack   = "T1070.004,T1222.002"
        description = "Log deletion, timestamp manipulation and immutable-flag removal on Linux."

    strings:
        $a = "chattr -i"              wide ascii
        $b = "shred -u"               wide ascii
        $c = "> /var/log/"            wide ascii
        $d = "touch -r"               wide ascii
        $e = "touch -t"               wide ascii
        $f = "/var/log/wtmp"          wide ascii
        $g = "utmpdump"               wide ascii

    condition:
        2 of them
}
