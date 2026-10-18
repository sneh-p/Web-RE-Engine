// Suspicious capabilities inferred from API names and strings.
// These are heuristics: legitimate software (debuggers, installers, AV) can match too.

rule Capability_Process_Injection
{
    meta:
        description = "Imports the classic remote-thread process injection API trio"
        severity = "high"
        category = "injection"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $b1 = "NtCreateThreadEx" ascii wide
        $b2 = "QueueUserAPC" ascii wide
        $b3 = "SetThreadContext" ascii wide
    condition:
        ($a1 and $a2 and ($a3 or $b1 or $b2 or $b3))
}

rule Capability_Process_Hollowing
{
    meta:
        description = "Unmaps and rewrites a suspended process image (process hollowing)"
        severity = "high"
        category = "injection"
    strings:
        $s1 = "NtUnmapViewOfSection" ascii wide
        $s2 = "ZwUnmapViewOfSection" ascii wide
        $s3 = "SetThreadContext" ascii wide
        $s4 = "ResumeThread" ascii wide
        $s5 = "WriteProcessMemory" ascii wide
    condition:
        ($s1 or $s2) and $s3 and $s4 and $s5
}

rule Capability_Keylogging
{
    meta:
        description = "Keyboard hooking or polling APIs commonly used by keyloggers"
        severity = "high"
        category = "collection"
    strings:
        $hook = "SetWindowsHookEx" ascii wide
        $k1 = "GetAsyncKeyState" ascii wide
        $k2 = "GetKeyboardState" ascii wide
        $k3 = "GetForegroundWindow" ascii wide
        $k4 = "WH_KEYBOARD_LL" ascii wide
    condition:
        ($hook and ($k1 or $k2 or $k4)) or ($k1 and $k3 and $k2)
}

rule Capability_Screen_Capture
{
    meta:
        description = "Captures the screen via GDI BitBlt from the desktop window"
        severity = "medium"
        category = "collection"
    strings:
        $s1 = "BitBlt" ascii wide
        $s2 = "GetDesktopWindow" ascii wide
        $s3 = "CreateCompatibleBitmap" ascii wide
        $s4 = "GetDC" ascii wide
    condition:
        all of them
}

rule Capability_Persistence_Run_Key
{
    meta:
        description = "References a Windows Run/RunOnce autostart registry key"
        severity = "medium"
        category = "persistence"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase ascii wide
        $s3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase ascii wide
    condition:
        any of them
}

rule Capability_Persistence_Scheduled_Task
{
    meta:
        description = "Creates a scheduled task from the command line"
        severity = "medium"
        category = "persistence"
    strings:
        $s1 = "schtasks" nocase ascii wide
        $s2 = "/create" nocase ascii wide
    condition:
        $s1 and $s2
}

rule Capability_Anti_Debug
{
    meta:
        description = "Several debugger-detection APIs"
        severity = "medium"
        category = "anti-analysis"
    strings:
        $s1 = "IsDebuggerPresent" ascii wide
        $s2 = "CheckRemoteDebuggerPresent" ascii wide
        $s3 = "NtQueryInformationProcess" ascii wide
        $s4 = "OutputDebugString" ascii wide
        $s5 = "NtSetInformationThread" ascii wide
    condition:
        3 of them
}

rule Capability_Anti_VM
{
    meta:
        description = "Strings used to detect virtual machines or sandboxes"
        severity = "medium"
        category = "anti-analysis"
    strings:
        $s1 = "VBoxService" nocase ascii wide
        $s2 = "VBoxTray" nocase ascii wide
        $s3 = "vmtoolsd" nocase ascii wide
        $s4 = "VMware" nocase ascii wide
        $s5 = "SbieDll.dll" nocase ascii wide
        $s6 = "qemu-ga" nocase ascii wide
        $s7 = "wine_get_unix_file_name" ascii wide
    condition:
        3 of them
}

rule Capability_Credential_Theft_Browsers
{
    meta:
        description = "References browser credential/cookie stores"
        severity = "high"
        category = "credential-access"
    strings:
        $c1 = "Login Data" ascii wide
        $c2 = "logins.json" ascii wide
        $c3 = "key4.db" ascii wide
        $c4 = "Local State" ascii wide
        $c5 = "Cookies" ascii wide
        $c6 = "encrypted_key" ascii wide
        $c7 = "CryptUnprotectData" ascii wide
    condition:
        3 of them
}

rule Capability_Crypto_Wallet_Theft
{
    meta:
        description = "References cryptocurrency wallet files or extensions"
        severity = "high"
        category = "credential-access"
    strings:
        $w1 = "wallet.dat" nocase ascii wide
        $w2 = "Exodus" ascii wide
        $w3 = "Electrum" ascii wide
        $w4 = "MetaMask" ascii wide
        $w5 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $w6 = "Atomic Wallet" ascii wide
    condition:
        2 of them
}

rule Capability_Ransomware_Indicators
{
    meta:
        description = "Shadow-copy deletion or ransom-note wording"
        severity = "high"
        category = "impact"
    strings:
        $v1 = "vssadmin" nocase ascii wide
        $v2 = "delete shadows" nocase ascii wide
        $v3 = "shadowcopy delete" nocase ascii wide
        $v4 = "bcdedit" nocase ascii wide
        $v5 = "recoveryenabled no" nocase ascii wide
        $n1 = "your files have been encrypted" nocase ascii wide
        $n2 = "decrypt your files" nocase ascii wide
        $n3 = "bitcoin" nocase ascii wide
    condition:
        ($v1 and ($v2 or $v3)) or ($v4 and $v5) or ($n1 or ($n2 and $n3))
}

rule Capability_Download_And_Execute
{
    meta:
        description = "Downloads a file and executes it"
        severity = "medium"
        category = "execution"
    strings:
        $d1 = "URLDownloadToFile" ascii wide
        $d2 = "InternetReadFile" ascii wide
        $d3 = "WinHttpReadData" ascii wide
        $e1 = "ShellExecute" ascii wide
        $e2 = "WinExec" ascii wide
        $e3 = "CreateProcess" ascii wide
    condition:
        any of ($d*) and any of ($e*)
}

rule Capability_PowerShell_Encoded
{
    meta:
        description = "Launches PowerShell with an encoded or hidden command"
        severity = "medium"
        category = "execution"
    strings:
        // A full command line, not just the two words appearing somewhere in a large binary
        $enc = /powershell(\.exe)?["']?\s[^\r\n]{0,80}-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+\/=]{24,}/ nocase ascii wide
        $hidden = /powershell(\.exe)?["']?\s[^\r\n]{0,80}-(w|wi|win|window|windowstyle)\s+hidden/ nocase ascii wide
        $b64 = /powershell[^\r\n]{0,200}FromBase64String/ nocase ascii wide
    condition:
        any of them
}
