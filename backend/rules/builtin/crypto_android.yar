// Crypto constants and Android abuse patterns

rule Crypto_AES_SBox
{
    meta:
        description = "Contains the AES forward S-box (embedded AES implementation)"
        severity = "low"
        category = "crypto"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 }
    condition:
        $sbox
}

rule Crypto_ChaCha_Salsa_Constant
{
    meta:
        description = "ChaCha20/Salsa20 'expand 32-byte k' constant"
        severity = "low"
        category = "crypto"
    strings:
        $s1 = "expand 32-byte k"
        $s2 = "expand 16-byte k"
    condition:
        any of them
}

rule Crypto_Custom_Base64_Alphabet
{
    meta:
        description = "Standard Base64 alphabet table (often used to decode embedded payloads)"
        severity = "low"
        category = "encoding"
    strings:
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    condition:
        $b64
}

rule Android_SMS_Abuse
{
    meta:
        description = "Sends SMS messages or reads incoming SMS (premium-SMS fraud, OTP theft)"
        severity = "high"
        category = "android"
    strings:
        $p1 = "android.permission.SEND_SMS"
        $p2 = "android.permission.RECEIVE_SMS"
        $p3 = "android.permission.READ_SMS"
        $c1 = "sendTextMessage"
        $c2 = "android.provider.Telephony.SMS_RECEIVED"
    condition:
        ($p1 and $c1) or (($p2 or $p3) and $c2)
}

rule Android_Accessibility_Abuse
{
    meta:
        description = "Registers an AccessibilityService (frequently abused by banking trojans for overlay/input capture)"
        severity = "medium"
        category = "android"
    strings:
        $s1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        $s2 = "android.accessibilityservice.AccessibilityService"
        $s3 = "performGlobalAction"
        $s4 = "AccessibilityNodeInfo"
    condition:
        ($s1 or $s2) and ($s3 or $s4)
}

rule Android_Dynamic_Code_Loading
{
    meta:
        description = "Loads DEX code at runtime (can hide payloads from static analysis)"
        severity = "medium"
        category = "android"
    strings:
        $s1 = "dalvik/system/DexClassLoader"
        $s2 = "dalvik.system.DexClassLoader"
        $s3 = "dalvik/system/InMemoryDexClassLoader"
        $s4 = "dalvik.system.InMemoryDexClassLoader"
    condition:
        any of them
}

rule Android_Device_Admin
{
    meta:
        description = "Requests device administrator rights (can block uninstall or lock the device)"
        severity = "medium"
        category = "android"
    strings:
        $s1 = "android.permission.BIND_DEVICE_ADMIN"
        $s2 = "android.app.action.DEVICE_ADMIN_ENABLED"
    condition:
        any of them
}
