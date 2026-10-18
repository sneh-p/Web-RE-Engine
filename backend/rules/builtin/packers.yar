// Packers, protectors and installer/bundler formats

rule Packer_UPX
{
    meta:
        description = "Packed with UPX"
        severity = "low"
        category = "packer"
    strings:
        $magic = "UPX!"
        $s0 = "UPX0"
        $s1 = "UPX1"
    condition:
        $magic or ($s0 and $s1)
}

rule Packer_MPRESS
{
    meta:
        description = "Packed with MPRESS"
        severity = "low"
        category = "packer"
    strings:
        $s1 = ".MPRESS1"
        $s2 = ".MPRESS2"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Packer_ASPack
{
    meta:
        description = "Packed with ASPack"
        severity = "low"
        category = "packer"
    strings:
        $s1 = ".aspack"
        $s2 = ".adata"
    condition:
        uint16(0) == 0x5A4D and $s1 and $s2
}

rule Protector_Themida_VMProtect
{
    meta:
        description = "Section names of Themida/WinLicense or VMProtect code virtualizers"
        severity = "medium"
        category = "protector"
    strings:
        $t1 = ".themida"
        $t2 = ".winlice"
        $v1 = ".vmp0"
        $v2 = ".vmp1"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Bundler_PyInstaller
{
    meta:
        description = "Python application bundled with PyInstaller"
        severity = "low"
        category = "bundler"
    strings:
        $cookie = { 4D 45 49 0C 0B 0A 0B 0E }
        $s1 = "_MEIPASS"
        $s2 = "PyInstaller"
    condition:
        $cookie or ($s1 and $s2)
}

rule Installer_NSIS
{
    meta:
        description = "Nullsoft Scriptable Install System installer"
        severity = "low"
        category = "installer"
    strings:
        $s1 = "Nullsoft.NSIS.exehead"
        $s2 = "NullsoftInst"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Installer_InnoSetup
{
    meta:
        description = "Inno Setup installer"
        severity = "low"
        category = "installer"
    strings:
        $s1 = "Inno Setup Setup Data"
        $s2 = "Inno Setup Messages"
    condition:
        uint16(0) == 0x5A4D and any of them
}
