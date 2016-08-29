#
# Deploy.ps1 - The diagnostic report script for Npcap
# Author: Yang Luo
# Date: August 29, 2016
#

function get_script_bit()
{
    if ([IntPtr]::Size -eq 8)
    {
        '64-bit'
    }
    else
    {
        '32-bit'
    }
}

function get_os_bit()
{
    if ([Environment]::Is64BitOperatingSystem)
    {
        '64-bit'
    }
    else
    {
        '32-bit'
    }
}

$os_bit = get_os_bit

#(Get-Item HKLM:\Software\Microsoft\Windows\Currentversion).GetValueNames()


Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host "DiagReport for Npcap 0.08 ( http://npcap.org )"
Write-Host ("*************************************************")
Write-Host "This Script:`t`t`t", (get_script_bit)

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("OS Info:")
Write-Host ("*************************************************")
Write-Host "Caption:`t`t`t", (Get-WmiObject Win32_OperatingSystem).Caption
Write-Host "BuildNumber:`t`t`t", (Get-WmiObject Win32_OperatingSystem).BuildNumber
#Write-Host "BuildType:`t`t`t`t`, (Get-WmiObject Win32_OperatingSystem).BuildType
Write-Host "Locale:`t`t`t`t", (Get-WmiObject Win32_OperatingSystem).Locale
Write-Host "MUILanguages:`t`t`t", (Get-WmiObject Win32_OperatingSystem).MUILanguages
Write-Host "OSArchitecture:`t`t`t", (Get-WmiObject Win32_OperatingSystem).OSArchitecture
Write-Host "ServicePackMajorVersion:`t", (Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion
Write-Host "ServicePackMinorVersion:`t", (Get-WmiObject Win32_OperatingSystem).ServicePackMinorVersion
Write-Host "SystemDirectory:`t`t", (Get-WmiObject Win32_OperatingSystem).SystemDirectory
Write-Host "Version:`t`t`t", (Get-WmiObject Win32_OperatingSystem).Version

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("File Info:")
Write-Host ("*************************************************")

dir "C:\Program Files\Npcap\"

dir "C:\Windows\System32\" NpcapHelper.exe
dir "C:\Windows\System32\" Packet.dll
dir "C:\Windows\System32\" WlanHelper.exe
dir "C:\Windows\System32\" wpcap.dll
dir "C:\Windows\System32\Npcap\"

dir "C:\Windows\SysWOW64\" NpcapHelper.exe
dir "C:\Windows\SysWOW64\" Packet.dll
dir "C:\Windows\SysWOW64\" WlanHelper.exe
dir "C:\Windows\SysWOW64\" wpcap.dll
dir "C:\Windows\SysWOW64\Npcap\"

#Test-Path "C:\Program Files\Npcap\NPFInstall.exe"

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("Service Info:")
Write-Host ("*************************************************")

Get-Service npcap
Get-Service npf

#cmd /c sc query npcap
