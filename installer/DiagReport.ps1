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
    return (Get-WmiObject Win32_OperatingSystem).OSArchitecture
}

function get_winpcap_mode()
{
    return (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\npcap).GetValue("WinPcapCompatible")
}

$os_bit = get_os_bit
$winpcap_mode = get_winpcap_mode


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

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("Registry Info:")
Write-Host ("*************************************************")

if ($os_bit -eq "32-bit")
{
    Write-Host ("HKLM:\SOFTWARE\Npcap:")
    (Get-ItemProperty HKLM:\SOFTWARE\Npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}
else
{
    Write-Host ("HKLM:\SOFTWARE\WOW6432Node\Npcap:")
    (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}

Write-Host ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap:")
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
Write-Host ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi:")
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })

if ($winpcap_mode -eq 1)
{
    Write-Host ("HKLM:\SYSTEM\CurrentControlSet\Services\npf:")
    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npf | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
    Write-Host ("HKLM:\SYSTEM\CurrentControlSet\Services\npf_wifi:")
    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npf_wifi | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("Service Info:")
Write-Host ("*************************************************")

Get-Service npcap

if ($winpcap_mode)
{
    Get-Service npf
}

#########################################################
Write-Host ("`n")
Write-Host ("*************************************************")
Write-Host ("Install Info:")
Write-Host ("*************************************************")

Write-Host ("Please refer to: C:\Program Files\Npcap\install.log")
