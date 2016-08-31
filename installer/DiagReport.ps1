#
# Deploy.ps1 - The diagnostic report script for Npcap
# Author: Yang Luo
# Date: August 29, 2016
#

$report_file_name = $MyInvocation.MyCommand.Definition.Replace(".ps1", ".txt")

# Delete the old report if exists.
if (Test-Path $report_file_name)
{
    Remove-Item $report_file_name
}

$(

# $ErrorActionPreference="SilentlyContinue"
# Stop-Transcript | Out-Null
# $ErrorActionPreference = "Continue"
# Start-Transcript -IncludeInvocationHeader -Path $report_file_name

function write_report($text)
{
    # Write-Host $text
    # Write-Output $text
    # $text | Out-File -Append -FilePath $report_file_name
    $text
    # $text >> $report_file_name
    # Write-Output $text | Out-File -Append -FilePath $report_file_name
}

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


write_report ("*************************************************")
write_report "DiagReport for Npcap ( http://npcap.org )"
write_report ("*************************************************")
write_report "Script Architecture:`t`t", (get_script_bit)
write_report "Current Time:`t`t`t", (Get-Date)
write_report "Npcap Version:`t`t`t", ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Npcap\NPFInstall.exe").FileVersion)

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("OS Info:")
write_report ("*************************************************")
write_report "Caption:`t`t`t", (Get-WmiObject Win32_OperatingSystem).Caption
write_report "BuildNumber:`t`t`t", (Get-WmiObject Win32_OperatingSystem).BuildNumber
# write_report "BuildType:`t`t`t`t`, (Get-WmiObject Win32_OperatingSystem).BuildType
write_report "Locale:`t`t`t`t", (Get-WmiObject Win32_OperatingSystem).Locale
write_report "MUILanguages:`t`t`t", (Get-WmiObject Win32_OperatingSystem).MUILanguages
write_report "OSArchitecture:`t`t`t", (Get-WmiObject Win32_OperatingSystem).OSArchitecture
write_report "ServicePackMajorVersion:`t", (Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion
write_report "ServicePackMinorVersion:`t", (Get-WmiObject Win32_OperatingSystem).ServicePackMinorVersion
write_report "SystemDirectory:`t`t", (Get-WmiObject Win32_OperatingSystem).SystemDirectory
write_report "Version:`t`t`t", (Get-WmiObject Win32_OperatingSystem).Version

#########################################################
write_report ("`n")
"*************************************************"
write_report ("File Info:")
write_report ("*************************************************")

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
write_report ("`n")
write_report ("*************************************************")
write_report ("Registry Info:")
write_report ("*************************************************")

if ($os_bit -eq "32-bit")
{
    write_report ("HKLM:\SOFTWARE\Npcap:")
    (Get-ItemProperty HKLM:\SOFTWARE\Npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}
else
{
    write_report ("HKLM:\SOFTWARE\WOW6432Node\Npcap:")
    (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}

write_report ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap:")
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
write_report ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi:")
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })

if ($winpcap_mode -eq 1)
{
    write_report ("HKLM:\SYSTEM\CurrentControlSet\Services\npf:")
    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npf | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
    write_report ("HKLM:\SYSTEM\CurrentControlSet\Services\npf_wifi:")
    (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\npf_wifi | out-string -stream | ? { $_ -NOTMATCH '^ps.+' })
}

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Service Info:")
write_report ("*************************************************")

Get-Service npcap

if ($winpcap_mode)
{
    Get-Service npf
}

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Install Info:")
write_report ("*************************************************")

write_report ("Please refer to: C:\Program Files\Npcap\install.log")

# Stop-Transcript
# ) *>&1 > $report_file_name
# ) >> $report_file_name
) 2>&1 >> $report_file_name

notepad $report_file_name