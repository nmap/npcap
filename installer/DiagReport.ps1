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

function get_install_path()
{
    if ($os_bit -eq "32-bit")
    {
        return (Get-ItemProperty HKLM:\SOFTWARE\Npcap).'(default)'
    }
    else
    {
        return (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Npcap).'(default)'
    }
}

$os_bit = get_os_bit
$winpcap_mode = get_winpcap_mode
$install_path = get_install_path


write_report ("*************************************************")
write_report "DiagReport for Npcap ( http://npcap.org )"
write_report ("*************************************************")
"Script Architecture:`t`t" + (get_script_bit)
"Script Path:`t`t`t" + ($MyInvocation.MyCommand.Definition)
"Current Time:`t`t`t" + (Get-Date)
"Npcap install path:`t`t" + $install_path
"Npcap Version:`t`t`t" + ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($install_path + "\NPFInstall.exe").FileVersion)
"PowerShell Version:`t`t" + ($PSVersionTable.PSVersion)

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("OS Info:")
write_report ("*************************************************")
"Caption:`t`t`t" + (Get-WmiObject Win32_OperatingSystem).Caption
"BuildNumber:`t`t`t" + (Get-WmiObject Win32_OperatingSystem).BuildNumber
# write_report "BuildType:`t`t`t`t`, (Get-WmiObject Win32_OperatingSystem).BuildType
"Locale:`t`t`t`t" + (Get-WmiObject Win32_OperatingSystem).Locale
"MUILanguages:`t`t`t" + (Get-WmiObject Win32_OperatingSystem).MUILanguages
"OSArchitecture:`t`t`t" + (Get-WmiObject Win32_OperatingSystem).OSArchitecture
"ServicePackMajorVersion:`t" + (Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion
"ServicePackMinorVersion:`t" + (Get-WmiObject Win32_OperatingSystem).ServicePackMinorVersion
"SystemDirectory:`t`t" + (Get-WmiObject Win32_OperatingSystem).SystemDirectory
"Version:`t`t`t" + (Get-WmiObject Win32_OperatingSystem).Version

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("CPU Info:")
write_report ("*************************************************")

"Name:`t`t`t`t" + (Get-WmiObject Win32_processor).Name
"Manufacturer:`t`t`t" + (Get-WmiObject Win32_processor).Manufacturer
"DeviceID:`t`t`t" + (Get-WmiObject Win32_processor).DeviceID
"NumberOfCores:`t`t`t" + (Get-WmiObject Win32_processor).NumberOfCores
"NumberOfEnabledCore:`t`t" + (Get-WmiObject Win32_processor).NumberOfEnabledCore
"NumberOfLogicalProcessors:`t" + (Get-WmiObject Win32_processor).NumberOfLogicalProcessors
"Addresswidth:`t`t`t" + (Get-WmiObject Win32_processor).Addresswidth

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Memory Info:")
write_report ("*************************************************")

"Size:`t`t`t`t" + [int]((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1024 / 1024) + " MB" + " (" + (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory + “ Bytes)”

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Network Adapter Info:")
write_report ("*************************************************")

Get-NetAdapter

#########################################################
write_report ("`n")
"*************************************************"
write_report ("File Info:")
write_report ("*************************************************")

# write_report ("C:\Program Files\Npcap:")
dir $install_path

# write_report ("C:\Windows\System32:")
dir "C:\Windows\System32\" NpcapHelper.exe
dir "C:\Windows\System32\" Packet.dll
dir "C:\Windows\System32\" WlanHelper.exe
dir "C:\Windows\System32\" wpcap.dll
dir "C:\Windows\System32\Npcap\"

if ($os_bit -eq "64-bit")
{
    # write_report ("C:\Windows\SysWOW64:")
    dir "C:\Windows\SysWOW64\" NpcapHelper.exe
    dir "C:\Windows\SysWOW64\" Packet.dll
    dir "C:\Windows\SysWOW64\" WlanHelper.exe
    dir "C:\Windows\SysWOW64\" wpcap.dll
    dir "C:\Windows\SysWOW64\Npcap\"
}

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

write_report ("Please refer to: $install_path\install.log")

# Stop-Transcript
# ) *>&1 > $report_file_name
# ) >> $report_file_name
) 2>&1 >> $report_file_name

notepad $report_file_name