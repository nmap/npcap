#
# Deploy.ps1 - The diagnostic report script for Npcap
# Author: Yang Luo
# Date: August 29, 2016
#

$report_file_name = $MyInvocation.MyCommand.Definition.Replace(".ps1", "-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")

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
$install_path = get_install_path

function get_props_safe($item)
{
	write_report ("${item}:")
	try {
		(Get-ItemProperty -erroraction stop $item | out-string -stream -Width 2147483647 | ? { $_ -NOTMATCH '^ps.+' })
	}
	catch [System.Management.Automation.ItemNotFoundException] {
		"Not present."
	}
}

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

(Get-WmiObject Win32_OperatingSystem) | Format-List Caption, BuildNumber, Locale, MUILanguages, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion, SystemDirectory, Version

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("CPU Info:")
write_report ("*************************************************")

(Get-WmiObject Win32_Processor) | Format-List Name, Manufacturer, DeviceID, NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors, Addresswidth

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Memory Info:")
write_report ("*************************************************")

"Size:`t`t`t`t" + [int]((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1024 / 1024) + " MB" + " (" + (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory + " Bytes)"

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Network Adapter(s) Info:")
write_report ("*************************************************")

(Get-WmiObject Win32_NetworkAdapter) | Where-Object {$_.GUID -ne $null} | Format-List Caption, GUID, Index, InterfaceIndex, Manufacturer, MACAddress, Speed, NetConnectionID, NetConnectionStatus, PNPDeviceID, ServiceName, AdapterType

#########################################################
#write_report ("`n")
#write_report ("*************************************************")
#write_report ("Driver Info:")
#write_report ("*************************************************")

#Get-WmiObject Win32_SystemDriver | 
#    select *, @{ N='CompanyName';E={ (Get-ItemProperty $_.pathname -ErrorAction Ignore).VersionInfo.companyname }} |
#    Where CompanyName -NotLike "*microsoft*" |
#    Where State -NotLike "Stopped" |
#    sort State, Name |
#    Format-Table Name, Description, ServiceType, State, ExitCode, CompanyName, PathName

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("NDIS Light-Weight Filter (LWF) Info:")
write_report ("*************************************************")

get_props_safe 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\*'

Get-NetAdapterBinding -ComponentID "INSECURE_NPCAP*"

#########################################################
write_report ("`n")
"*************************************************"
write_report ("File Info:")
write_report ("*************************************************")

# write_report ("C:\Program Files\Npcap:")
dir $install_path
Get-AuthenticodeSignature ($install_path + '\npcap.*'),($install_path + '\*.exe') | select -property Path, Status, StatusMessage, @{Name="Thumbprint"; Expression={$_.SignerCertificate | select -expandproperty Thumbprint}}

# write_report ("C:\Windows\System32:")
dir ($env:WinDir + "\System32\") NpcapHelper.exe
dir ($env:WinDir + "\System32\") Packet.dll
dir ($env:WinDir + "\System32\") WlanHelper.exe
dir ($env:WinDir + "\System32\") wpcap.dll
dir ($env:WinDir + "\System32\Npcap\")

if ($os_bit -eq "64-bit")
{
    # write_report ("C:\Windows\SysWOW64:")
    dir ($env:WinDir + "\SysWOW64\") NpcapHelper.exe
    dir ($env:WinDir + "\SysWOW64\") Packet.dll
    dir ($env:WinDir + "\SysWOW64\") WlanHelper.exe
    dir ($env:WinDir + "\SysWOW64\") wpcap.dll
    dir ($env:WinDir + "\SysWOW64\Npcap\")
}

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("WinPcap Info:")
write_report ("*************************************************")

if ($os_bit -eq "32-bit")
{
    get_props_safe ("HKLM:\SOFTWARE\WinPcap")
}
else
{
    get_props_safe ("HKLM:\SOFTWARE\WOW6432Node\WinPcap")
}

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Registry Info:")
write_report ("*************************************************")

if ($os_bit -eq "32-bit")
{
    get_props_safe ("HKLM:\SOFTWARE\Npcap")
}
else
{
    get_props_safe ("HKLM:\SOFTWARE\WOW6432Node\Npcap")
}

get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap")
get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap\Parameters")
get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npcap_wifi")

# WinPcap registry items
get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npf")
get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npf\Parameters")
get_props_safe ("HKLM:\SYSTEM\CurrentControlSet\Services\npf_wifi")

#########################################################
write_report ("`n")
write_report ("*************************************************")
write_report ("Service Info:")
write_report ("*************************************************")

Get-Service npcap

Get-Service npf

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

# SIG # Begin signature block
# MIIbqQYJKoZIhvcNAQcCoIIbmjCCG5YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUn8St85S51ngG/Y+iMCnTk/Qq
# 3/mggha9MIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZ
# oAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnF
# OVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQA
# OPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhis
# EeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQj
# MF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+f
# MRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW
# /5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAf
# BgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/
# AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafD
# DiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6
# HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4
# H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHK
# eZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIo
# xhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIwggXCMIIEqqADAgECAhAKpgeD
# 67UHbrwtEtqbBMKQMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzAp
# BgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikwHhcNMjEw
# NTA1MDAwMDAwWhcNMjQwNjEwMjM1OTU5WjCB0jEdMBsGA1UEDwwUUHJpdmF0ZSBP
# cmdhbml6YXRpb24xEzARBgsrBgEEAYI3PAIBAxMCVVMxGzAZBgsrBgEEAYI3PAIB
# AhMKQ2FsaWZvcm5pYTEVMBMGA1UEBRMMMjAwMDEwMzEwMDEzMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEZMBcGA1UE
# ChMQSW5zZWN1cmUuQ29tIExMQzEZMBcGA1UEAxMQSW5zZWN1cmUuQ29tIExMQzCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbsgU7ixwdeLimsfr0QthiA
# VZKTcKITuD+24zfYLtB1bRXiZ/a8ZF5ttbsdWG7xCY6tFZUUfQOJevBLZmqlpQ3v
# KzryOXSJbG+09SRrrz7DdNv9kO7sdXX/sRpu/qeg19oK2wTq8ACxrVINnpUpsqjP
# QgmY1MekbB+V5AXjX2mtjAXWLfD5dFAXpihBNK+6JvkF2QDaHEEiAObKXGsUjz94
# WqDr416pFgZEvWkktUYl60BKs525gfayFrbdlgkwoUQ7JqqwjNvPHF/XTbtWw+nf
# eR+EKUAd7lhp6Qw5+VAA/GFrWsg5a1iOJEByNeoHQyjGCBEvbLTwc0fNTSjSirkC
# AwEAAaOCAfcwggHzMB8GA1UdIwQYMBaAFI/ofvBtMmoABSPHcJdqOpD/a+rUMB0G
# A1UdDgQWBBTFshBIPHWY+Q0yg4zQdj082F/vUTA1BgNVHREELjAsoCoGCCsGAQUF
# BwgDoB4wHAwaVVMtQ0FMSUZPUk5JQS0yMDAwMTAzMTAwMTMwDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWduaW5nU0hBMi1nMS5jcmwwN6A1
# oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWduaW5nU0hBMi1n
# MS5jcmwwSgYDVR0gBEMwQTA2BglghkgBhv1sAwIwKTAnBggrBgEFBQcCARYbaHR0
# cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEDMH4GCCsGAQUFBwEBBHIw
# cDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEgGCCsGAQUF
# BzAChjxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVkNvZGVT
# aWduaW5nQ0EtU0hBMi5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
# AQEAiyGCiHraDgjkr+iQGd7Rboj/b/GxL9mymUuUW4x2xjhirjWhdRZyxHTIV1oD
# klAQXjRrt8564fJJTnYN5Bi5RT8busklWw3Mr9KWrbPNtJ1G1Uw0E7/DSj5kDiRN
# p7Hh29GwTOpBT/ZP5X8O8olEpC5BBlVI5INPKwXUquhRah8VTFsJryX+BZppp9x1
# p960zzBoxAJhTs4FCe3wKwlotcjRCBza/Pujt8FZklbmaF73OR9GdG6vgpvI/UD1
# W+cKP8URQmSLeKkD51AVgyjLgNVKrdzoLfj+mDsONq9Nr729/+iJa+6ak8Nw539z
# X+nEL8Ilmj5Wcun3Xzfs9xBOUzCCBrwwggWkoAMCAQICEAPxtOFfOoLxFJZ4s9fY
# R1wwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGln
# aUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBDQTAeFw0xMjA0MTgxMjAwMDBa
# Fw0yNzA0MTgxMjAwMDBaMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNVBAMTIkRpZ2lD
# ZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCnU/oPsrUT8WTPhID8roA10bbXx6MsrBosrPGErDo1EjqS
# kbpX5MTJ8y+oSDy31m7clyK6UXlhr0MvDbebtEkxrkRYPqShlqeHTyN+w2xlJJBV
# PqHKI3zFQunEemJFm33eY3TLnmMl+ISamq1FT659H8gTy3WbyeHhivgLDJj0yj7Q
# Rap6HqVYkzY0visuKzFYZrQyEJ+d8FKh7+g+03byQFrc+mo9G0utdrCMXO42uoPq
# MKhM3vELKlhBiK4AiasD0RaCICJ2615UOBJi4dJwJNvtH3DSZAmALeK2nc4f8rsh
# 82zb2LMZe4pQn+/sNgpcmrdK0wigOXn93b89OgklAgMBAAGjggNYMIIDVDASBgNV
# HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDAzB/BggrBgEFBQcBAQRzMHEwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNydDCBjwYDVR0fBIGH
# MIGEMECgPqA8hjpodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdo
# QXNzdXJhbmNlRVZSb290Q0EuY3JsMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMIIBxAYDVR0g
# BIIBuzCCAbcwggGzBglghkgBhv1sAwIwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8v
# d3d3LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYB
# BQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMA
# ZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEA
# YwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIA
# dAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcA
# IABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwA
# aQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkA
# bgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUA
# ZgBlAHIAZQBuAGMAZQAuMB0GA1UdDgQWBBSP6H7wbTJqAAUjx3CXajqQ/2vq1DAf
# BgNVHSMEGDAWgBSxPsNpA/i/RwHUmCYaCALvY2QrwzANBgkqhkiG9w0BAQsFAAOC
# AQEAGTNKDIEzN9utNsnkyTq7tRsueqLi9ENCF56/TqFN4bHb6YHdnwHy5IjV6f4J
# /SHB7F2A0vDWwUPC/ncr2/nXkTPObNWyGTvmLtbJk0+IQI7N4fV+8Q/GWVZy6Otq
# Qb0c1UbVfEnKZjgVwb/gkXB3h9zJjTHJDCmiM+2N4ofNiY0/G//V4BqXi3zabfuo
# xrI6Zmt7AbPN2KY07BIBq5VYpcRTV6hg5ucCEqC5I2SiTbt8gSVkIb7P7kIYQ5e7
# pTcGr03/JqVNYUvsRkG4Zc64eZ4IlguBjIo7j8eZjKMqbphtXmHGlreKuWEtk7jr
# DgRD1/X+pvBi1JlqpcHB8GSUgDGCBFYwggRSAgEBMIGAMGwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikC
# EAqmB4PrtQduvC0S2psEwpAwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMOgPMZ88W4gSH4V47HO
# 4qR5rWMMMA0GCSqGSIb3DQEBAQUABIIBAH2b+a7rEupjpOCaPBQsUcXd7ht6U7OV
# v2sUtnn9QX3MST37QduCH3wTFYx8ejbSC6NvO/19g0M4qUKNVUNVNO156pnkGaUp
# AUsUBp0Bl00usxhuGzoYnFsidRMRUBW4wmxTzQUDG921t2L/rh8GXgmjjZf1E6Nc
# JXAgDfkk3MIiNsyfykFz6F8igS8LwvVP+Xpoa0lyfjlc6+JAc8qtjMREnhVJbGnt
# UNlxmcLhJogzkXwTASTF4zXIFllz5rIp9jwR1oy+M6OLvi5Iu/zR4YYXdpBmwHQX
# BjYOwIRpD2HDCBW6lSYMxjU+Q/wYQoqwTHe0f0LX//Wf3UehnVHj9GGhggIwMIIC
# LAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQ
# DUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMDYyMjE4NDQ1N1owLwYJKoZI
# hvcNAQkEMSIEIKGbUsNDXTo/47RuNjZzTJPbOW0qUAgu0AYs58FFEQOZMA0GCSqG
# SIb3DQEBAQUABIIBAEtyllHvGtGEdSutssnMZXfJlNpPhD9EDMlxy2X1ufnkiwzh
# +HwP3mOgSYowT8uzQCCEGbznZ7nqThVKE8cIQBZKNeyNKgZJxgVLPo5RCxLAoV3k
# 8dQejdZp/DRisSo6KPnen/sJkZ6UvRaf9SB4jS7SlQSmH6nZrS5PEmibXqk4lryj
# U0SJ4usxc6GVgo1lUDW1Umy7aBlSMeQVP55GYqeJEeMrRTaHEmVwgNO5n8ZD8Nvb
# cihcTreringO4B79uoq3dR0u5CEmpEuElTY73+31pCgMgQebBAXU93ES1l59SyU/
# 32KP+5U2eXWhDBaId9Ss7f0O59A8sX8bFgT0p4s=
# SIG # End signature block
