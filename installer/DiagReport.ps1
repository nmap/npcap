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
ls ($install_path + '\npcap.*'),($install_path + '\*.exe') | Get-AuthenticodeSignature | select -property Path, Status, StatusMessage, @{Name="Thumbprint"; Expression={$_.SignerCertificate | select -expandproperty Thumbprint}}

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
# MIIbzgYJKoZIhvcNAQcCoIIbvzCCG7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBQ7eNMra/Ux4oL
# OfX2CAh1GJnq+oaa063f2hzC92bGM6CCFr0wggT+MIID5qADAgECAhANQkrgvjqI
# /2BAIc4UAPDdMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcN
# MjEwMTAxMDAwMDAwWhcNMzEwMTA2MDAwMDAwWjBIMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFt
# cCAyMDIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuZhhGfFivUN
# CKRFymNrUdc6EUK9CnV1TZS0DFC1JhD+HchvkWsMlucaXEjvROW/m2HNFZFiWrj/
# ZwucY/02aoH6KfjdK3CF3gIY83htvH35x20JPb5qdofpir34hF0edsnkxnZ2OlPR
# 0dNaNo/Go+EvGzq3YdZz7E5tM4p8XUUtS7FQ5kE6N1aG3JMjjfdQJehk5t3Tjy9X
# tYcg6w6OLNUj2vRNeEbjA4MxKUpcDDGKSoyIxfcwWvkUrxVfbENJCf0mI1P2jWPo
# GqtbsR0wwptpgrTb/FZUvB+hh6u+elsKIC9LCcmVp42y+tZji06lchzun3oBc/gZ
# 1v4NSYS9AQIDAQABo4IBuDCCAbQwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQC
# MAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQQYDVR0gBDowODA2BglghkgBhv1s
# BwEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMB8G
# A1UdIwQYMBaAFPS24SAd/imu0uRhpbKiJbLIFzVuMB0GA1UdDgQWBBQ2RIaOpLqw
# Zr68KC0dRDbd42p6vDBxBgNVHR8EajBoMDKgMKAuhixodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDAyoDCgLoYsaHR0cDovL2NybDQu
# ZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwgYUGCCsGAQUFBwEBBHkw
# dzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME8GCCsGAQUF
# BzAChkNodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNz
# dXJlZElEVGltZXN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQBIHNy1
# 6ZojvOca5yAOjmdG/UJyUXQKI0ejq5LSJcRwWb4UoOUngaVNFBUZB3nw0QTDhtk7
# vf5EAmZN7WmkD/a4cM9i6PVRSnh5Nnont/PnUp+Tp+1DnnvntN1BIon7h6JGA078
# 9P63ZHdjXyNSaYOC+hpT7ZDMjaEXcw3082U5cEvznNZ6e9oMvD0y0BvL9WH8dQgA
# dryBDvjA4VzPxBFy5xtkSdgimnUVQvUtMjiB2vRgorq0Uvtc4GEkJU+y38kpqHND
# Udq9Y9YfW5v3LhtPEx33Sg1xfpe39D+E68Hjo0mh+s6nv1bPull2YYlffqe0jmd4
# +TaY4cso2luHpoovMIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkq
# hkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBB
# c3N1cmVkIElEIFJvb3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAw
# WjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3Vy
# ZWQgSUQgVGltZXN0YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAvdAy7kvNj3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0jbOI
# 5Je/YyGQmL8TvFfTw+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+Cyd+
# wKL1oODeIj8O/36V+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8iEA91
# z3FyTgqt30A6XLdR4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEnKYmE
# UeaC50ZQ/ZQqLKfkdT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3vBkL9
# olMqT4UdxB08r8/arBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYEFPS2
# 4SAd/imu0uRhpbKiJbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3z
# bcgPMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8E
# ejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZIAYb9
# bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793afKpj
# erN4zwY3QITvS4S/ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/Capg
# 33akOpMP+LLR2HwZYuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTlH0gQ
# GF+JOGFNYkYkh2OMkVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo9WuW
# wPRYaQ18yAGxuSh1t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oMLStt
# osR+u8QlK0cCCHxJrhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY9aaO
# UjCCBcIwggSqoAMCAQICEAqmB4PrtQduvC0S2psEwpAwDQYJKoZIhvcNAQELBQAw
# bDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWdu
# aW5nIENBIChTSEEyKTAeFw0yMTA1MDUwMDAwMDBaFw0yNDA2MTAyMzU5NTlaMIHS
# MR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEGCysGAQQBgjc8AgED
# EwJVUzEbMBkGCysGAQQBgjc8AgECEwpDYWxpZm9ybmlhMRUwEwYDVQQFEwwyMDAw
# MTAzMTAwMTMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdTZWF0dGxlMRkwFwYDVQQKExBJbnNlY3VyZS5Db20gTExDMRkwFwYDVQQD
# ExBJbnNlY3VyZS5Db20gTExDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEApuyBTuLHB14uKax+vRC2GIBVkpNwohO4P7bjN9gu0HVtFeJn9rxkXm21ux1Y
# bvEJjq0VlRR9A4l68EtmaqWlDe8rOvI5dIlsb7T1JGuvPsN02/2Q7ux1df+xGm7+
# p6DX2grbBOrwALGtUg2elSmyqM9CCZjUx6RsH5XkBeNfaa2MBdYt8Pl0UBemKEE0
# r7om+QXZANocQSIA5spcaxSPP3haoOvjXqkWBkS9aSS1RiXrQEqznbmB9rIWtt2W
# CTChRDsmqrCM288cX9dNu1bD6d95H4QpQB3uWGnpDDn5UAD8YWtayDlrWI4kQHI1
# 6gdDKMYIES9stPBzR81NKNKKuQIDAQABo4IB9zCCAfMwHwYDVR0jBBgwFoAUj+h+
# 8G0yagAFI8dwl2o6kP9r6tQwHQYDVR0OBBYEFMWyEEg8dZj5DTKDjNB2PTzYX+9R
# MDUGA1UdEQQuMCygKgYIKwYBBQUHCAOgHjAcDBpVUy1DQUxJRk9STklBLTIwMDAx
# MDMxMDAxMzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwewYD
# VR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0VWQ29kZVNp
# Z25pbmdTSEEyLWcxLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQuY29t
# L0VWQ29kZVNpZ25pbmdTSEEyLWcxLmNybDBKBgNVHSAEQzBBMDYGCWCGSAGG/WwD
# AjApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwBwYF
# Z4EMAQMwfgYIKwYBBQUHAQEEcjBwMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wSAYIKwYBBQUHMAKGPGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEVWQ29kZVNpZ25pbmdDQS1TSEEyLmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCLIYKIetoOCOSv6JAZ3tFuiP9v8bEv2bKZ
# S5RbjHbGOGKuNaF1FnLEdMhXWgOSUBBeNGu3znrh8klOdg3kGLlFPxu6ySVbDcyv
# 0pats820nUbVTDQTv8NKPmQOJE2nseHb0bBM6kFP9k/lfw7yiUSkLkEGVUjkg08r
# BdSq6FFqHxVMWwmvJf4Fmmmn3HWn3rTPMGjEAmFOzgUJ7fArCWi1yNEIHNr8+6O3
# wVmSVuZoXvc5H0Z0bq+Cm8j9QPVb5wo/xRFCZIt4qQPnUBWDKMuA1Uqt3Ogt+P6Y
# Ow42r02vvb3/6Ilr7pqTw3Dnf3Nf6cQvwiWaPlZy6fdfN+z3EE5TMIIGvDCCBaSg
# AwIBAgIQA/G04V86gvEUlniz19hHXDANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290
# IENBMB4XDTEyMDQxODEyMDAwMFoXDTI3MDQxODEyMDAwMFowbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdT+g+ytRPxZM+EgPyu
# gDXRttfHoyysGiys8YSsOjUSOpKRulfkxMnzL6hIPLfWbtyXIrpReWGvQy8Nt5u0
# STGuRFg+pKGWp4dPI37DbGUkkFU+ocojfMVC6cR6YkWbfd5jdMueYyX4hJqarUVP
# rn0fyBPLdZvJ4eGK+AsMmPTKPtBFqnoepViTNjS+Ky4rMVhmtDIQn53wUqHv6D7T
# dvJAWtz6aj0bS612sIxc7ja6g+owqEze8QsqWEGIrgCJqwPRFoIgInbrXlQ4EmLh
# 0nAk2+0fcNJkCYAt4radzh/yuyHzbNvYsxl7ilCf7+w2Clyat0rTCKA5ef3dvz06
# CSUCAwEAAaOCA1gwggNUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQD
# AgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMH8GCCsGAQUFBwEBBHMwcTAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEkGCCsGAQUFBzAChj1odHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZS
# b290Q0EuY3J0MIGPBgNVHR8EgYcwgYQwQKA+oDyGOmh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwQKA+oDyG
# Omh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VF
# VlJvb3RDQS5jcmwwggHEBgNVHSAEggG7MIIBtzCCAbMGCWCGSAGG/WwDAjCCAaQw
# OgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVw
# b3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUA
# IABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4A
# cwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQA
# aABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQA
# aABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUA
# bgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkA
# IABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUA
# cgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0OBBYEFI/o
# fvBtMmoABSPHcJdqOpD/a+rUMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9j
# ZCvDMA0GCSqGSIb3DQEBCwUAA4IBAQAZM0oMgTM32602yeTJOru1Gy56ouL0Q0IX
# nr9OoU3hsdvpgd2fAfLkiNXp/gn9IcHsXYDS8NbBQ8L+dyvb+deRM85s1bIZO+Yu
# 1smTT4hAjs3h9X7xD8ZZVnLo62pBvRzVRtV8ScpmOBXBv+CRcHeH3MmNMckMKaIz
# 7Y3ih82JjT8b/9XgGpeLfNpt+6jGsjpma3sBs83YpjTsEgGrlVilxFNXqGDm5wIS
# oLkjZKJNu3yBJWQhvs/uQhhDl7ulNwavTf8mpU1hS+xGQbhlzrh5ngiWC4GMijuP
# x5mMoypumG1eYcaWt4q5YS2TuOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIEZzCCBGMC
# AQEwgYAwbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29k
# ZSBTaWduaW5nIENBIChTSEEyKQIQCqYHg+u1B268LRLamwTCkDANBglghkgBZQME
# AgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCBlWZScJ8Fx6Km+WW1mjgpNIz1eG1asA/dAwkwhhJL6mjANBgkq
# hkiG9w0BAQEFAASCAQCS4bio9svu/kPp3DQqTQHVeUcOwMTLPH1YKOtcKviI4jw+
# TAyAG6ps0ZvukXnv2HulFWNlokFYh4F9wBdN7rFovgjHIxkEMrieO70+//KRezG1
# drZWhApgL+wsYWU48ye6iKsqaF8xjXTvJhxlburhuKYMuI3RxKufrcUFC2d6LWN5
# OGBmP5mn+wvOYKDIuFQK+w5OKti/Bz5DM+u8gjyeYd6/AJwOuaPO7w1rPvMTr/MQ
# lEKoii8XfOmTP9+ygv9bS4kbKc+t34+UJJRDFDp0XFsedfqNiUiqVtGPViUL1Oc/
# 4w3beBa3AKKFLj69YeBoQ8eKel7tR93u8FqNSNoQoYICMDCCAiwGCSqGSIb3DQEJ
# BjGCAh0wggIZAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lD
# ZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0ECEA1CSuC+Ooj/YEAh
# zhQA8N0wDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yMTA5MjMyMTQzMzhaMC8GCSqGSIb3DQEJBDEiBCCo
# lyK64cLOTICxLWx7JgfpSVvi/zVYSSiTRSnvuNLYizANBgkqhkiG9w0BAQEFAASC
# AQAcKv0KXxGMJolhiOY9Je5vq5X0+TTZKi5paVP6BP6Re+7kMeW/ArWOIATdyD14
# DgOB87sw/EHAplfC1llDv5GuDCnceImQCZCATzC0/mSDF5ECCCSDfjI6/6BYYclT
# tvCM8nE7DB4nL8L9F6vm7bED6pHrl359VMGkbHCbD+JInbmHnokFlYlXNqdd2e0z
# Tl5uVKToq2qf7mY3zjE+cYFtpB1kqfpqHmI4tUPgsyvh3amVfOuxem8vAWv73Dmh
# kk00oR30EtAx+ym78RYP3j7+pj3kqP00sEUy5pCpeyWrrKrlFJIxGNWaemau8Ywe
# a3F5wup63nYoIvvR3yGCDNeM
# SIG # End signature block
