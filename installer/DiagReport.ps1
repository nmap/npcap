#
# Deploy.ps1 - The diagnostic report script for Npcap
# Author: Yang Luo
# Date: August 29, 2016
#
# 1. Force all PowerShell cmdlets and redirection operators (>, >>) to use UTF-8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# 2. Ensure PowerShell reads external command output as UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8

# 3. Ensure the console and spawned external tools use UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

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
write_report "DiagReport for Npcap ( https://npcap.com )"
write_report ("*************************************************")
"Script Architecture:`t`t" + (get_script_bit)
"Script Path:`t`t`t" + ($MyInvocation.MyCommand.Definition)
"Current Time:`t`t`t" + (Get-Date)
"Npcap install path:`t`t" + $install_path
"Npcap Version:`t`t`t" + ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($install_path + "\NPFInstall.exe").FileVersion)
"PowerShell Version:`t`t" + ($PSVersionTable.PSVersion)

#########################################################
write_report ("*************************************************")
write_report ("OS Info:")
write_report ("*************************************************")

(Get-WmiObject Win32_OperatingSystem) | Format-List Caption, BuildNumber, Locale, MUILanguages, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion, SystemDirectory, Version

#########################################################
write_report ("*************************************************")
write_report ("CPU Info:")
write_report ("*************************************************")

(Get-WmiObject Win32_Processor) | Format-List Name, Manufacturer, DeviceID, NumberOfCores, NumberOfEnabledCore, NumberOfLogicalProcessors, Addresswidth

#########################################################
write_report ("*************************************************")
write_report ("Memory Info:")
write_report ("*************************************************")

"Size:`t`t`t`t" + [int]((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1024 / 1024) + " MB" + " (" + (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory + " Bytes)"

#########################################################
write_report ("*************************************************")
write_report ("Network Adapter(s) Info:")
write_report ("*************************************************")

(Get-WmiObject Win32_NetworkAdapter) | Where-Object {$_.GUID -ne $null} | Format-List Caption, GUID, Index, InterfaceIndex, Manufacturer, MACAddress, Speed, NetConnectionID, NetConnectionStatus, PNPDeviceID, ServiceName, AdapterType

#########################################################
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
write_report ("*************************************************")
write_report ("NDIS Light-Weight Filter (LWF) Info:")
write_report ("*************************************************")

get_props_safe 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\*'

Get-NetAdapterBinding -ComponentID "INSECURE_NPCAP*"
Get-NetAdapterBinding -ComponentID "nmap_npcap*"

#########################################################
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
write_report ("*************************************************")
write_report ("Service Info:")
write_report ("*************************************************")

Get-Service npcap

Get-Service npf

#########################################################
write_report ("*************************************************")
write_report ("Install Info:")
write_report ("*************************************************")

write_report ("Please refer to: $install_path\install.log")

if (Test-Path -Path "$install_path\DriverQuery.exe" -PathType Leaf) {
	& "$install_path\DriverQuery.exe"
}

# Stop-Transcript
# ) *>&1 > $report_file_name
# ) >> $report_file_name
) 2>&1 >> $report_file_name

notepad $report_file_name

# SIG # Begin signature block
# MIIouAYJKoZIhvcNAQcCoIIoqTCCKKUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCV9+WGm55zppmo
# oK09Q134S4Mj/b21pLEGTEyL9O5zBqCCIbUwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqG
# SIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C0Cit
# eLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS
# 1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZM
# swEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBC
# Mo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3
# /hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7OhD26j
# q22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5
# OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo
# 7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05huzU
# tw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNYmtwm
# KwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NP
# TLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95RysQDK
# r2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvda
# qpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+
# lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnhOE7a
# brs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIhdXNS
# y0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV9zeK
# iwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/jwVYb
# KyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYHKi8Q
# xAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmCXBVm
# zGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCn
# HwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZWeE4w
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZC
# Lv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5oCG5Z69Aq
# EN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI+qiZP3ai
# xAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgS
# WG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y9
# 0ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9
# FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive4PuESaT8
# zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNUOCybMc/k
# xC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67WowuUs0Hd
# Y4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0
# ++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9icflf55W1zOEKAcJVA
# IXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOK
# MC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxrFbJblzCV
# P/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbR
# Wt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9EVh71SJel
# cEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv
# +xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUU
# Tnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0rbHXEu27o
# +Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9etE14jOQA
# zLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX7NbEdcof
# y0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMREUTgu+Oc
# a7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim6cjEzVSi
# LSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzCCB8MwggWr
# oAMCAQICEAZ11rWe8bCrMOXS4EbaJDEwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MTAeFw0yNDA3MjUwMDAwMDBaFw0yNzA2MDkyMzU5NTlaMIHLMRMwEQYLKwYBBAGC
# NzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMR0wGwYDVQQPDBRQ
# cml2YXRlIE9yZ2FuaXphdGlvbjEQMA4GA1UEBRMHNjM5NzU4ODELMAkGA1UEBhMC
# VVMxDzANBgNVBAgTBk9yZWdvbjESMBAGA1UEBxMJQmVhdmVydG9uMRowGAYDVQQK
# ExFObWFwIFNvZnR3YXJlIExMQzEaMBgGA1UEAxMRTm1hcCBTb2Z0d2FyZSBMTEMw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDoD32B1DtufyfFqdZxv5K1
# u06+KasIc0GruUoYmGkznSkoJp/4oUKoMctsd+RfhpE3WuAJKA0UhFatf4F82W2L
# 6s0JmAdh/dmdjOsonctPDaQDDuumH88ifz5Cco49Vp/iORl9ROzztTKtEmz/mhWq
# /GaAe6nWN6o6XUq0UYm4NdFcy1UCUTsAuEI7PFNrS/O8Q3QYYjdgMiMUL2aIHrF/
# aZ+UZ/ZsgpNmuNZniLoSaMzayQniAk5TQTq+IDOCXI+UvcyW8UZNel47Cup6p+0t
# rrVXn0AnnE2HmuFn/H8GSlSn9HTPioWQ5vnHjvt/T205bMayPCPHWioK187RDp0Y
# 2INQigH4eswbs7wz21RkQyvl5QQqtOE47GRnsltTYszhqFb+0cjc06Hli019vjji
# y5qaD3r4jeWGeOlIwpXb8afzXUvhOJ7YArPRvJgsInLq8TqNoEwAXO8h/6x+spK9
# OEvTPHJrt/1Gm21ekmvUFyjwsWEaI3M0Y2hYrU91OTIj2TLMhX2GPo8irzvcOUNv
# oxzrbQPItlX9Ovs00WigkvtDSzJQYMzGTeCzmcrK3LoCQl9WQzIEvUTsLJJkU+FU
# 5z4zUcFsBvAV1S58KJs1P+XwgxnidLpjw7SN/NGxE4lkOOioFVLRp4RN64Fk2QOT
# oeE4l4fXWf5bzwzfsA+czwIDAQABo4ICAjCCAf4wHwYDVR0jBBgwFoAUaDfg67Y7
# +F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFHu1WsUGAQKH/u+t5UY4reZm/xufMD0G
# A1UdIAQ2MDQwMgYFZ4EMAQMwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdp
# Y2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsG
# AQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0
# MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIBAHwAekesQiThjV0MenlfhxgH
# C4+9Wbri+kkmApzEZMvKN+9wxoPMF2JlX0qR+urJ3jBKQZMUitgHg1oIQ4nvJII3
# o3TCSNphIERto5wQpGhS6PwqWUwDHS3mwZ6w7mtNqLUVnOmUerW5d/gFk0rvEcy5
# j8G24Z6kE4Te4bvL7yyK9dJnCYZi+NcvgrmLGAvifz0CiUadJ8xpgfZ7wHU2kycn
# hsy7SQl8iGabag2w31zaBDRwTFeFQYncqow4c/+hcvdX7yh4RELAg575LGLKcxTW
# gErUoovDksh+xZKiB+SYFRNnfi9/KU2w9hCbWoDZ0E02QCLM4eCq8p3lX64HVsh8
# 0cFH5mMWilGM4t5enk3pmxw1DShCd8xb0V/Li6kvmu5s82MunouXL3rLOMjOTkQC
# sbJqlPfLCejs17gX7SLi5MH681IsI4RZsf1Ce158hO/jIUtkQiP2UDkpKMgVM2Jk
# lh6r2hcvCJjrSkLuqgM8TwrekGjn4/lksveIujwTqhwjaa/MrFgQ4WbCrurrtkiv
# KHZz/j38bQooWXt9L+XcRVL37h0BgAmGjraWfFc0jvCqhK9+f3423K7apay4cbQX
# KS1yeOwxSZ4AAVNY1eTcTygNZW7LoY/nrFue5VKHSv2/p7ZFIafvlivYtsFh8vTE
# lDS6TitAblSNuq7JtmS5MYIGWTCCBlUCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAGdda1nvGw
# qzDl0uBG2iQxMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEGcAzWBgsbo4RA93oZWY4cL
# yssYBI/22FNOP+LpG+x8MA0GCSqGSIb3DQEBAQUABIICAAE29lNOjhl4unPchkVW
# OsBe4EplTrmzzpkRd6+/VQ9at11Pmv1K5DEyU3xYqhqx7CyZ3N7G6hGVt1Jk8Fnh
# 4PMAXpbp3sv5TZSVSAmj0umb7BhlgeINKpsznfaLQaArHLSygkrDED38blWfVk98
# WRRi9/gvOF7+ImXnPetG5WwjMbwshQ8ZnzbaGCzYeLqXX0bybNlcNrQCZ+vWepft
# EmWa9S4hJH0F/Ayg/AnrcVMT6Fgwl8EKT65XMke1TFcDfhE3azM7t426Ybx+vIev
# UspS1hYMygA4P7hCS6xhbe1AjV0fGUu26X0zWVCHlKPRfZDVdMFkpj8bT1VVheGI
# UQ8nTqS6/2axTXl1AQAbLPyU9qqfyyhUusGSIC+2JpO4PTNEq9yfW1qNzagKjgxK
# qvCNN8JdUNHuEeqNGd9XwrGs3YJJUYTPVoQ1ErIS30MFDrqGM2XGV1JT1AikI6KX
# vu8+J7fDDm7uzEPj863gd8WH/BozvC86ntgUFRpDpTIfxh3S02uKzxk2S2hWyoke
# AyTYqXxbfNWG+E/IztdKOzbdxBM5MxIpeXkSCGUTsiieQ453mZ0mM7/5KocaBOlt
# aXeSlCOsToc3xv10PPgKz9ucJj9e7o6NW8K4nU1GX8ExTIpr0rRvmTcZZkRDTg3H
# eBV+52+O7NahLQeR4n+/Fjn6oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEB
# MH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBp
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAw
# OTIyMjA1OVowLwYJKoZIhvcNAQkEMSIEIDRJj4PBVc6RB28fzr44wvjjyexdrUSQ
# j/uTiAWWAZnTMA0GCSqGSIb3DQEBAQUABIICAE4C95HXZFZ0LtW8bwJazvgtljoI
# pEwhMUrv0JQA+IMo83SIoVqHSGFY5D0fIhqbIrUON9fo68lJanWfz14zr83zvvWO
# LKGB2yE65vyPgXURL53IIEekalQqlHfZBPvZU8/KiAIA35rolbSfYW5v1sAoosIc
# 64ppFR7Azw+7sqcDmqCcZvq+ezSdtnNK3wjoxxnb8JNjDCkqLkpYcZKN778O/UbX
# +b4eteOQQlOyrkILfMyqXHjShVh1PZy51uuRR+ru/ROX+gZpwDUs0S7MREv1/m48
# psjyjKPh6oGr2UG69uYlienRm3jtdJFa3301DZ2L0MGiSuOrlxu1ZJV9Dk0jpYrM
# tRNdW93JDJS5zZy05WALrrUf87W68uTfXo7FYY9F6kFCtqQncwpriI/+L99CwykC
# lxczV0IAraYXyfKvapGjQObzZfRvGdie6+eAXIlG7ogL6817xUz2EN8hEdCgrrEA
# 7hdsQO22VkjLumEVhEFjhZrEhzY6NAdN19z2bdaDuDRrBGYmmdA57mjs2GT2KQuP
# HIP37FX7ZfJcbfbTfcyMuv2rGayPZTSKwlTXX7zKr3WL6ZPHCgQbfpGjjmtj291W
# K4bKZiP1CbhSeIp8ehzPdzpa9M1N35DdZjodvsL+vaoHTwpezY1wvTVAYXF6zlQj
# Koy07hkMJwPQeH+8
# SIG # End signature block
