#
# Deploy.ps1 - The deployment script for Npcap
# Author: Yang Luo
# Date: March 23, 2016
#

###########################################################
# The variables about deployment.
$file_name_array = @()
$from_path_array = @()
$to_path_array = @()

$cert_sign_tool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
$cert_ms_cross_cert = "C:\DigiCert High Assurance EV Root CA.crt"
$cert_hash_vista = "67cdca7703a01b25e6e0426072ec08b0046eb5f8"
$cert_hash_win7_above = "928101b5d0631c8e1ada651478e41afaac798b4c"
$cert_timestamp_server = "http://timestamp.digicert.com"

$driver_name_array = "npf", "npcap"
$vs_config_mode_array = "(WinPcap Mode)", ""
$deploy_folder_mode_array = "_winpcap", ""

###########################################################
# The variables about generating the installer.
$has_file_updated = 0
$install_script = "NPcap-for-nmap.nsi"
$installer_name = "npcap-0.07.exe"
$nsis_compiler_tool = "C:\Program Files (x86)\NSIS\makensis.exe"

###########################################################
# The variables about generating the symbols.
$archive_7zip_tool = "C:\Program Files\7-Zip\7z.exe"
$symbols_zip_name = $installer_name.Replace(".exe", "-DebugSymbols.zip")
$symbols_folder = ".\npcap-DebugSymbols\"

###########################################################
# The npf/npcap driver.
$driver_filename_array = "{0}.cat", "{0}.inf", "{0}_wfp.inf", "{0}_wifi.inf", "{0}.sys"
$driver_init_from_path_array = 
	"..\packetWin7\npf\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\x64\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\x64\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\Vista Release{0}\npf Package\",
	"..\packetWin7\npf\x64\Vista Release{0}\npf Package\"
$driver_init_to_path_array = 
	".\win8_above{0}\x86\",
	".\win8_above{0}\x64\",
	".\win7{0}\x86\",
	".\win7{0}\x64\",
	".\vista{0}\x86\",
	".\vista{0}\x64\"

###########################################################
# Common intial to_path_array
$init_to_path_array =
".\win8_above{0}\x86\",
".\win8_above{0}\x64\"

###########################################################
# wpcap.dll
$wpcap_filename = "wpcap.dll"
$wpcap_init_from_path_array =
"..\wpcap\PRJ\Release No AirPcap\x86\",
"..\wpcap\PRJ\Release No AirPcap\x64\"

###########################################################
# Packet.dll
$packet_filename = "Packet.dll"
$packet_init_from_path_array =
"..\packetWin7\Dll\Project\Release No NetMon and AirPcap{0}\",
"..\packetWin7\Dll\Project\x64\Release No NetMon and AirPcap{0}\"

###########################################################
# NPFInstall.exe
$npfinstall_filename = "NPFInstall.exe"
$npfinstall_init_from_path_array =
"..\packetWin7\NPFInstall\Release{0}\",
"..\packetWin7\NPFInstall\x64\Release{0}\"

###########################################################
# NPcapHelper.exe
$npcaphelper_filename = "NPcapHelper.exe"
$npcaphelper_init_from_path_array =
"..\packetWin7\Helper\release\",
"..\packetWin7\Helper\x64\release\"

###########################################################
# WlanHelper.exe
$wlanhelper_filename = "WlanHelper.exe"
$wlanhelper_init_from_path_array =
"..\packetWin7\WlanHelper\release\",
"..\packetWin7\WlanHelper\x64\release\"


function initialize_list([ref]$file_name_array, [ref]$from_path_array, [ref]$to_path_array)
{
	$my_file_name_array = @()
	$my_from_path_array = @()
	$my_to_path_array = @()

	# The npf/npcap driver.
	for ($i = 0; $i -lt 2; $i ++)
	{
		$driver_name = $driver_name_array[$i]
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 6; $j ++)
		{
			foreach ($filename in $driver_filename_array)
			{
				$my_file_name_array += $filename -f $driver_name
				$my_from_path_array += $driver_init_from_path_array[$j] -f $vs_config_mode
				$my_to_path_array += $driver_init_to_path_array[$j] -f $deploy_folder_mode
			}
		}
	}
	
	# wpcap.dll
	for ($i = 0; $i -lt 2; $i ++)
	{
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 2; $j ++)
		{
			$my_file_name_array += $wpcap_filename
			$my_from_path_array += $wpcap_init_from_path_array[$j] -f $vs_config_mode
			$my_to_path_array += $init_to_path_array[$j] -f $deploy_folder_mode
		}
	}

	# Packet.dll
	for ($i = 0; $i -lt 2; $i ++)
	{
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 2; $j ++)
		{
			$my_file_name_array += $packet_filename
			$my_from_path_array += $packet_init_from_path_array[$j] -f $vs_config_mode
			$my_to_path_array += $init_to_path_array[$j] -f $deploy_folder_mode
		}
	}

	# NPFInstall.exe
	for ($i = 0; $i -lt 2; $i ++)
	{
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 2; $j ++)
		{
			$my_file_name_array += $npfinstall_filename
			$my_from_path_array += $npfinstall_init_from_path_array[$j] -f $vs_config_mode
			$my_to_path_array += $init_to_path_array[$j] -f $deploy_folder_mode
		}
	}

	# NPcapHelper.exe
	for ($i = 0; $i -lt 2; $i ++)
	{
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 2; $j ++)
		{
			$my_file_name_array += $npcaphelper_filename
			$my_from_path_array += $npcaphelper_init_from_path_array[$j] -f $vs_config_mode
			$my_to_path_array += $init_to_path_array[$j] -f $deploy_folder_mode
		}
	}

	# WlanHelper.exe
	for ($i = 0; $i -lt 2; $i ++)
	{
		$vs_config_mode = $vs_config_mode_array[$i]
		$deploy_folder_mode = $deploy_folder_mode_array[$i]

		for ($j = 0; $j -lt 2; $j ++)
		{
			$my_file_name_array += $wlanhelper_filename
			$my_from_path_array += $wlanhelper_init_from_path_array[$j] -f $vs_config_mode
			$my_to_path_array += $init_to_path_array[$j] -f $deploy_folder_mode
		}
	}
	
	$file_name_array.value = $my_file_name_array
	$from_path_array.value = $my_from_path_array
	$to_path_array.value = $my_to_path_array
}

function copy_and_sign($file_name, $from_path, $to_path)
{
	if (!(Test-Path ($from_path + $file_name)))
	{
		Write-Host ("Error: source path not exist, path = " + $from_path + $file_name)
		return 0
	}
	if (Test-Path ($to_path + $file_name))
	{
		if ((Get-Item ($from_path + $file_name)).LastWriteTime -le (Get-Item ($to_path + $file_name)).LastWriteTime)
		{
			Write-Host ("Info: source path is not modified, stop deploy it, source path = " + $from_path + $file_name)
			return 0
		}
	}

	if (!(Test-Path -path $to_path))
	{
		$null = New-Item $to_path -Type Directory
	}
	Copy-Item ($from_path + $file_name) $to_path
	Write-Host ("Info: copy source path to deployment folder, source path = " + $from_path + $file_name)

	if ($file_name -match ".sys" -or $file_name -match ".cat")
	{
		if ($to_path -match ".\win8_above")
		{
			$null = sign_driver_sha256 ($to_path + $file_name)
		}
		else
		{
			$null = sign_driver_sha1 ($to_path + $file_name)
		}
	}
	elseif ($file_name -match ".inf" -or $file_name -match ".pdb")
	{

	}
	else
	{
		$null = sign_file_sha1 ($to_path + $file_name)
		$null = sign_file_sha256 ($to_path + $file_name)
	}

	return 1
}

function sign_driver_sha1($file_path_name)
{
	&$cert_sign_tool "sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_vista, "/fd", "sha1", "/t", $cert_timestamp_server, $file_path_name
}

function sign_driver_sha256($file_path_name)
{
	&$cert_sign_tool "sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_win7_above, "/fd", "sha256", "/tr", $cert_timestamp_server, "/td", "sha256", $file_path_name
}

function sign_file_sha1($file_path_name)
{
	&$cert_sign_tool "sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_win7_above, "/fd", "sha1", "/t", $cert_timestamp_server, $file_path_name
}

function sign_file_sha256($file_path_name)
{
	&$cert_sign_tool "sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_win7_above, "/as", "/fd", "sha256", "/tr", $cert_timestamp_server, "/td", "sha256", $file_path_name
}

function generate_installer($install_script, $installer_name)
{
	&$nsis_compiler_tool $install_script
	sign_driver_sha1 $installer_name
	sign_file_sha256 $installer_name
}

function generate_symbols($symbols_folder, $symbols_zip_name)
{
	&$archive_7zip_tool "a" $symbols_zip_name $symbols_folder
}

function do_deploy($installer_or_symbols = 1)
{
	if ($installer_or_symbols)
	{
		Write-Host ("Info: start deploy installer now.")
	}
	else
	{
		Write-Host ("Info: start deploy symbols now.")
	}
	
	initialize_list ([ref]$file_name_array) ([ref]$from_path_array) ([ref]$to_path_array)

	$has_file_updated = 0
	for ($i = 0; $i -lt $file_name_array.Count; $i ++)
	{
		$res = copy_and_sign $file_name_array[$i] $from_path_array[$i] $to_path_array[$i]
		$has_file_updated += $res
		# echo ($file_name_array[$i] + ", " + $from_path_array[$i] + ", " + $to_path_array[$i])
	}
	Write-Host ("Info: Updated file count: " + $has_file_updated)

	if ($installer_or_symbols)
	{
		$install_script = ".\" + $install_script
		$installer_name = ".\" + $installer_name
		if ((Test-Path $installer_name) -and ($has_file_updated -eq 0))
		{
			Write-Host ("Info: no deployment change, installer not generated.")
			return
		}
		else
		{
			generate_installer (".\" + $install_script) (".\" + $installer_name)
		}
	}
	else
	{
		$symbols_zip_name = ".\" + $symbols_zip_name
		if ((Test-Path $symbols_zip_name) -and ($has_file_updated -eq 0))
		{
			Write-Host ("Info: no deployment change, symbols not generated.")
			return
		}
		else
		{
			generate_symbols ($symbols_folder + "*") $symbols_zip_name
		}
	}
}

if ($args.count -eq 0)
{
	do_deploy
}
elseif ($args.count -eq 1)
{
	if ($args[0] -eq "deploy")
	{
		do_deploy
	}
	elseif ($args[0] -eq "debug-deploy")
	{
		$driver_init_from_path_array = $driver_init_from_path_array.replace("Release", "Debug")
		do_deploy
	}
	elseif ($args[0] -eq "deploy-symbols")
	{
		$driver_filename_array = , "{0}.pdb"
		$driver_init_from_path_array = $driver_init_from_path_array.replace("npf Package\", "")
		$driver_init_to_path_array = $driver_init_to_path_array.replace(".\", $symbols_folder)

		$init_to_path_array = $init_to_path_array.replace(".\", $symbols_folder)

		$packet_filename = $packet_filename.replace(".dll", ".pdb")
		$npfinstall_filename = $npfinstall_filename.replace(".exe", ".pdb")
		$npcaphelper_filename = $npcaphelper_filename.replace(".exe", ".pdb")
		$wlanhelper_filename = $wlanhelper_filename.replace(".exe", ".pdb")
		$wpcap_filename = $wpcap_filename.replace(".dll", ".pdb")

		$wpcap_init_to_path_array = $wpcap_init_to_path_array.replace(".\", $symbols_folder)

		do_deploy 0
	}
	elseif ($args[0] -eq "installer")
	{
		generate_installer (".\" + $install_script) (".\" + $installer_name) 0
	}
}
else
{
	Write-Warning "Error: too many parameters."
}

