#
# Deploy.ps1 - The deployment script for Npcap
# Author: Yang Luo
# Date: March 23, 2016
#

###########################################################
# The variables about deployment.

# Set the script path to be the current directory
$script_dir =  (Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path) + "\"
cd $script_dir

$file_name_array = @()
$from_path_array = @()
$to_path_array = @()

$cert_sign_tool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
$cert_ms_cross_cert = "C:\DigiCert High Assurance EV Root CA.crt"
$cert_digi_root_ev = "C:\digicert-ev-code-signing.cer"
$cert_hash_sha1_digi = "67cdca7703a01b25e6e0426072ec08b0046eb5f8"
$cert_hash_sha256_digi = "928101b5d0631c8e1ada651478e41afaac798b4c"
$cert_hash_ev = "ec2ae51775f3252541b266c40528daa77baa072f"
$cert_hash_modern = $cert_hash_ev

# The DigiCert timestamp server (also for RFC3161)
$cert_timestamp_server_DigiCert = "http://timestamp.digicert.com"

$has_timestamp = 1
$header_name = "..\version.h"

$driver_name_array = "npf", "npcap"
$vs_config_mode_array = "(WinPcap Mode)", ""
$deploy_folder_mode_array = "_winpcap", ""

function get_version()
{
    $token = [Management.Automation.PSParser]::Tokenize((Get-Content $header_name), [ref]$null)
    for ($i = 0; $i -lt $token.Count; $i ++)
    {
        if ($token[$i].Content -eq "WINPCAP_VER_STRING")
        {
            return $token[$i + 1].Content
        }
    }
	Write-Warning "Error: no valid version found, use 0.00 instead."
    return "0.00"
}

$version_no = get_version
$version_no = $version_no.Replace(" r", "-r")

###########################################################
# The variables about generating the installer.
$has_file_updated = 0
$install_script = "Npcap-for-nmap.nsi"
$installer_name = "npcap-{0}.exe" -f $version_no
$nsis_compiler_tool = "C:\Program Files (x86)\NSIS\makensis.exe"

###########################################################
# The variables about generating the symbols.
$symbols_zip_name = $installer_name.Replace(".exe", "-DebugSymbols.zip")
$symbols_folder = ".\npcap-DebugSymbols\"

###########################################################
# The npf/npcap driver.
$driver_filename_array = "{0}.cat", "{0}.inf", "{0}_wfp.inf", "{0}.sys"
$driver_init_from_path_array = 
	"..\packetWin7\npf\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\x64\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\Win7 Release{0}\npf Package\",
	"..\packetWin7\npf\x64\Win7 Release{0}\npf Package\"
$driver_init_to_path_array = 
	".\win8_below{0}\x86\",
	".\win8_below{0}\x64\",
    ".\win10{0}\x86\",
    ".\win10{0}\x64\"

###########################################################
# Common intial to_path_array
$init_to_path_array =
".\win8_below{0}\x86\",
".\win8_below{0}\x64\"

###########################################################
# wpcap.dll
$wpcap_filename = "wpcap.dll"
$wpcap_init_from_path_array =
"..\wpcap\libpcap\Win32\Prj\Release\",
"..\wpcap\libpcap\Win32\Prj\x64\Release\"

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
# NpcapHelper.exe
$npcaphelper_filename = "NpcapHelper.exe"
$npcaphelper_init_from_path_array =
"..\packetWin7\Helper\release\",
"..\packetWin7\Helper\x64\release\"

###########################################################
# WlanHelper.exe
$wlanhelper_filename = "WlanHelper.exe"
$wlanhelper_init_from_path_array =
"..\packetWin7\WlanHelper\release\",
"..\packetWin7\WlanHelper\x64\release\"

# http://stackoverflow.com/a/13302548/1183387
# Author: @Eld
function ZipFiles( $zipfilename, $sourcedir )
{
    write-host ("Zipping " + $sourcedir + " to " + $zipfilename)
       Add-Type -Assembly System.IO.Compression.FileSystem
          $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
             [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir,
                     $zipfilename, $compressionLevel, $false)
}


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

		for ($j = 0; $j -lt 4; $j ++)
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

	# NpcapHelper.exe
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


function copy_and_sign($file_name, $from_path, $to_path, [ref]$arr_to_sign)
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
    if ($file_name -notmatch ".inf" -and $file_name -notmatch ".pdb")
    {
        # Don't sign the .inf or .pdb
        $arr_to_sign.value += ($to_path + $file_name)
    }

	return 1
}

function sign_driver_modern($file_path_name)
{
	if ($has_timestamp)
	{
		&$cert_sign_tool "sign", "/ac", $cert_digi_root_ev, "/sha1", $cert_hash_modern, "/fd", "sha256", "/tr", $cert_timestamp_server_DigiCert, "/td", "sha256", $file_path_name
	}
	else
	{
		&$cert_sign_tool "sign", "/ac", $cert_digi_root_ev, "/sha1", $cert_hash_modern, "/fd", "sha256", $file_path_name
	}
}

function dual_sign_driver_arr([ref]$file_path_name)
{
	if ($has_timestamp)
	{
        &$cert_sign_tool ("sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_sha1_digi, "/fd", "sha1", "/t", $cert_timestamp_server_DigiCert) $file_path_name.value
		&$cert_sign_tool ("sign", "/ac", $cert_ms_cross_cert, "/as", "/sha1", $cert_hash_modern, "/fd", "sha256", "/tr", $cert_timestamp_server_DigiCert, "/td", "sha256") $file_path_name.value
	} 
	else
	{
        &$cert_sign_tool ("sign", "/ac", $cert_ms_cross_cert, "/sha1", $cert_hash_sha1_digi, "/fd", "sha1") $file_path_name.value
		&$cert_sign_tool ("sign", "/ac", $cert_ms_cross_cert, "/as", "/sha1", $cert_hash_modern, "/fd", "sha256") $file_path_name.value
	}
}

function generate_installer($install_script, $installer_name)
{
	$signargs = "sign /ac $cert_digi_root_ev /sha1 $cert_hash_modern /fd sha256 /tr $cert_timestamp_server_DigiCert /td sha256"
	&$nsis_compiler_tool "`"/XOutFile $installer_name`"" "`"/DSIGNCMD=$cert_sign_tool`"" "`"/DSIGNARGS=$signargs`"" $install_script

	sign_driver_modern $installer_name
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
    $arr_to_sign = @()
	for ($i = 0; $i -lt $file_name_array.Count; $i ++)
	{
		$res = copy_and_sign $file_name_array[$i] $from_path_array[$i] $to_path_array[$i] ([ref]$arr_to_sign)
		$has_file_updated += $res
		# echo ($file_name_array[$i] + ", " + $from_path_array[$i] + ", " + $to_path_array[$i])
	}
    if ($has_file_updated -gt 0)
    {
        dual_sign_driver_arr([ref]$arr_to_sign)
    }
    Write-Host ("Info: Updated file count: " + $has_file_updated)
    return $res
}

if ($args.count -eq 0)
{
	$has_file_updated = do_deploy
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
elseif ($args.count -eq 1)
{
	if ($args[0] -eq "deploy")
	{
		do_deploy
	}
	elseif ($args[0] -eq "deploy-no_timestamp")
	{
		$has_timestamp = 0
		do_deploy
	}
	elseif ($args[0] -eq "debug-deploy")
	{
		$driver_init_from_path_array = $driver_init_from_path_array.replace("Release", "Debug")
		$packet_init_from_path_array = $packet_init_from_path_array.replace("Release", "Debug")
		$installer_name = $installer_name.replace(".exe", "-debug.exe")
		do_deploy
	}
	elseif ($args[0] -eq "debug-deploy-no_timestamp")
	{
		$has_timestamp = 0
		$driver_init_from_path_array = $driver_init_from_path_array.replace("Release", "Debug")
		$packet_init_from_path_array = $packet_init_from_path_array.replace("Release", "Debug")
		$installer_name = $installer_name.replace(".exe", "-debug.exe")
		do_deploy
	}
	elseif ($args[0] -eq "deploy-symbols")
	{
		$driver_filename_array = , "{0}.pdb"
		$driver_init_from_path_array = $driver_init_from_path_array.replace("npf Package\", "")
		$driver_init_to_path_array = $driver_init_to_path_array.replace(".\", $symbols_folder)

		$init_to_path_array = $init_to_path_array.replace(".\", $symbols_folder)

		$wpcap_filename = $wpcap_filename.replace(".dll", ".pdb")
		$packet_filename = $packet_filename.replace(".dll", ".pdb")
		$npfinstall_filename = $npfinstall_filename.replace(".exe", ".pdb")
		$npcaphelper_filename = $npcaphelper_filename.replace(".exe", ".pdb")
		$wlanhelper_filename = $wlanhelper_filename.replace(".exe", ".pdb")

        $has_file_updated = do_deploy 0
		$symbols_zip_name = ".\" + $symbols_zip_name
		if ((Test-Path $symbols_zip_name) -and ($has_file_updated -eq 0))
		{
			Write-Host ("Info: no deployment change, symbols not generated.")
			return
		}
		else
		{
            # Requires full path
            ZipFiles ($script_dir + $symbols_zip_name) ($script_dir + $symbols_folder)
		}
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

