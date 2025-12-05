param(
    [string]$ManifestPath = ".\manifest.txt",
    [string]$InstallRoot  = "C:\Program Files\Npcap",
    [switch]$Uninstall
)

$Is64OS  = [Environment]::Is64BitOperatingSystem
$Is64PS  = [Environment]::Is64BitProcess

$IsARM64 = $false
if ($Is64OS) {
	$IsARM64 = (Get-CimInstance Win32_OperatingSystem -Property OSArchitecture).OSArchitecture.StartsWith("ARM")
}

$BadCondition = "Missing items"
if ($Uninstall) {
	$BadCondition = "Remaining items"
}

$System32 = "${env:SystemRoot}\System32"
$System64 = $null
if ($Is64OS) {
	if ($Is64PS) {
		$System64 = "${env:SystemRoot}\SysWoW64"
	}
	else {
		$System64 = "${env:SystemRoot}\Sysnative"
	}
}

# Read manifest
$manifest = Get-Content $ManifestPath |
    ForEach-Object {
	    $_ = $_.Trim()
	    if ($IsARM64 -and $_.EndsWith(".dll")) {
		    $_.Replace(".dll", "_arm64.dll")
		    $_.Replace(".dll", "_x64.dll")
	    }
	    $_
	    } |
    Where-Object { $_ -and -not $_.StartsWith("#") }

$requiredPaths = foreach ($line in $manifest) {
    # Split at first backslash: token + remainder
    if ($line -notmatch '^(?<root>[^\\]+)\\(?<rest>.+)$') {
        throw "Invalid manifest line: $line"
    }

    $rootToken = $Matches.root
    $relative  = $Matches.rest

    if ($rootToken -eq "INSTDIR") {
        Join-Path $InstallRoot $relative
    }
    elseif ($rootToken -eq "SYSDIR") {
        Join-Path $System32 $relative
	if (-not $relative.EndsWith(".sys")) {
		Join-Path $System32 "Npcap\$relative"
	}
	if ($Is64OS) {
		Join-Path $System64 $relative
		if (-not $relative.EndsWith(".sys")) {
			Join-Path $System64 "Npcap\$relative"
		}
	}
    }
    else {
        throw "Unknown root token '$rootToken' in manifest line: $line"
    }
}

$results = @()

foreach ($path in $requiredPaths) {
    $exists = Test-Path $path

    $results += [pscustomobject]@{
        Path      = $path
        Exists    = $exists
    }
}
Write-Information -InformationAction Continue ($results | Format-Table | Out-String)

# Report missing
$missing = $results | Where-Object { $_.Exists -eq $Uninstall }

Write-Host "=== Manifest Verification Report ==="
Write-Host ""

if ($missing) {
    Write-Host "${BadCondition}:"
    $missing | Format-Table -AutoSize
    throw "Manifest validation failed: ${BadCondition}"
} else {
    Write-Host "Passed: No ${BadCondition}."
}

# Optional: Check for unexpected files in install root
$expectedSet = $results | Where-Object { $_.Exists } | ForEach-Object { $_.Path.ToLowerInvariant() }
$actual = foreach ($path in ($InstallRoot, "$System32\Npcap")) {
	if (Test-Path $path) {
		Get-ChildItem -Recurse $path | Select-Object -ExpandProperty FullName
	}
}
$actualSet = $actual | ForEach-Object { $_.ToLowerInvariant() }

$unexpected = $actualSet | Where-Object { -not $_.EndsWith(".log") -and $expectedSet -notcontains $_ }

if ($unexpected) {
    Write-Host ""
    Write-Host "Unexpected items present:"
    $unexpected | Format-Table -AutoSize
    throw "Manifest validation failed: unexpected items"
} else {
    Write-Host "No unexpected items are present."
}
