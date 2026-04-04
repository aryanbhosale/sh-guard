$ErrorActionPreference = 'Stop'

$packageName = 'sh-guard'
$version = $env:chocolateyPackageVersion
$url64 = "https://github.com/aryanbhosale/sh-guard/releases/download/v$version/sh-guard-x86_64-pc-windows-msvc.tar.gz"

$installDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Install-ChocolateyZipPackage -PackageName $packageName `
  -Url64bit $url64 `
  -UnzipLocation $installDir `
  -Checksum64 '2d610b49a9ad7481471b2a287ed6ad3c4f7dd550ad100aa09a621174a8b3e1eb' `
  -ChecksumType64 'sha256'
