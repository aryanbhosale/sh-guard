$ErrorActionPreference = 'Stop'

$packageName = 'sh-guard'
$version = $env:chocolateyPackageVersion
$url64 = "https://github.com/aryanbhosale/sh-guard/releases/download/v$version/sh-guard-x86_64-pc-windows-msvc.zip"

$installDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Install-ChocolateyZipPackage -PackageName $packageName `
  -Url64bit $url64 `
  -UnzipLocation $installDir `
  -Checksum64 'bcdb4a8678e6f57ac3660784f168a78ff0e76f8b3e005090b612be089c5de49a' `
  -ChecksumType64 'sha256'
