$ErrorActionPreference = 'Stop'

$packageName = 'sh-guard'
$version = $env:chocolateyPackageVersion
$url64 = "https://github.com/aryanbhosale/sh-guard/releases/download/v$version/sh-guard-x86_64-pc-windows-msvc.tar.gz"

$installDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Install-ChocolateyZipPackage -PackageName $packageName `
  -Url64bit $url64 `
  -UnzipLocation $installDir `
  -Checksum64 '10b10d2fc374c91bcb6c58a5299fae174ff8a82cad9264fabb9ff1cff48e71bc' `
  -ChecksumType64 'sha256'
