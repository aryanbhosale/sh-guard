$ErrorActionPreference = 'Stop'

$installDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
Remove-Item "$installDir\sh-guard.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "$installDir\sh-guard-mcp.exe" -Force -ErrorAction SilentlyContinue
