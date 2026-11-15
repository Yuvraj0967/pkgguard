<#
.SYNOPSIS
  Stops what start-demo.ps1 started (only the executables in this project's bin folder).
#>
$bin = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin'
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($bin, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
  Write-Host "stopping $($_.ProcessName) (pid $($_.Id))"
  Stop-Process -Id $_.Id -Force
}
