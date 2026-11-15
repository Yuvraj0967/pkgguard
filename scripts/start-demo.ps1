<#
.SYNOPSIS
  Starts the genuine demo stack: a real Bifrost gateway, pkgguard's proxy in front of it, and the dashboard.

.DESCRIPTION
    agent -> pkgguard proxy (127.0.0.1:8089) -> Bifrost (127.0.0.1:8081) -> real model API

  Reads GEMINI_API_KEY (or any key Bifrost's config references) from .env in the project root; the key
  is never printed. If bin\bifrost-http.exe exists it starts that gateway with examples\bifrost-gemini.config.json.
  To use a gateway you already run, pass -Upstream and no gateway is started.

.EXAMPLE
  .\scripts\start-demo.ps1
  .\scripts\start-demo.ps1 -Upstream http://127.0.0.1:8080
#>
param(
  [string]$Upstream = "",
  [int]$GatewayPort = 8081,
  [int]$ProxyPort = 8089,
  [int]$DashboardPort = 8099
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null

# --- load .env (names only are ever shown) ---
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
  Get-Content $envFile | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$') { Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2] }
  }
}

# --- gateway ---
if (-not $Upstream) {
  $gw = Join-Path $bin 'bifrost-http.exe'
  if (-not (Test-Path $gw)) { throw "No gateway: $gw not found. Run your own Bifrost and pass -Upstream http://127.0.0.1:8080" }
  if (-not $env:GEMINI_API_KEY) { throw "GEMINI_API_KEY is not set (put it in $envFile)" }
  $app = Join-Path $bin 'bf-app'
  New-Item -ItemType Directory -Force $app | Out-Null
  Copy-Item (Join-Path $root 'examples\bifrost-gemini.config.json') (Join-Path $app 'config.json') -Force
  # quote the path: Start-Process does not, and the project folder may contain spaces
  Start-Process -FilePath $gw -ArgumentList @('-app-dir', "`"$app`"", '-port', $GatewayPort, '-log-style', 'pretty') `
    -RedirectStandardOutput (Join-Path $bin 'gateway.log') -RedirectStandardError (Join-Path $bin 'gateway.err.log') -WindowStyle Hidden
  $Upstream = "http://127.0.0.1:$GatewayPort"
  Write-Host "starting Bifrost on $Upstream ..."
  $ok = $false
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 750
    try { if ((Invoke-WebRequest -UseBasicParsing "$Upstream/health" -TimeoutSec 2).StatusCode -eq 200) { $ok = $true; break } } catch {}
  }
  if (-not $ok) { throw "Bifrost did not become healthy; see $bin\gateway.log" }
}

# --- pkgguard ---
$pg = Join-Path $bin 'pkgguard.exe'
if (-not (Test-Path $pg)) {
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "bin\pkgguard.exe is missing and Go is not installed to build it" }
  Push-Location $root; go build -o $pg ./cmd/pkgguard; Pop-Location
}
$plog = Join-Path $bin 'proxy.log'
Remove-Item $plog -ErrorAction SilentlyContinue
Start-Process -FilePath $pg -ArgumentList @('proxy', '-upstream', $Upstream, '-listen', "127.0.0.1:$ProxyPort", '-dashboard', "127.0.0.1:$DashboardPort") `
  -RedirectStandardError $plog -RedirectStandardOutput (Join-Path $bin 'proxy.out.log') -WindowStyle Hidden
$dash = $null
for ($i = 0; $i -lt 20 -and -not $dash; $i++) {
  Start-Sleep -Milliseconds 500
  if (Test-Path $plog) { $m = Select-String -Path $plog -Pattern 'dashboard: (http\S+)' | Select-Object -First 1; if ($m) { $dash = $m.Matches[0].Groups[1].Value } }
}
if (-not $dash) { throw "pkgguard proxy did not start; see $plog" }

Write-Host ""
Write-Host "READY" -ForegroundColor Green
Write-Host "  gateway   $Upstream"
Write-Host "  proxy     http://127.0.0.1:$ProxyPort/v1   (point the agent here)"
Write-Host "  dashboard $dash"
Write-Host ""
Write-Host "try:  $pg agent -base http://127.0.0.1:$ProxyPort/v1 -model gemini/gemini-3.1-flash-lite `"Set up an Express server with request logging`""
Write-Host "stop: .\scripts\stop-demo.ps1"
