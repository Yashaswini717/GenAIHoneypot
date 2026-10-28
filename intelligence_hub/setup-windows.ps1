<#
.SYNOPSIS
Starts the intelligence hub on this Windows PC for a honeypot running on
another machine on the same network.

.DESCRIPTION
Run it from this folder, in PowerShell opened with "Run as administrator"
(the firewall rule needs it):

    powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1

It checks Docker Desktop, creates the shared Docker network, lets the
honeypot machine through Windows Firewall on TCP 8000 and 5173, starts the
stack and waits for the API to answer. At the end it prints the HUB_URL to
give the honeypot's sidecar.

Safe to run again, for example after either machine's IP address changes.

.PARAMETER HoneypotIp
The honeypot machine's LAN address. Only this address is let through the
firewall. Pass "LocalSubnet" to allow every machine on this network instead.
#>
param(
    [string]$HoneypotIp = "192.168.0.15"
)

$ruleName = "GenAI Honeypot - intelligence hub"
$composeFiles = @("-f", "docker-compose.yml", "-f", "docker-compose.windows.yml")

function Fail($message) {
    Write-Host ""
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

function Step($message) {
    Write-Host ""
    Write-Host "==> $message" -ForegroundColor Cyan
}

Set-Location -Path $PSScriptRoot

Step "Checking for administrator rights"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Open PowerShell with 'Run as administrator' and run this script again."
}

Step "Checking Docker Desktop"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "docker was not found. Install Docker Desktop (WSL 2 backend), start it, then retry."
}
$osType = docker info --format "{{.OSType}}" 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "Docker is installed but not running. Start Docker Desktop, wait for 'Engine running', then retry."
}
if ("$osType".Trim() -ne "linux") {
    Fail "Docker is in Windows-containers mode. Right-click the Docker tray icon and choose 'Switch to Linux containers'."
}
# docker-compose.windows.yml uses !override and !reset, which arrived in 2.24.
$composeVersion = docker compose version --short 2>$null
if ($LASTEXITCODE -ne 0 -or -not ("$composeVersion" -match '(\d+)\.(\d+)')) {
    Fail "docker compose is not available. Update Docker Desktop."
}
if ([int]$Matches[1] -lt 2 -or ([int]$Matches[1] -eq 2 -and [int]$Matches[2] -lt 24)) {
    Fail "docker compose $composeVersion is too old; 2.24 or newer is needed. Update Docker Desktop."
}
Write-Host "Docker is running Linux containers, compose $composeVersion."

Step "Checking .env"
if (-not (Test-Path ".env")) {
    Fail ".env is missing. Use the hub .env from the honeypot machine; its HMAC_SECRET must match the honeypot's."
}
$secretLine = Select-String -Path ".env" -Pattern '^HMAC_SECRET=(.+)$' | Select-Object -First 1
if (-not $secretLine) {
    Fail ".env has no HMAC_SECRET line."
}
$secret = $secretLine.Matches[0].Groups[1].Value.Trim()
if ($secret -eq "dev") {
    Fail "HMAC_SECRET is 'dev', which switches signature checks off. Copy the real value from the honeypot's .env."
}
Write-Host "HMAC_SECRET is set ($($secret.Length) characters)."

Step "Creating the honeypot-telemetry Docker network"
# The base compose file attaches the backend to it as an external network.
docker network inspect honeypot-telemetry 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    docker network create honeypot-telemetry | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "Could not create the honeypot-telemetry network." }
    Write-Host "Created."
} else {
    Write-Host "Already exists."
}

Step "Letting $HoneypotIp through Windows Firewall on TCP 8000 and 5173"
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP `
    -LocalPort 8000,5173 -RemoteAddress $HoneypotIp -Profile Any | Out-Null
if (-not $?) { Fail "Could not create the firewall rule." }
Write-Host "Rule '$ruleName' is in place."

# Block rules beat allow rules in Windows Firewall. Pressing Cancel on Docker
# Desktop's first network prompt leaves exactly such a rule behind, and then
# nothing from the LAN reaches a published port, whatever is allowed above.
$blocking = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "docker" }
if ($blocking) {
    Write-Host "WARNING: these inbound rules block Docker and override the rule above:" -ForegroundColor Yellow
    $blocking | ForEach-Object { Write-Host "  $($_.DisplayName)" -ForegroundColor Yellow }
    Write-Host "Disable them with:" -ForegroundColor Yellow
    Write-Host "  Get-NetFirewallRule -Direction Inbound -Action Block | Where-Object DisplayName -match 'docker' | Disable-NetFirewallRule" -ForegroundColor Yellow
}

Step "Starting the hub (the first run downloads about 2 GB and takes several minutes)"
docker compose @composeFiles up -d --build
if ($LASTEXITCODE -ne 0) { Fail "docker compose failed; the reason is above." }

Step "Waiting for http://localhost:8000/health"
$deadline = (Get-Date).AddMinutes(6)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) { $healthy = $true; break }
    } catch { }
    Start-Sleep -Seconds 5
}
if (-not $healthy) {
    Fail "The API did not answer within 6 minutes. See: docker compose -f docker-compose.yml -f docker-compose.windows.yml logs backend"
}

$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.InterfaceAlias -notmatch "vEthernet|WSL|Loopback|Docker"
    } |
    Select-Object -ExpandProperty IPAddress)

Write-Host ""
Write-Host "The hub is running." -ForegroundColor Green
Write-Host "  Dashboard on this PC:  http://localhost:5173"
foreach ($ip in $addresses) {
    Write-Host "  Dashboard from the LAN: http://${ip}:5173"
}
Write-Host ""
Write-Host "On the honeypot machine, set this line in honeypot-ecosystem/.env"
Write-Host "(use the address on the same network as the honeypot):"
foreach ($ip in $addresses) {
    Write-Host "  HUB_URL=http://${ip}:8000" -ForegroundColor Green
}
Write-Host "then recreate the sidecar there:  docker compose up -d sidecar"
Write-Host ""
Write-Host "Stop the hub later with (data is kept):"
Write-Host "  docker compose -f docker-compose.yml -f docker-compose.windows.yml down"
