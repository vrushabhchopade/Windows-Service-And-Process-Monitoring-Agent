# PowerShell Windows Service Installer script for Stitch Sentinel Agent

$ServiceName = "StitchSentinelAgent"
$DisplayName = "Stitch Sentinel Endpoint EDR Agent"
$Description = "Continuously monitors process parentage, startup services, event logs, and system health for SOC threat analysis."
$ExecutablePath = Join-Path (Get-Location) "dist\stitch_agent.exe"

if (-not (Test-Path $ExecutablePath)) {
    Write-Warning "[-] Compiled executable not found at $ExecutablePath. Run installer/build.bat first."
    Exit
}

Write-Output "[*] Registering Windows Service: $ServiceName"

# Check if service already exists
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Service) {
    Write-Output "[*] Stopping existing service..."
    Stop-Service -Name $ServiceName -Force
    Write-Output "[*] Removing existing service..."
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 2
}

# Create Windows Service
New-Service -Name $ServiceName -BinaryPathName "$ExecutablePath --service" -DisplayName $DisplayName -Description $Description -StartupType Automatic

# Set Recovery Options on failure: restart service
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/20000/restart/60000

Write-Output "[+] Windows Service registered successfully!"
Write-Output "[*] Starting $ServiceName..."
Start-Service -Name $ServiceName
Get-Service -Name $ServiceName
