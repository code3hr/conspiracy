# CyxWiz End-to-End Demo
# ========================
# This script demonstrates the CyxWiz mesh network:
# 1. Starts a bootstrap server
# 2. Launches 3 nodes that discover each other
# 3. Nodes form a mesh and run consensus

$ErrorActionPreference = "Stop"

$BUILD_DIR = "$PSScriptRoot\..\build-release\Release"
$BOOTSTRAP = "$BUILD_DIR\cyxwiz-bootstrap.exe"
$DAEMON = "$BUILD_DIR\cyxwizd.exe"

# Check if executables exist
if (-not (Test-Path $BOOTSTRAP)) {
    Write-Host "ERROR: Bootstrap not found. Run: cmake --build build-release --config Release" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $DAEMON)) {
    Write-Host "ERROR: Daemon not found. Run: cmake --build build-release --config Release" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "       CyxWiz End-to-End Demo" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  This demo will:" -ForegroundColor White
Write-Host "  1. Start a bootstrap server on port 7777" -ForegroundColor Gray
Write-Host "  2. Launch 3 nodes that connect via UDP" -ForegroundColor Gray
Write-Host "  3. Nodes will discover each other" -ForegroundColor Gray
Write-Host "  4. After 30s, consensus validation will trigger" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C in any window to stop that component." -ForegroundColor Yellow
Write-Host ""

# Start bootstrap server
Write-Host "[1/4] Starting bootstrap server..." -ForegroundColor Green
Start-Process -FilePath $BOOTSTRAP -ArgumentList "7777" -WindowStyle Normal

Start-Sleep -Seconds 2

# Start 3 nodes
$env:CYXWIZ_BOOTSTRAP = "127.0.0.1:7777"

Write-Host "[2/4] Starting Node 1..." -ForegroundColor Green
Start-Process -FilePath $DAEMON -WindowStyle Normal

Start-Sleep -Seconds 1

Write-Host "[3/4] Starting Node 2..." -ForegroundColor Green
Start-Process -FilePath $DAEMON -WindowStyle Normal

Start-Sleep -Seconds 1

Write-Host "[4/4] Starting Node 3..." -ForegroundColor Green
Start-Process -FilePath $DAEMON -WindowStyle Normal

Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "       Demo Running!" -ForegroundColor Green
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Watch the windows for:" -ForegroundColor White
Write-Host "  - 'Registered' messages in bootstrap" -ForegroundColor Gray
Write-Host "  - 'Discovered peer' messages in nodes" -ForegroundColor Gray
Write-Host "  - 'Peer state: UNKNOWN -> ACTIVE' transitions" -ForegroundColor Gray
Write-Host "  - 'Triggering test validation' after 30s" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Enter to close all windows..." -ForegroundColor Yellow
Read-Host

# Kill all processes
Write-Host "Stopping all processes..." -ForegroundColor Yellow
Get-Process -Name "cyxwiz*" -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Demo complete!" -ForegroundColor Green
