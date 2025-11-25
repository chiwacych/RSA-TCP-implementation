# ===========================
# RSA TCP Demo Launcher - Windows PowerShell
# ===========================
# This script automatically launches both Alice and Bob GUIs in separate windows
# for easy demonstration of RSA over TCP communication.

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   RSA over TCP - Demo Launcher (Windows)     " -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory and project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Check if virtual environment exists
$VenvPath = Join-Path $ProjectRoot "rsa_tcp_impl_env"
if (Test-Path $VenvPath) {
    $PythonExe = Join-Path $VenvPath "Scripts\python.exe"
    Write-Host "✓ Using virtual environment" -ForegroundColor Green
} else {
    $PythonExe = "python"
    Write-Host "⚠ Virtual environment not found, using system Python" -ForegroundColor Yellow
}

# Paths to GUI scripts
$AliceScript = Join-Path $ProjectRoot "alice_gui.py"
$BobScript = Join-Path $ProjectRoot "bob_gui.py"

# Check if scripts exist
if (-not (Test-Path $AliceScript)) {
    Write-Host "✗ Error: alice_gui.py not found!" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $BobScript)) {
    Write-Host "✗ Error: bob_gui.py not found!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Launching Alice GUI (Server)..." -ForegroundColor Cyan
Write-Host "  - Alice will run on port 3000 (configurable in GUI)" -ForegroundColor Gray
Write-Host "  - Change to port 5000 if you get permission errors" -ForegroundColor Gray

# Launch Alice in new PowerShell window
Start-Process pwsh -ArgumentList "-NoExit", "-Command", "& '$PythonExe' '$AliceScript'"

# Wait a moment for Alice to start
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Launching Bob GUI (Client)..." -ForegroundColor Cyan
Write-Host "  - Bob will connect to localhost:3000 by default" -ForegroundColor Gray
Write-Host "  - Update port in GUI if Alice uses different port" -ForegroundColor Gray

# Launch Bob in new PowerShell window
Start-Process pwsh -ArgumentList "-NoExit", "-Command", "& '$PythonExe' '$BobScript'"

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "✓ Both GUIs launched successfully!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. In Alice's window: Generate Keys → Start Server" -ForegroundColor White
Write-Host "  2. In Bob's window: Generate Keys → Connect to Alice" -ForegroundColor White
Write-Host "  3. Send encrypted messages between Alice and Bob!" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit this launcher..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
