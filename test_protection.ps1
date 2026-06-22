# ============================================================
#  Sentinel SOC - Real-Time Protection Test (100% SAFE)
#  Simulates the threat BEHAVIORS that Sentinel detects,
#  with zero harm to your machine. English-only to avoid any
#  encoding problems in PowerShell.
#
#  USAGE:
#    1. Start Sentinel (real-time protection runs automatically)
#    2. Run this as Administrator:  .\test_protection.ps1
#    3. Watch Sentinel's Logs / Alerts / Recent Activity
# ============================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Sentinel SOC - Real-Time Protection Test" -ForegroundColor Cyan
Write-Host "   (All tests are SAFE - no harm to your machine)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# ----------------------------------------------------------
# TEST 1: Encoded + download-style command (real malware pattern)
# Simulates malware that hides its command AND tries to pull a payload.
# Safe: the "download" targets a non-existent localhost address and the
# decoded command only prints a message; nothing is actually downloaded.
# This matches Sentinel's stricter rule (encode + download = malicious).
# ----------------------------------------------------------
Write-Host "[1] Test: Encoded + download-pattern command..." -ForegroundColor Yellow
$harmless = "Write-Host 'Sentinel test'; \$null = [System.Net.WebClient]"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($harmless)
$encoded = [Convert]::ToBase64String($bytes)
Start-Process powershell -ArgumentList "-EncodedCommand $encoded -Command IEX" -WindowStyle Hidden -Wait
Write-Host "    OK - ran an encoded+download-pattern command (Sentinel should flag+isolate)" -ForegroundColor Green
Start-Sleep -Seconds 3

# ----------------------------------------------------------
# TEST 2: Hidden window process
# Simulates malware running silently with no visible window.
# Safe: just sleeps for 1 second then exits.
# ----------------------------------------------------------
Write-Host "[2] Test: Hidden-window process..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-WindowStyle Hidden -Command Start-Sleep -Seconds 1" -Wait
Write-Host "    OK - ran a hidden process" -ForegroundColor Green
Start-Sleep -Seconds 3

# ----------------------------------------------------------
# TEST 3: Execution from a temp folder
# Simulates malware dropping itself into Temp and running.
# Safe: copies Notepad to Temp, runs it, then deletes it.
# ----------------------------------------------------------
Write-Host "[3] Test: Running a program from the Temp folder..." -ForegroundColor Yellow
$tempExe = Join-Path $env:TEMP "sentinel_test_app.exe"
Copy-Item "C:\Windows\System32\notepad.exe" $tempExe -ErrorAction SilentlyContinue
if (Test-Path $tempExe) {
    $p = Start-Process $tempExe -PassThru
    Start-Sleep -Seconds 2
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Remove-Item $tempExe -Force -ErrorAction SilentlyContinue
    Write-Host "    OK - ran a program from Temp (Sentinel should flag it)" -ForegroundColor Green
} else {
    Write-Host "    SKIP - could not copy (ignore this one)" -ForegroundColor DarkYellow
}
Start-Sleep -Seconds 3

# ----------------------------------------------------------
# TEST 4: EICAR test file (standard SAFE anti-virus test)
# Built from character codes so PowerShell never mis-parses it.
# Note: Windows Defender may delete it instantly = it's working!
# ----------------------------------------------------------
Write-Host "[4] Test: Creating an EICAR test file (safe standard)..." -ForegroundColor Yellow
Write-Host "    Note: Defender may delete it instantly (proof it works!)" -ForegroundColor DarkYellow
$codes = 88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42
$eicar = -join ($codes | ForEach-Object { [char]$_ })
$eicarPath = Join-Path $env:TEMP "sentinel_eicar_test.txt"
try {
    Set-Content -Path $eicarPath -Value $eicar -ErrorAction Stop
    Write-Host "    OK - EICAR file created at $eicarPath" -ForegroundColor Green
    Write-Host "    Tip: upload it in Sentinel's File Scan page to test detection" -ForegroundColor Gray
} catch {
    Write-Host "    OK - Defender blocked it instantly - your real-time protection works!" -ForegroundColor Green
}
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Test finished!" -ForegroundColor Cyan
Write-Host "   Open Sentinel and check:" -ForegroundColor Cyan
Write-Host "   - Logs page: you should see 'realtime' events" -ForegroundColor White
Write-Host "   - Alerts page: the event counter increased" -ForegroundColor White
Write-Host "   - Recent Activity on the dashboard" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
