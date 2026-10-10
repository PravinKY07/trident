# simulate_threat.ps1 — spawns a harmless process with a malware-like name
# and path. TRIDENT will score it and (correctly) decide terminate.

$payload = Join-Path $env:TEMP "Unicorn-demo.exe"
Copy-Item "C:\Windows\System32\notepad.exe" $payload -Force

Write-Host "[demo] Spawning $payload" -ForegroundColor Yellow
Start-Process -FilePath $payload -WindowStyle Hidden

Write-Host "[demo] Waiting 5 seconds for TRIDENT to catch it..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

Write-Host "[demo] Cleaning up if still running..." -ForegroundColor Cyan
Get-Process -Name "Unicorn-demo" -ErrorAction SilentlyContinue | Stop-Process -Force

Remove-Item $payload -Force -ErrorAction SilentlyContinue
Write-Host "[demo] Done." -ForegroundColor Green
