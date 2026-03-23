# Test IDS Backend
cd "c:\Users\madas\OneDrive\Desktop\PROJECTS\IDS\backend"

# Kill existing process on port 5000 if any
$proc = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($proc) {
    Stop-Process -Id $proc.OwningProcess -Force -ErrorAction SilentlyContinue
}

# Start Flask in background
Start-Process python -ArgumentList "app.py" -NoNewWindow

Write-Host "Waiting for server to start..."
Start-Sleep -Seconds 6

Write-Host "Running Health Check..."
try {
    $health = Invoke-RestMethod -Uri "http://localhost:5000/api/health" -Method Get
    $health | ConvertTo-Json
} catch {
    Write-Host "Health check failed: $_"
}

Write-Host "`nRunning Detection Test..."
try {
    $body = '{"packetData":"dos attack flood syn","modelType":"rf"}'
    $det = Invoke-RestMethod -Uri "http://localhost:5000/api/detect" -Method POST -Body $body -ContentType "application/json"
    $det | ConvertTo-Json
} catch {
    Write-Host "Detection test failed: $_"
}
