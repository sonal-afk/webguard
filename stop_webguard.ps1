$connections = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue

if (-not $connections) {
    Write-Host "WebGuard is not listening on port 5000."
    exit 0
}

$pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($pidValue in $pids) {
    Stop-Process -Id $pidValue -Force
    Write-Host "Stopped WebGuard process $pidValue."
}
