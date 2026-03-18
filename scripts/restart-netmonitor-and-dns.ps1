# NetMonitor Windows servisini ve technitium-dns Docker container'ini yeniden baslatir.
# 3 saatte bir calistirmak icin Task Scheduler ile zamanlayin.

$ErrorActionPreference = 'Stop'

try {
    Restart-Service -Name 'NetMonitor' -Force
    Write-Output "$(Get-Date -Format o) NetMonitor servisi yeniden baslatildi."
}
catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
    Write-Error "NetMonitor servisi baslatilamadi: $($_.Exception.Message)"
    exit 1
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Error "docker komutu bulunamadi. PATH veya Docker Desktop kurulumunu kontrol edin."
    exit 2
}

& docker restart technitium-dns
if ($LASTEXITCODE -ne 0) {
    Write-Error "technitium-dns container yeniden baslatilamadi (cikis kodu: $LASTEXITCODE)."
    exit 3
}

Write-Output "$(Get-Date -Format o) technitium-dns container yeniden baslatildi."
