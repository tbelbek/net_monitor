# NetMonitor Windows servisini ve technitium-dns Docker container'ini yeniden baslatir.
# 3 saatte bir calistirmak icin Task Scheduler ile zamanlayin.
# Servisi durdurup baslatmak icin yonetici yetkisi gerekir; aksi halde "Cannot open ... service" hatasi alinir.

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

try {
    Restart-Service -Name 'NetMonitor' -Force
    Write-Output "$(Get-Date -Format o) NetMonitor servisi yeniden baslatildi."
}
catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
    Write-Error @"
NetMonitor servisi baslatilamadi: $($_.Exception.Message)

Kontrol listesi:
- PowerShell'i sag tik > Yonetici olarak calistir.
- Zamanlanmis gorev: calistiran hesap Yoneticiler grubunda olsun; Gorevde 'En yuksek ayricaliklarla calistir' acik olsun.
"@
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

# $script = "\net_monitor\scripts\restart-netmonitor-and-dns.ps1"
# schtasks /Create /TN "NetMonitor ve DNS 3 saat" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$script`"" /SC HOURLY /MO 3 /RL HIGHEST