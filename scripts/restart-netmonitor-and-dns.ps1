schtasks /Create /TN "NetMonitor restart" /TR "powershell.exe -NoProfile -Command \"Restart-Service -Name NetMonitor -Force\"" /SC HOURLY /MO 3 /RL HIGHEST

schtasks /Create /TN "DNS container restart" /TR "docker restart technitium-dns" /SC HOURLY /MO 3