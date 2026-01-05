# Network Monitor - Real-time Malicious IP Detection

Monitors all network traffic using Npcap and detects suspicious IPs in real-time.

## Prerequisites

1. **Install Npcap**
   - Download from: https://npcap.com/
   - During installation, check "Install Npcap in WinPcap API-compatible mode"
   - Run installer as Administrator

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the monitor (requires Administrator privileges):

```bash
python net_monitor.py
```

The script will:
- List available network interfaces
- Let you select an interface (or monitor all)
- Display suspicious IPs in real-time when thresholds are exceeded

## Detection Criteria

An IP is flagged as suspicious if it exceeds:
- **500 packets** in a 10-second window, OR
- **50 unique destination ports** in a 10-second window

Alerts are throttled (one per IP per 30 seconds) to avoid spam.

## Customization

Edit the thresholds in `main()`:

```python
monitor = NetworkMonitor(
    window_seconds=10,      # Time window for analysis
    max_packets=500,        # Max packets per window
    max_ports=50,           # Max unique ports per window
    alert_cooldown=30       # Seconds between alerts for same IP
)
```

