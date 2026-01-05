# Network Monitor - Real-time Malicious IP Detection

A Python-based network monitoring tool that uses Npcap to monitor all network traffic and detect suspicious IPs and subnets in real-time. The tool analyzes packet patterns, port scanning behavior, and automatically classifies threats into severity levels (L1-L4) with optional Windows Firewall integration.

## Features

- Real-time network traffic monitoring using Npcap/Scapy
- Detection of suspicious IPs and /16 subnets based on packet counts and port scanning patterns
- Four-level severity classification system (L1-L4) with cubic escalation thresholds
- Automatic Windows Firewall rule creation for L4 threats (optional)
- Protection against blocking excluded IPs (excluded IPs are never blocked even if they reach L4)
- Windows toast notifications for critical subnet attacks
- Persistent status tracking across restarts
- Real-time console display with organized severity columns
- Comprehensive logging to `net_monitor.log`
- JSON-based status and blocked entity persistence
- Attack start/end detection and logging
- IP exclusion support (e.g., exclude host's public IP)

## Prerequisites

1. **Windows Operating System** (required for Npcap and Windows Firewall integration)
2. **Npcap** - Download and install from: https://npcap.com/
   - During installation, check "Install Npcap in WinPcap API-compatible mode"
   - Run installer as Administrator
3. **Python 3.7+**
4. **Administrator privileges** (required to capture network traffic and manage firewall rules)

## Installation

1. Install Npcap (see Prerequisites)

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

Required packages:
- `scapy>=2.5.0` - Network packet capture and analysis
- `win10toast>=0.9` - Windows toast notifications (optional, falls back to PowerShell if unavailable)

## Usage

### Basic Usage

Run the monitor (requires Administrator privileges):

```bash
python net_monitor.py
```

The script will:
- List available network interfaces
- Let you select an interface (or monitor all interfaces)
- Display suspicious IPs/subnets in real-time organized by severity level

### Command-Line Arguments

```bash
python net_monitor.py [OPTIONS]
```

**Options:**

- `-i, --interface INTERFACE_ID` - Interface ID (index number or name) to monitor. Omit to see list and select interactively.
- `--auto-block` - Automatically add Windows Firewall rules for L4 IPs/subnets (requires Administrator privileges)
- `--window-seconds SECONDS` - Time window in seconds for analysis (default: 1)
- `--max-packets COUNT` - Maximum packets per window to trigger suspicion (default: 20)
- `--max-ports COUNT` - Maximum unique destination ports per window to trigger suspicion (default: 50)
- `--alert-cooldown SECONDS` - Seconds between alerts for the same IP (default: 30)
- `--exclude-ip IP_ADDRESS` - IP address to exclude from monitoring and blocking (e.g., host's public IP). Can be specified multiple times or comma-separated. Can also be set via `EXCLUDE_IP` environment variable. Excluded IPs are loaded from `excluded_ips.json` by default.

### Examples

Monitor all interfaces with default settings:
```bash
python net_monitor.py
```

Monitor specific interface by index:
```bash
python net_monitor.py -i 0
```

Monitor with custom thresholds and auto-blocking:
```bash
python net_monitor.py --window-seconds 10 --max-packets 500 --max-ports 50 --auto-block
```

Exclude host's public IP from monitoring and blocking:
```bash
python net_monitor.py --exclude-ip 203.0.113.1
```

Exclude multiple IPs:
```bash
python net_monitor.py --exclude-ip 203.0.113.1 --exclude-ip 192.168.1.1
```

Or set via environment variable:
```bash
set EXCLUDE_IP=203.0.113.1,192.168.1.1
python net_monitor.py
```

**Note**: Excluded IPs are also loaded from `excluded_ips.json` file. If you specify `--exclude-ip`, it overrides the JSON file. Excluded IPs will never be blocked, even if they reach L4 severity.

## Detection Criteria

An IP or subnet is flagged as suspicious if it exceeds either threshold within the analysis window:
- **Packet count threshold**: Exceeds `--max-packets` packets (default: 20)
- **Port scanning threshold**: Exceeds `--max-ports` unique destination ports (default: 50)

### Severity Levels

Severity is classified based on the number of suspicious windows detected (suspicion_count), using cubic escalation:

- **Level 0**: Below thresholds (no alert)
- **Level 1 (L1)**: 16+ suspicious windows (16 * 1³ = 16)
- **Level 2 (L2)**: 128+ suspicious windows (16 * 2³ = 128)
- **Level 3 (L3)**: 432+ suspicious windows (16 * 3³ = 432)
- **Level 4 (L4)**: 1024+ suspicious windows (16 * 4³ = 1024)

**Alert Behavior:**
- Alerts are throttled (one per IP per `--alert-cooldown` seconds) to avoid spam
- Severity escalation triggers immediate alerts regardless of cooldown
- L3/L4 levels trigger attack start/end detection and logging
- L4 entities are added to firewall suggestions list
- L4 subnet attacks trigger Windows toast notifications

### Subnet Detection

The tool also tracks /16 subnets to detect distributed attacks from rotating IPs within the same network prefix. Subnet statistics are aggregated independently and follow the same severity classification.

## Output Files

The tool creates several files in the same directory as the script:

### `net_monitor.log`

UTC-timestamped log file containing:
- Suspicious IP/subnet detections
- Attack start/end events
- Firewall rule creation attempts
- Status loading/saving events

Example log entries:
```
2026-01-05T11:03:31.916087 ATTACK_START IP 98.128.167.1 level=L3 first_suspicious=2026-01-05T11:03:31.916087
2026-01-05T11:26:58.006932 ATTACK_END IP 98.128.167.1 last_level=L3 duration_sec=1406.09
2026-01-05T11:21:08.516048 FIREWALL_BLOCKED 200.115.0.0/16 remote_address=200.115.0.0-200.115.255.255 display_name=Block_Attacker_200_115_0_0_16
```

### `net_monitor_status.json`

JSON file containing current monitoring status (saved every 60 seconds):
- Active IP and subnet statistics
- Suspicion counts and severity levels
- First/last suspicious timestamps
- Attack state (in_attack flag)
- Detected IPs and subnets
- Firewall suggestions

### `blocked_entities.json`

JSON file containing entities that have been blocked via Windows Firewall:
- List of blocked IPs and subnets
- Last update timestamp

### `excluded_ips.json`

JSON file containing IP addresses to exclude from monitoring and blocking:
- List of excluded IP addresses
- Excluded IPs are not monitored for suspicious activity
- Excluded IPs are never blocked, even if they reach L4 severity
- Subnets containing excluded IPs are also prevented from being blocked

## Windows Firewall Integration

When `--auto-block` is enabled, the tool automatically creates Windows Firewall rules for L4 entities:

- **IP blocking**: Creates inbound block rule for the specific IP address
- **Subnet blocking**: Creates inbound block rule for the /16 subnet range (e.g., `200.115.0.0-200.115.255.255`)

Firewall rules are named: `Block_Attacker_{entity}` (with dots and slashes replaced by underscores)

**Protection Mechanisms:**
- The tool checks if a rule already exists before creating a new one to avoid duplicates
- **Excluded IPs are never blocked**: IPs in `excluded_ips.json` or specified via `--exclude-ip` are skipped from firewall rule creation
- **Subnet protection**: Subnets containing excluded IPs are also prevented from being blocked

**Note**: Firewall rule creation requires Administrator privileges and may take a few seconds per rule.

## Real-Time Display

The console displays a dynamic table updated every second:

```
==============================================================================================================
L1                        L2                        L3                        L4
==============================================================================================================
95.70.206.222 27(p443)   198.41.0.0/16 234(50)     98.128.167.1 508(50)     200.115.0.0/16 1377(50)
213.186.33.99 26(50)      
76.76.2.191 17(p443)      
==============================================================================================================

New L4 Entries Added:
--------------------------------------------------------------------------------------------------------------
  [2026-01-05 11:21:08 UTC] SUBNET: 200.115.0.0/16
--------------------------------------------------------------------------------------------------------------

Press Ctrl+C to stop.
```

**Display Format:**
- Each entry shows: `{entity} {packet_count}({port_info})`
- Port info: Single port shown as `p{port}`, multiple ports shown as count
- Entries are sorted by severity level (L4 → L1), then by packet count
- Only currently suspicious entities are displayed

## Status Persistence

The tool maintains state across restarts:

- **Status restoration**: On startup, loads previous status from `net_monitor_status.json`
- **Suspicion count preservation**: Continues counting from previous session
- **Blocked entities**: Loads previously blocked entities to avoid duplicate firewall rules
- **Periodic saves**: Status is saved every 60 seconds and on shutdown

## Stopping the Monitor

Press `Ctrl+C` to gracefully stop the monitor. The tool will:
- Save current status to `net_monitor_status.json`
- Display summary of detected IPs
- Clean up threads and resources

## Customization

All detection thresholds can be customized via command-line arguments:

```bash
python net_monitor.py \
  --window-seconds 10 \
  --max-packets 500 \
  --max-ports 50 \
  --alert-cooldown 30
```

**Recommended Settings:**

- **High-traffic environments**: Increase `--max-packets` and `--max-ports`
- **Sensitive environments**: Decrease thresholds for earlier detection
- **Noisy networks**: Increase `--alert-cooldown` to reduce alert frequency

## Troubleshooting

**No network interfaces found:**
- Ensure Npcap is installed correctly
- Run as Administrator
- Check that Npcap is installed in WinPcap API-compatible mode

**Permission errors:**
- Run Python script as Administrator
- Ensure Windows Firewall service is running (for auto-block feature)

**High CPU usage:**
- Increase `--window-seconds` to reduce analysis frequency
- Monitor specific interface instead of all interfaces
- Increase thresholds to reduce number of tracked entities

**False positives:**
- Adjust `--max-packets` and `--max-ports` thresholds
- Use `--exclude-ip` to exclude legitimate high-traffic sources
- Review `net_monitor.log` to understand detection patterns

## License

This project is provided as-is for network security monitoring purposes.
