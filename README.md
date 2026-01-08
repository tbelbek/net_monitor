# Network Monitor - Real-time Malicious IP Detection

A Python-based network monitoring tool that uses Npcap to monitor all network traffic and detect suspicious IPs and subnets in real-time. The tool analyzes packet patterns, port scanning behavior, and automatically classifies threats into severity levels (L1-L4) with optional Windows Firewall integration.

## Features

- Real-time network traffic monitoring using Npcap/Scapy
- Detection of suspicious IPs and /16 subnets based on packet counts and port scanning patterns
- Four-level severity classification system (L1-L4) with exponential escalation thresholds
- Automatic Windows Firewall rule creation for L4 threats (optional)
- Protection against blocking excluded IPs (excluded IPs are never blocked even if they reach L4)
- **Automatic exclusion of local IPs and WAN IP** (prevents self-blocking)
- Windows toast notifications for critical subnet attacks
- **Email alerts for L4 attacks and firewall blocks** (configurable via `.env` file or command-line)
- Persistent status tracking across restarts
- Real-time console display with organized severity columns
- Comprehensive logging to `net_monitor.log` with **daily log rotation**
- SQLite-based status and excluded IP persistence with optimized queries
- Attack start/end detection and logging
- IP exclusion support (manual and automatic)
- **Automatic IPinfo integration** - Automatic IP geolocation and organization lookup for suspicious IPs
- **Packet samples** - Captures and stores sample packets from suspicious IPs with automatic cleanup

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
- `python-dotenv>=1.0.0` - Environment variable management (optional, for `.env` file support)
- `fastapi>=0.110.0` - Web framework (optional, for `--web-ui` mode)
- `uvicorn[standard]>=0.23.0` - ASGI server (optional, for `--web-ui` mode)
- `httpx>=0.24.0` - HTTP client (optional, for IPinfo integration and web UI)

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
- `--exclude-ip IP_ADDRESS` - IP address to exclude from monitoring and blocking (e.g., host's public IP). Can be specified multiple times or comma-separated. Can also be set via `EXCLUDE_IP` environment variable. Excluded IPs are loaded from SQLite database by default.
- `--email-smtp-server SERVER` - SMTP server for email alerts (e.g., smtp.gmail.com, smtp.office365.com). Can also be set via `EMAIL_SMTP_SERVER` environment variable or `.env` file.
- `--email-smtp-port PORT` - SMTP server port (default: 587 for TLS, use 465 for SSL). Can also be set via `EMAIL_SMTP_PORT` environment variable.
- `--email-username USERNAME` - SMTP username/email address for authentication. Can also be set via `EMAIL_USERNAME` environment variable or `.env` file.
- `--email-password PASSWORD` - SMTP password (or app password for Gmail/Office365). Can also be set via `EMAIL_PASSWORD` environment variable or `.env` file.
- `--email-from ADDRESS` - From email address for alerts. Can also be set via `EMAIL_FROM` environment variable or `.env` file.
- `--email-to ADDRESS` - Recipient email address(es) for alerts. Can be specified multiple times or comma-separated. Can also be set via `EMAIL_TO` environment variable or `.env` file (comma-separated).
- `--email-no-tls` - Disable TLS/SSL for SMTP (not recommended)
- `--web-ui` - Run FastAPI-based web UI instead of console display (suitable for Windows service)
- `--web-port PORT` - HTTP port for web UI (when --web-ui is enabled, default: 8080)

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

**Note**: Excluded IPs are loaded from SQLite database. If you specify `--exclude-ip`, it overrides the database. Excluded IPs will never be blocked, even if they reach L4 severity.

**Automatic IP Exclusion:**
- The tool automatically excludes all local/private IPs (e.g., 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- The tool automatically detects and excludes your WAN (public) IP address
- All server IPs (from all network interfaces) are automatically excluded
- This prevents false positives and self-blocking scenarios

### Email Alert Configuration

Email alerts can be configured via command-line arguments, environment variables, or a `.env` file (recommended for security).

**Using `.env` file (recommended):**

Create a `.env` file in the same directory as the script:

```env
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=recipient1@example.com,recipient2@example.com
EMAIL_USE_TLS=true
```

**Using command-line arguments:**

```bash
python net_monitor.py \
  --email-smtp-server smtp.gmail.com \
  --email-username your-email@gmail.com \
  --email-password your-app-password \
  --email-from your-email@gmail.com \
  --email-to recipient@example.com
```

**Email Alert Behavior:**
- **Firewall Block**: Email sent when a new firewall rule is created (only for newly created rules, not existing ones)
- All attack start/decay/end events are logged to `net_monitor.log` but do **not** generate emails
- **L3 and below**: No email alerts (only logged to `net_monitor.log`)

**Note**: For Gmail and Office365, you may need to use an app-specific password instead of your regular password. See your email provider's documentation for details.

## Detection Criteria

An IP or subnet is flagged as suspicious if it exceeds either threshold within the analysis window:
- **Packet count threshold**: Exceeds `--max-packets` packets (default: 20)
- **Port scanning threshold**: Exceeds `--max-ports` unique destination ports (default: 50)

### Severity Levels

Severity is classified based on the number of suspicious windows detected (suspicion_count), using exponential escalation with a configurable base value:

- **Level 0**: Below thresholds (no alert)
- **Level 1 (L1)**: BASE^1 suspicious windows (default: 8)
- **Level 2 (L2)**: BASE^2 suspicious windows (default: 8² = 64)
- **Level 3 (L3)**: BASE^3 suspicious windows (default: 8³ = 512)
- **Level 4 (L4)**: BASE^4 suspicious windows (default: 8⁴ = 4,096)

The base value (`BASE_SUSPICION_COUNT`) is defined in `net_monitor.py` and can be modified to adjust all thresholds. Threshold values are logged at startup for verification.

**Alert Behavior:**
- Alerts are throttled (one per IP per `--alert-cooldown` seconds) to avoid spam
- Severity escalation triggers immediate alerts regardless of cooldown
- L3/L4 levels trigger attack start/end detection and logging
- **L4 attacks trigger email alerts** (if email is configured): one email when attack starts, one when it ends
- L4 entities are added to firewall suggestions list

**Attack End Detection:**
An attack ends when the entity was previously in attack state (L3 or L4) but the current analysis window no longer exceeds the packet/port thresholds. This means the attack ends when activity drops below `--max-packets` AND `--max-ports` in the current window.

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
- Email alert status
- Auto-excluded IPs (local IPs and WAN IP)

**Daily Log Rotation:**
- Logs are automatically rotated daily at midnight UTC
- Old logs are renamed to `net_monitor.log.YYYY-MM-DD`
- If a dated log file already exists, new entries are appended to it

Example log entries:
```
2026-01-05T11:00:00.000000 Severity thresholds: L1=8, L2=64, L3=512, L4=4096 (BASE=8)
2026-01-05T11:03:31.916087 ATTACK_START IP 98.128.167.1 level=L4 first_suspicious=2026-01-05T11:03:31.916087
2026-01-05T11:26:58.006932 ATTACK_END IP 98.128.167.1 last_level=L4 duration_sec=1406.09
2026-01-05T11:21:08.516048 FIREWALL_BLOCKED 200.115.0.0/16 remote_address=200.115.0.0-200.115.255.255 display_name=Block_Attacker_200_115_0_0_16
2026-01-05T11:21:08.516048 Email alert sent: 🛡️ Firewall Block: 200.115.0.0/16
2026-01-05T00:00:00.000000 Auto-excluded 2 server IP(s): 192.168.1.100, 10.0.0.5
2026-01-05T00:00:00.000000 Auto-excluded WAN IP (public IP): 203.0.113.1
```

### `net_monitor_status.db`

SQLite database containing current monitoring status (saved every 60 seconds):
- Active IP and subnet statistics (only L4 entities persist)
- Suspicion counts and severity levels
- First/last suspicious timestamps
- Attack state (in_attack flag)
- Detected IPs and subnets
- Firewall suggestions
- Excluded IPs with notes and timestamps
- **IP analysis cache** - Cached IPinfo results (7-day expiry)

**Database Optimizations:**
- WAL (Write-Ahead Logging) mode enabled for better concurrency
- Indexes on frequently queried columns
- Batch INSERT operations for improved performance
- Optimized queries with proper connection handling

**Note**: The tool queries Windows Firewall directly to check for existing rules, ensuring consistency with the actual firewall state. Legacy JSON files (`net_monitor_status.json`, `excluded_ips.json`) are automatically migrated to SQLite on first run.

### `.env` (optional)

Environment configuration file for email alerts (not committed to version control):
- Contains SMTP server credentials and email addresses
- See "Email Alert Configuration" section above for format
- Create a `.env` file in the same directory as the script
- **Security**: Never commit `.env` files to version control (already in `.gitignore`)

## Windows Firewall Integration

When `--auto-block` is enabled, the tool automatically creates Windows Firewall rules for L4 entities:

- **IP blocking**: Creates inbound block rule for the specific IP address
- **Subnet blocking**: Creates inbound block rule for the /16 subnet range (e.g., `200.115.0.0-200.115.255.255`)

Firewall rules are named: `Block_Attacker_{entity}` (with dots and slashes replaced by underscores)

**Protection Mechanisms:**
- The tool queries Windows Firewall directly to check if a rule already exists before creating a new one (prevents duplicates)
- **Excluded IPs are never blocked**: IPs in the SQLite database, specified via `--exclude-ip`, or automatically excluded (local/WAN IPs) are skipped from firewall rule creation
- **Subnet protection**: Subnets containing excluded IPs are also prevented from being blocked
- **Email alerts for firewall blocks**: Email notifications are sent only when a new firewall rule is created (not for existing rules)

**Note**: Firewall rule creation requires Administrator privileges and may take a few seconds per rule. The tool performs a privilege check at startup and logs the result.

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

- **Status restoration**: On startup, loads previous status from `net_monitor_status.db`
- **Suspicion count preservation**: Continues counting from previous session (L4 entities only)
- **Blocked entities**: Loads previously blocked entities to avoid duplicate firewall rules
- **Periodic saves**: Status is saved every 60 seconds and on shutdown

## Stopping the Monitor

Press `Ctrl+C` to gracefully stop the monitor. The tool will:
- Save current status to `net_monitor_status.db`
- Display summary of detected IPs
- Clean up threads and resources

## Web UI

The tool includes a web-based dashboard for monitoring and management:

```bash
python net_monitor.py --web-ui --web-port 8080
```

The web UI provides:
- Real-time traffic visualization with charts (updated via Server-Sent Events)
- Severity history over time with configurable time ranges
- Top talkers and port distribution (5-minute aggregated windows)
- Last seen IPs and subnets (24h) with cumulative packet counts
- Excluded IPs management
- Firewall rules management (Windows only)
- **Packet samples** - View captured packet samples from suspicious IPs with IPinfo integration
- Interactive filtering and search
- Auto-refreshing data tables

**Technical Details:**
- Uses Server-Sent Events (SSE) for efficient real-time updates
- Optimized database queries with indexes and batch operations
- Firewall rule caching to minimize PowerShell calls
- Packet samples auto-refresh every minute

Access the dashboard at `http://localhost:8080` (or your configured port).

## Running as a Windows Service (NSSM)

The network monitor can be run as a Windows service using NSSM (Non-Sucking Service Manager), allowing it to start automatically on boot and run in the background.

### Prerequisites

1. **Download NSSM**: Download from https://nssm.cc/download
2. **Extract NSSM**: Extract to a folder (e.g., `C:\nssm`)
3. **Administrator privileges**: Required for service installation

### Installation Steps

1. **Open Command Prompt as Administrator**

2. **Navigate to NSSM directory**:
   ```cmd
   cd C:\nssm\win64
   ```

3. **Install the service** (replace paths as needed):
   ```cmd
   nssm install NetMonitor "C:\Python39\python.exe" "D:\Dev\net_monitor\net_monitor.py --web-ui --web-port 8080 --auto-block -i 0"
   ```

   **Important parameters:**
   - `NetMonitor` - Service name (can be any name)
   - `C:\Python39\python.exe` - Full path to your Python executable
   - `D:\Dev\net_monitor\net_monitor.py` - Full path to the script
   - `--web-ui` - Required for service mode (console mode won't work)
   - `--web-port 8080` - Web UI port (adjust as needed)
   - `--auto-block` - Enable automatic firewall blocking (optional)
   - `-i 0` - Interface ID (use `python net_monitor.py` first to find your interface ID)

4. **Configure service settings**:
   ```cmd
   nssm set NetMonitor AppDirectory "D:\Dev\net_monitor"
   nssm set NetMonitor DisplayName "Network Monitor"
   nssm set NetMonitor Description "Real-time network traffic monitoring and malicious IP detection"
   ```

5. **Configure service to run as Administrator** (required for packet capture and firewall):
   ```cmd
   nssm set NetMonitor ObjectName LocalSystem
   ```
   Or use a specific administrator account:
   ```cmd
   nssm set NetMonitor ObjectName "DOMAIN\Administrator" "password"
   ```

6. **Configure logging** (optional but recommended):
   ```cmd
   nssm set NetMonitor AppStdout "D:\Dev\net_monitor\nssm_stdout.log"
   nssm set NetMonitor AppStderr "D:\Dev\net_monitor\nssm_stderr.log"
   ```

7. **Configure auto-restart** (recommended):
   ```cmd
   nssm set NetMonitor AppRestartDelay 5000
   nssm set NetMonitor AppExit Default Restart
   ```

8. **Start the service**:
   ```cmd
   nssm start NetMonitor
   ```

### Service Management

**Start service:**
```cmd
nssm start NetMonitor
```

**Stop service:**
```cmd
nssm stop NetMonitor
```

**Restart service:**
```cmd
nssm restart NetMonitor
```

**View service status:**
```cmd
nssm status NetMonitor
```

**Edit service configuration:**
```cmd
nssm edit NetMonitor
```

**Remove service:**
```cmd
nssm remove NetMonitor confirm
```

### Alternative: Using Windows Services Manager

You can also manage the service using Windows Services Manager (`services.msc`):
- Search for "Services" in Windows Start menu
- Find "Network Monitor" (or your service name)
- Right-click to Start/Stop/Restart
- Right-click → Properties to configure startup type (Automatic/Manual/Disabled)

### Finding Your Interface ID

Before installing the service, determine which network interface to monitor:

1. Run the monitor interactively:
   ```cmd
   python net_monitor.py
   ```

2. Note the interface ID from the list (e.g., `0`, `1`, `2`, etc.)

3. Use this ID in the service installation command with `-i <ID>`

### Configuration via Environment Variables

For service mode, you can use a `.env` file in the script directory for email configuration:

```env
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=recipient@example.com
```

### Troubleshooting Service Issues

**Service won't start:**
- Check NSSM logs: `nssm_stdout.log` and `nssm_stderr.log`
- Verify Python path is correct
- Verify script path is correct
- Ensure service account has Administrator privileges
- Check Windows Event Viewer for service errors

**Can't capture packets:**
- Service must run as LocalSystem or Administrator account
- Verify Npcap is installed correctly
- Check that Npcap is in WinPcap API-compatible mode

**Web UI not accessible:**
- Verify firewall allows connections on the configured port
- Check if another service is using the port
- Review `nssm_stderr.log` for errors

**View real-time logs:**
```cmd
type D:\Dev\net_monitor\net_monitor.log
```

Or use PowerShell to tail the log:
```powershell
Get-Content D:\Dev\net_monitor\net_monitor.log -Wait -Tail 50
```

## IPinfo Integration

The tool automatically integrates with IPinfo.io to provide geolocation and organization information for suspicious IPs:

- **Automatic analysis**: Suspicious IPs (packet count > 500/hour) are automatically queued for IPinfo lookup
- **Free tier support**: Works without an API key (rate-limited free tier)
- **Optional API key**: Set `IPINFO_API_KEY` environment variable for higher rate limits
- **Caching**: Results are cached for 7 days to minimize API calls
- **Display**: IPinfo results appear in packet samples table with status indicators

**Configuration:**
```bash
# Optional: Set IPinfo API key for higher rate limits
set IPINFO_API_KEY=your_api_key_here
```

Or in `.env` file:
```env
IPINFO_API_KEY=your_api_key_here
```

## Packet Samples

The tool automatically captures sample packets from suspicious IPs:

- **Automatic capture**: Samples are captured when packet count increases significantly
- **Rate limiting**: Only samples IPs with > 500 packets in the last hour
- **Uniqueness**: Captures unique combinations of (source IP, destination IP, port, protocol)
- **Storage**: Up to 10 samples per entity, stored in memory
- **Auto-cleanup**: Samples older than 7 days are automatically removed
- **Display**: View samples in the web UI with IPinfo integration
- **Auto-refresh**: Packet samples table refreshes every minute

## Customization

All detection thresholds can be customized via command-line arguments:

```bash
python net_monitor.py \
  --window-seconds 10 \
  --max-packets 500 \
  --max-ports 50 \
  --alert-cooldown 30
```

**Severity Threshold Customization:**

The severity thresholds use exponential growth based on `BASE_SUSPICION_COUNT` (default: 8). To change the base value, edit the constant in `net_monitor.py`:

```python
BASE_SUSPICION_COUNT = 8  # Change this value
```

All thresholds will be automatically recalculated:
- L1 = BASE^1
- L2 = BASE^2
- L3 = BASE^3
- L4 = BASE^4

Threshold values are logged at startup for verification.

**Recommended Settings:**

- **High-traffic environments**: Increase `--max-packets` and `--max-ports`
- **Sensitive environments**: Decrease thresholds for earlier detection
- **Noisy networks**: Increase `--alert-cooldown` to reduce alert frequency
- **Adjust severity escalation**: Modify `BASE_SUSPICION_COUNT` to change how quickly entities escalate to higher severity levels

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
