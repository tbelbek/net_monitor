#!/usr/bin/env python3
"""
Network Monitor - Real-time malicious IP detection using Npcap
Monitors all network traffic and detects suspicious behavior patterns.
"""

import asyncio
import sys
import platform
import os
import time
import argparse
import subprocess
import json
import sqlite3
import socket
import ipaddress
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque, defaultdict, Counter
from datetime import datetime, timedelta
from threading import Lock, Thread
from typing import Optional, Dict, List, Set, Tuple, Any

from scapy.all import get_if_list, sniff, IP, TCP, UDP

# Constants
BASE_SUSPICION_COUNT = 8
L4_SEVERITY_LEVEL = 4
L3_SEVERITY_LEVEL = 3
L1_THRESHOLD = BASE_SUSPICION_COUNT  # BASE^1
L2_THRESHOLD = BASE_SUSPICION_COUNT ** 2  # BASE^3
L3_THRESHOLD = BASE_SUSPICION_COUNT ** 3  # BASE^6
L4_THRESHOLD = BASE_SUSPICION_COUNT ** 4  # BASE^9
FIREWALL_PREFIX = "Block_Attacker_"
SUBNET_MASK = 16

# Timing constants
SAVE_INTERVAL_SECONDS = 60
DISPLAY_UPDATE_INTERVAL_SECONDS = 1
DISPLAY_SHUTDOWN_WAIT_SECONDS = 1.5
SSE_UPDATE_INTERVAL_SECONDS = 1
SSE_KEEPALIVE_INTERVAL_SECONDS = 15
FIREWALL_CACHE_REFRESH_INTERVAL_SECONDS = 30
AUTO_ANALYZE_INITIAL_DELAY_SECONDS = 2
AUTO_ANALYZE_CHECK_INTERVAL_SECONDS = 2
AUTO_ANALYZE_ERROR_WAIT_SECONDS = 5
PACKET_SAMPLE_CLEANUP_DAYS = 7
IP_ANALYSIS_CACHE_EXPIRY_DAYS = 7

# SQL table name whitelist for security
ALLOWED_SQL_TABLES = {"ip_stats", "subnet_stats", "detected_ips", "detected_subnets", "metadata", "firewall_suggestions", "excluded_ips", "ip_analysis_cache"}

# Common port names mapping
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "KERBEROS", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC", 139: "NETBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 515: "LPD", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 5900: "VNC", 6379: "REDIS",
    8080: "HTTP-PROXY", 8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9200: "ELASTICSEARCH",
    27017: "MONGODB", 5000: "UPNP", 5060: "SIP", 5222: "XMPP", 6667: "IRC",
    8000: "HTTP-ALT", 9000: "SONARQUBE", 9092: "KAFKA"
}

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import StreamingResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


def is_windows() -> bool:
    """Check if running on Windows platform."""
    return platform.system().lower().startswith("win")


class IpStats:
    """Tracks statistics for a single IP address or subnet"""
    
    def __init__(self):
        self.lock = Lock()
        self.packet_times = deque()
        self.packet_times_last_hour = deque()  # Track packets for last hour for rate limiting
        self.dst_ports = set()
        self.last_alert = None
        self.last_level = 0  # 0 = no alert yet, 1-4 = severity levels
        self.suspicion_count = 0  # how many windows this entity has been suspicious
        self.first_suspicious = None  # datetime of first suspicious window
        self.last_suspicious = None   # datetime of last suspicious window
        self.in_attack = False        # True while in an L3/L4 attack window
        self.last_suspicious_window_start = None  # track which window we last counted
        self.sample_packets = deque(maxlen=10)  # Store up to 10 sample packets
        self.last_packet_count = 0  # Track previous packet count for increase detection
        self.last_sample_time = None  # Track last time a sample was captured (for rate limiting)


class NetworkMonitor:
    """Monitors network traffic and detects suspicious IPs and subnets"""
    
    def __init__(self, window_seconds=10, max_packets=500, max_ports=50, alert_cooldown=30, auto_block=False, exclude_ips=None, 
                 email_smtp_server=None, email_smtp_port=587, email_username=None, email_password=None, 
                 email_from=None, email_to=None, email_use_tls=True):
        self.window = timedelta(seconds=window_seconds)
        self.max_packets = max_packets
        self.max_ports = max_ports
        self.alert_cooldown = timedelta(seconds=alert_cooldown)
        self.auto_block = auto_block  # Automatically add firewall rules for L4
        self.exclude_ips = set()  # Will be loaded from DB or set from parameter
        self.exclude_lock = Lock()
        
        # Email alert configuration
        self.email_smtp_server = email_smtp_server
        self.email_smtp_port = email_smtp_port
        self.email_username = email_username
        self.email_password = email_password
        self.email_from = email_from
        self.email_to = email_to if email_to else []
        self.email_use_tls = email_use_tls
        self.email_enabled = bool(email_smtp_server and email_username and email_password and email_from and email_to)
        # How long an IP/subnet should stay visible once it has reached a level > 0
        self.persistence_window = timedelta(hours=24)
        self.stats = defaultdict(IpStats)
        self.subnet_stats = defaultdict(IpStats)
        self.detected_ips = set()
        self.detected_subnets = set()
        self.running = False
        self.display_lock = Lock()
        self.firewall_suggestions = {}  # entity -> {"added": datetime, "is_subnet": bool}
        self.logged_skip_entities = set()  # Track entities that have been logged as skipped
        self.firewall_block_emails_sent = set()  # Track entities that have had firewall block emails sent
        self.email_skip_logged = set()  # Track entities for which we've logged email skip messages (to avoid log spam)
        self.packet_samples = {}  # entity -> list of sample packet info
        self.sampled_combinations = {}  # entity -> set of (src_ip, dst_ip, dst_port, proto) tuples
        self.auto_analyze_queue = deque()  # Queue of IPs to auto-analyze with IPinfo
        self.last_auto_analyze_times = {}  # Track last auto-analysis time per IP (rate limiting)
        self.auto_analyze_lock = Lock()  # Lock for auto-analyze queue

        # Log file (in the same directory as this script)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_path = os.path.join(base_dir, "net_monitor.log")
        self.log_dir = base_dir
        self.status_file = os.path.join(base_dir, "net_monitor_status.json")
        self.status_db_path = os.path.join(base_dir, "net_monitor_status.db")
        self.excluded_ips_file = os.path.join(base_dir, "excluded_ips.json")
        self.last_log_date = None  # Track the date of the current log file
        
        # Ensure DB schema before loading exclusions
        self._ensure_status_db()
        self._migrate_excluded_ips_json_to_db()

        # Load excluded IPs from SQLite unless provided via command line
        if exclude_ips is None:
            self.exclude_ips = self._load_excluded_ips_from_db()
        else:
            if isinstance(exclude_ips, str):
                self.exclude_ips = {exclude_ips}
            else:
                self.exclude_ips = set(exclude_ips) if exclude_ips else set()
        
        # Automatically detect and exclude local IPs and WAN IP
        self._auto_exclude_local_and_wan_ips()
        
        # Initialize log rotation (check if log file exists and get its date)
        self._initialize_log_rotation()
        
        # Log threshold configuration
        self._log(f"Severity thresholds: L1={L1_THRESHOLD}, L2={L2_THRESHOLD}, L3={L3_THRESHOLD}, L4={L4_THRESHOLD} (BASE={BASE_SUSPICION_COUNT})")
        
        # Log email configuration status
        if self.email_enabled:
            self._log(f"Email alerts enabled: SMTP={self.email_smtp_server}:{self.email_smtp_port}, From={self.email_from}, To={', '.join(self.email_to)}")
        else:
            self._log("Email alerts disabled (email configuration not provided)")
        
        # Load previous status if available
        self._migrate_status_json_to_db()
        self._load_status()

    # --- Web API helpers are defined later; see create_web_app() at module level ---

    def _initialize_log_rotation(self) -> None:
        """Initialize log rotation by checking the current log file date."""
        try:
            if os.path.exists(self.log_path):
                # Try to read the first line to get the actual log date
                try:
                    with open(self.log_path, "r", encoding="utf-8") as f:
                        first_line = f.readline().strip()
                        if first_line:
                            # Extract date from timestamp (format: YYYY-MM-DDTHH:MM:SS...)
                            date_str = first_line.split("T")[0]
                            self.last_log_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                        else:
                            # Empty file, use file modification time
                            file_mtime = datetime.utcfromtimestamp(os.path.getmtime(self.log_path))
                            self.last_log_date = file_mtime.date()
                except (ValueError, IndexError, IOError):
                    # Fallback to file modification time if parsing fails
                    file_mtime = datetime.utcfromtimestamp(os.path.getmtime(self.log_path))
                    self.last_log_date = file_mtime.date()
            else:
                self.last_log_date = datetime.utcnow().date()
        except (OSError, ValueError, AttributeError):
            self.last_log_date = datetime.utcnow().date()
    
    def _rotate_log_if_needed(self) -> None:
        """Rotate log file if it's a new day."""
        try:
            now = datetime.utcnow()
            current_date = now.date()
            
            # Check if we need to rotate (new day)
            if self.last_log_date is not None and self.last_log_date != current_date:
                if os.path.exists(self.log_path):
                    # Create rotated log filename with date: net_monitor.log.YYYY-MM-DD
                    rotated_name = f"net_monitor.log.{self.last_log_date.isoformat()}"
                    rotated_path = os.path.join(self.log_dir, rotated_name)
                    
                    # Rename the old log file
                    if not os.path.exists(rotated_path):
                        os.rename(self.log_path, rotated_path)
                    else:
                        # If rotated file already exists, append to it
                        with open(self.log_path, "r", encoding="utf-8") as old_log:
                            with open(rotated_path, "a", encoding="utf-8") as rotated_log:
                                rotated_log.write(f"\n--- Continued from {self.last_log_date.isoformat()} ---\n")
                                rotated_log.write(old_log.read())
                        os.remove(self.log_path)
            
            # Update the last log date
            self.last_log_date = current_date
        except (OSError, IOError, ValueError) as e:
            # Log rotation failures should not break monitoring
            # Silently fail to avoid breaking the monitoring loop
            pass
    
    def _log(self, message: str, level: str = "INFO") -> None:
        """Append a log line with UTC timestamp to the log file."""
        # Rotate log if needed (check daily)
        self._rotate_log_if_needed()
        
        # Sanitize sensitive data
        sanitized_message = self._sanitize_log_message(message)
        
        timestamp = datetime.utcnow().isoformat()
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} [{level}] {sanitized_message}\n")
        except (OSError, IOError) as e:
            # Logging failures should not break monitoring
            # Only log if we can (avoid infinite recursion)
            try:
                print(f"Logging error: {e}", file=sys.stderr)
            except (OSError, IOError):
                pass
    
    def _load_excluded_ips_from_db(self) -> Set[str]:
        """Load excluded IPs from SQLite table."""
        try:
            with sqlite3.connect(self.status_db_path) as conn:
                rows = conn.execute("SELECT ip FROM excluded_ips").fetchall()
                ips = {row[0] for row in rows if row and row[0]}
                if ips:
                    self._log(f"Loaded {len(ips)} excluded IPs from SQLite")
                return ips
        except (sqlite3.Error, OSError) as e:
            self._log(f"Error loading excluded IPs from SQLite: {e}", "ERROR")
            return set()
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is a private/local IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    def _get_firewall_display_name(self, entity: str) -> str:
        """Generate a firewall rule display name from an entity (IP or subnet)."""
        return f"{FIREWALL_PREFIX}{entity.replace('/', '_').replace('.', '_')}"
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate that a string is a valid IP address or CIDR network. Returns True if valid, False otherwise."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            pass
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False

    def _is_ip_excluded(self, ip: str) -> bool:
        """Return True if the IP is in exclude_ips (exact) or falls inside any excluded CIDR."""
        if ip in self.exclude_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.exclude_ips:
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    if addr in net:
                        return True
                except ValueError:
                    continue
        return False

    def _sanitize_log_message(self, message: str) -> str:
        """Sanitize sensitive data in log messages."""
        import re
        sanitized = message
        
        # Mask email addresses (show first 3 chars + domain)
        email_pattern = r'\b([a-zA-Z0-9._%+-]{3})([a-zA-Z0-9._%+-]*?)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        sanitized = re.sub(email_pattern, r'\1***@\3', sanitized)
        
        # Optionally mask IP addresses (show first 3 octets)
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b'
        sanitized = re.sub(ip_pattern, r'\1.xxx', sanitized)
        
        # Remove any potential password/API key patterns
        if 'password' in sanitized.lower() or 'api_key' in sanitized.lower() or 'api-key' in sanitized.lower():
            sanitized = re.sub(r'(password|api[_-]?key)\s*[:=]\s*[^\s]+', r'\1=***', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def _validate_sql_table_name(self, table_name: str) -> bool:
        """Validate that a table name is in the whitelist."""
        return table_name in ALLOWED_SQL_TABLES
    
    def _escape_powershell_argument(self, arg: str) -> str:
        """Escape a PowerShell argument to prevent command injection."""
        if not arg:
            return "''"
        # Replace single quotes with two single quotes (PowerShell escaping)
        escaped = arg.replace("'", "''")
        # Wrap in single quotes
        return f"'{escaped}'"
    
    def _validate_display_name(self, display_name: str) -> bool:
        """Validate display name contains only safe characters."""
        import re
        # Only allow alphanumeric, underscore, hyphen, dot, slash
        return bool(re.match(r'^[a-zA-Z0-9_\-./]+$', display_name))
    
    def _build_powershell_check_rule_cmd(self, display_name: str) -> List[str]:
        """Build a safe PowerShell command to check if a firewall rule exists."""
        if not self._validate_display_name(display_name):
            raise ValueError(f"Invalid display name: {display_name}")
        escaped_name = self._escape_powershell_argument(display_name)
        return [
            "powershell", "-Command",
            f"Get-NetFirewallRule -DisplayName {escaped_name} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
        ]
    
    def _build_powershell_create_rule_cmd(self, display_name: str, remote_address: str) -> List[str]:
        """Build a safe PowerShell command to create a firewall rule."""
        if not self._validate_display_name(display_name):
            raise ValueError(f"Invalid display name: {display_name}")
        # Validate remote_address is a valid IP or IP range
        try:
            if '-' in remote_address:
                # IP range format: x.x.x.x-y.y.y.y
                parts = remote_address.split('-')
                if len(parts) == 2:
                    ipaddress.ip_address(parts[0].strip())
                    ipaddress.ip_address(parts[1].strip())
            elif '/' in remote_address:
                # CIDR format
                ipaddress.ip_network(remote_address, strict=False)
            else:
                # Single IP
                ipaddress.ip_address(remote_address)
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid remote address: {remote_address}")
        
        escaped_name = self._escape_powershell_argument(display_name)
        escaped_addr = self._escape_powershell_argument(remote_address)
        return [
            "powershell", "-Command",
            f"New-NetFirewallRule -DisplayName {escaped_name} -Direction Inbound -Action Block -RemoteAddress {escaped_addr} -Protocol Any -ErrorAction Stop"
        ]
    
    def _build_powershell_list_rules_cmd(self, prefix: str) -> List[str]:
        """Build a safe PowerShell command to list firewall rules."""
        if not self._validate_display_name(prefix):
            raise ValueError(f"Invalid prefix: {prefix}")
        escaped_prefix = self._escape_powershell_argument(prefix + "*")
        return [
            "powershell", "-Command",
            f"Get-NetFirewallRule -DisplayName {escaped_prefix} | ForEach-Object {{ "
            f"$rule=$_; "
            f"$addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule; "
            f"[PSCustomObject]@{{ "
            f"DisplayName=$rule.DisplayName; "
            f"Direction=$rule.Direction; "
            f"Action=$rule.Action; "
            f"Enabled=$rule.Enabled; "
            f"RemoteAddress=($addr.RemoteAddress -join ',') "
            f"}} "
            f"}} | ConvertTo-Json"
        ]
    
    def _build_powershell_remove_rule_cmd(self, display_name: str) -> List[str]:
        """Build a safe PowerShell command to remove a firewall rule."""
        if not self._validate_display_name(display_name):
            raise ValueError(f"Invalid display name: {display_name}")
        escaped_name = self._escape_powershell_argument(display_name)
        return [
            "powershell", "-Command",
            f"Remove-NetFirewallRule -DisplayName {escaped_name} -ErrorAction Stop"
        ]
    
    def _get_all_server_ips(self) -> Set[str]:
        """Get all IP addresses (both private and public) from all network interfaces."""
        server_ips = set()

        # Get all IPs from network interfaces
        try:
            if is_windows():
                from scapy.arch.windows import get_windows_if_list
                win_if_info = get_windows_if_list()
                for w in win_if_info:
                    ip = w.get("ip")
                    if ip:
                        server_ips.add(ip)
            else:
                # On Linux/Unix, attempt a single outbound connect to discover primary IP
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    server_ips.add(local_ip)
                except (socket.error, OSError, AttributeError):
                    pass
        except (OSError, AttributeError, ImportError):
            pass

        # Also check all network interfaces using socket
        try:
            addrinfo = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            for info in addrinfo:
                ip = info[4][0]
                server_ips.add(ip)
        except Exception:
            pass
        
        return server_ips
    
    def _get_local_ips(self) -> Set[str]:
        """Get all local/private IP addresses from network interfaces."""
        all_ips = self._get_all_server_ips()
        return {ip for ip in all_ips if self._is_private_ip(ip)}
    
    def _get_wan_ip(self) -> Optional[str]:
        """Get the WAN/public IP address of the host."""
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://api.ip.sb/ip",
            "https://checkip.amazonaws.com",
            "https://ipinfo.io/ip",
            "https://ipecho.net/plain",
            "https://whatismyip.akamai.com",
            "https://myip.dnsomatic.com"
        ]
        
        for service in services:
            try:
                if is_windows():
                    cmd = [
                        "powershell", "-Command",
                        f"try {{ (Invoke-WebRequest -Uri '{service}' -UseBasicParsing -TimeoutSec 5).Content.Trim() }} catch {{ '' }}"
                    ]
                else:
                    cmd = ["curl", "-s", "--max-time", "5", service]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if result.returncode == 0:
                    ip = result.stdout.strip()
                    # Remove any whitespace, newlines, or HTML tags
                    ip = ip.split()[0] if ip else ""
                    if ip and not self._is_private_ip(ip):
                        if self._validate_ip(ip):
                            self._log(f"Detected WAN IP from {service}: {ip}")
                            return ip
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                # Log the error but continue trying other services
                continue
        
        self._log("WAN IP detection failed - could not determine public IP from any service")
        return None
    
    def _auto_exclude_local_and_wan_ips(self) -> None:
        """Automatically detect and exclude local IPs, server IPs, and WAN IP."""
        auto_excluded = set()
        
        # Get and exclude all server IPs (from all network interfaces)
        server_ips = self._get_all_server_ips()
        for ip in server_ips:
            if ip not in self.exclude_ips:
                self.exclude_ips.add(ip)
                auto_excluded.add(ip)
        
        if server_ips:
            newly_excluded = [ip for ip in server_ips if ip in auto_excluded]
            if newly_excluded:
                self._log(f"Auto-excluded {len(newly_excluded)} server IP(s): {', '.join(sorted(newly_excluded))}")
        
        # Get and exclude WAN IP (public IP from "what is my ip" services)
        wan_ip = self._get_wan_ip()
        if wan_ip:
            if wan_ip not in self.exclude_ips:
                self.exclude_ips.add(wan_ip)
                auto_excluded.add(wan_ip)
                self._log(f"Auto-excluded WAN IP (public IP): {wan_ip}")
            else:
                self._log(f"WAN IP {wan_ip} already in exclusion list")
        else:
            self._log("WAN IP detection failed - public IP not detected (may already be excluded or services unavailable)")
        
        if not auto_excluded:
            self._log("No additional IPs auto-excluded (server IPs and WAN IP already in exclusion list or not detected)")
    
    def _save_stats_to_db(
        self, conn: sqlite3.Connection, stats_dict: Dict[str, IpStats], table_name: str
    ) -> None:
        """Save stats dictionary to database table."""
        if not self._validate_sql_table_name(table_name):
            raise ValueError(f"Invalid table name: {table_name}")
        conn.execute(f"DELETE FROM {table_name}")
        rows_to_insert = []
        for entity, stats in stats_dict.items():
            with stats.lock:
                if stats.suspicion_count >= L4_THRESHOLD:
                    rows_to_insert.append((
                        entity,
                        stats.suspicion_count,
                        stats.last_level,
                        stats.first_suspicious.isoformat() if stats.first_suspicious else None,
                        stats.last_suspicious.isoformat() if stats.last_suspicious else None,
                        1 if stats.in_attack else 0,
                    ))
        if rows_to_insert:
            conn.executemany(
                f"""
                INSERT INTO {table_name} (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows_to_insert
            )

    def _save_detected_entities(self, conn: sqlite3.Connection, entities: Set[str], table_name: str) -> None:
        """Save detected entities to database table."""
        if not self._validate_sql_table_name(table_name):
            raise ValueError(f"Invalid table name: {table_name}")
        conn.execute(f"DELETE FROM {table_name}")
        if entities:
            conn.executemany(
                f"INSERT INTO {table_name} (entity) VALUES (?)",
                [(entity,) for entity in entities]
            )

    def _save_status(self) -> None:
        """Persist monitoring status to SQLite (only L4 entities persist)."""
        try:
            now = datetime.utcnow()
            with sqlite3.connect(self.status_db_path) as conn:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM metadata")
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ("last_updated", now.isoformat()),
                )

                self._save_stats_to_db(conn, self.stats, "ip_stats")
                self._save_stats_to_db(conn, self.subnet_stats, "subnet_stats")
                self._save_detected_entities(conn, self.detected_ips, "detected_ips")
                self._save_detected_entities(conn, self.detected_subnets, "detected_subnets")

                conn.execute("DELETE FROM firewall_suggestions")
                if self.firewall_suggestions:
                    conn.executemany(
                        """
                        INSERT INTO firewall_suggestions (entity, added, is_subnet)
                        VALUES (?, ?, ?)
                        """,
                        [
                            (
                                entity,
                                info["added"].isoformat(),
                                1 if info["is_subnet"] else 0,
                            )
                            for entity, info in self.firewall_suggestions.items()
                        ]
                    )
                conn.commit()
        except (sqlite3.Error, OSError) as e:
            self._log(f"Error saving status: {e}", "ERROR")

    def _load_stats_from_db(
        self, conn: sqlite3.Connection, stats_dict: Dict[str, IpStats], table_name: str
    ) -> None:
        """Load stats from database table into stats dictionary."""
        if not self._validate_sql_table_name(table_name):
            raise ValueError(f"Invalid table name: {table_name}")
        for entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack in conn.execute(
            f"SELECT entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack FROM {table_name}"
        ):
            stats = stats_dict[entity]
            with stats.lock:
                stats.suspicion_count = suspicion_count or 0
                stats.last_level = last_level or 0
                if first_suspicious:
                    stats.first_suspicious = datetime.fromisoformat(first_suspicious)
                if last_suspicious:
                    stats.last_suspicious = datetime.fromisoformat(last_suspicious)
                stats.in_attack = bool(in_attack)

    def _load_status(self) -> None:
        """Load previous monitoring status from SQLite store."""
        try:
            if not os.path.exists(self.status_db_path):
                return

            with sqlite3.connect(self.status_db_path) as conn:
                self._load_stats_from_db(conn, self.stats, "ip_stats")
                self._load_stats_from_db(conn, self.subnet_stats, "subnet_stats")

                self.detected_ips = {row[0] for row in conn.execute("SELECT entity FROM detected_ips")}
                self.detected_subnets = {row[0] for row in conn.execute("SELECT entity FROM detected_subnets")}

                for entity, added, is_subnet in conn.execute(
                    "SELECT entity, added, is_subnet FROM firewall_suggestions"
                ):
                    self.firewall_suggestions[entity] = {
                        "added": datetime.fromisoformat(added),
                        "is_subnet": bool(is_subnet),
                    }

                loaded_ips = len(self.stats)
                loaded_subnets = len(self.subnet_stats)
                loaded_firewall = len(self.firewall_suggestions)
                self._log(
                    f"Loaded status: {loaded_ips} IPs, {loaded_subnets} subnets, {len(self.detected_ips)} detected IPs, "
                    f"{len(self.detected_subnets)} detected subnets, {loaded_firewall} firewall suggestions"
                )
        except (sqlite3.Error, OSError, ValueError) as e:
            self._log(f"Error loading status: {e}")

    def _ensure_status_db(self) -> None:
        """Create SQLite schema for status storage if missing."""
        try:
            with sqlite3.connect(self.status_db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ip_stats (
                        entity TEXT PRIMARY KEY,
                        suspicion_count INTEGER,
                        last_level INTEGER,
                        first_suspicious TEXT,
                        last_suspicious TEXT,
                        in_attack INTEGER
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS subnet_stats (
                        entity TEXT PRIMARY KEY,
                        suspicion_count INTEGER,
                        last_level INTEGER,
                        first_suspicious TEXT,
                        last_suspicious TEXT,
                        in_attack INTEGER
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detected_ips (
                        entity TEXT PRIMARY KEY
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS detected_subnets (
                        entity TEXT PRIMARY KEY
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS firewall_suggestions (
                        entity TEXT PRIMARY KEY,
                        added TEXT,
                        is_subnet INTEGER
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS excluded_ips (
                        ip TEXT PRIMARY KEY,
                        note TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ip_analysis_cache (
                        ip TEXT PRIMARY KEY,
                        result_json TEXT NOT NULL,
                        analyzed_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_ip_analysis_expires 
                    ON ip_analysis_cache(expires_at)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_excluded_ips_created_at 
                    ON excluded_ips(created_at)
                    """
                )
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA cache_size=-64000")
                conn.commit()
        except Exception as e:
            self._log(f"Error initializing status DB: {e}")

    def _migrate_status_json_to_db(self) -> None:
        """Migrate legacy JSON status file into SQLite once."""
        try:
            if not os.path.exists(self.status_file):
                return

            # Skip migration if DB already has metadata
            existing_meta = False
            if os.path.exists(self.status_db_path):
                with sqlite3.connect(self.status_db_path) as conn:
                    row = conn.execute("SELECT COUNT(*) FROM metadata").fetchone()
                    existing_meta = bool(row and row[0])
            if existing_meta:
                return

            with open(self.status_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            now_val = data.get("last_updated") or datetime.utcnow().isoformat()
            with sqlite3.connect(self.status_db_path) as conn:
                conn.execute("BEGIN")
                conn.execute("DELETE FROM metadata")
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ("last_updated", now_val),
                )
                conn.execute("DELETE FROM ip_stats")
                ip_stats_data = [
                    (
                        ip,
                        stats_data.get("suspicion_count", 0),
                        stats_data.get("last_level", 0),
                        stats_data.get("first_suspicious"),
                        stats_data.get("last_suspicious"),
                        1 if stats_data.get("in_attack", False) else 0,
                    )
                    for ip, stats_data in data.get("ip_stats", {}).items()
                ]
                if ip_stats_data:
                    conn.executemany(
                        """
                        INSERT INTO ip_stats (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        ip_stats_data
                    )

                conn.execute("DELETE FROM subnet_stats")
                subnet_stats_data = [
                    (
                        subnet,
                        stats_data.get("suspicion_count", 0),
                        stats_data.get("last_level", 0),
                        stats_data.get("first_suspicious"),
                        stats_data.get("last_suspicious"),
                        1 if stats_data.get("in_attack", False) else 0,
                    )
                    for subnet, stats_data in data.get("subnet_stats", {}).items()
                ]
                if subnet_stats_data:
                    conn.executemany(
                        """
                        INSERT INTO subnet_stats (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        subnet_stats_data
                    )

                conn.execute("DELETE FROM detected_ips")
                detected_ips_data = [(ip,) for ip in data.get("detected_ips", [])]
                if detected_ips_data:
                    conn.executemany("INSERT INTO detected_ips (entity) VALUES (?)", detected_ips_data)

                conn.execute("DELETE FROM detected_subnets")
                detected_subnets_data = [(subnet,) for subnet in data.get("detected_subnets", [])]
                if detected_subnets_data:
                    conn.executemany("INSERT INTO detected_subnets (entity) VALUES (?)", detected_subnets_data)

                conn.execute("DELETE FROM firewall_suggestions")
                firewall_suggestions_data = [
                    (
                        entity,
                        info.get("added"),
                        1 if info.get("is_subnet", False) else 0,
                    )
                    for entity, info in data.get("firewall_suggestions", {}).items()
                ]
                if firewall_suggestions_data:
                    conn.executemany(
                        """
                        INSERT INTO firewall_suggestions (entity, added, is_subnet)
                        VALUES (?, ?, ?)
                        """,
                        firewall_suggestions_data
                    )
                conn.commit()

            self._log(
                f"Migrated legacy status JSON to SQLite at {self.status_db_path}"
            )
        except Exception as e:
            self._log(f"Error migrating status JSON to DB: {e}")
    
    def _migrate_excluded_ips_json_to_db(self) -> None:
        """One-time migration of excluded_ips.json into SQLite excluded_ips table."""
        try:
            if not os.path.exists(self.excluded_ips_file):
                return

            with sqlite3.connect(self.status_db_path) as conn:
                row = conn.execute("SELECT COUNT(*) FROM excluded_ips").fetchone()
                if row and row[0]:
                    return

                with open(self.excluded_ips_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ips = data.get("excluded_ips", []) if isinstance(data, dict) else []

            now_val = datetime.utcnow().isoformat()
            valid_ips = [(ip, None, now_val) for ip in ips if ip]
            if valid_ips:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO excluded_ips (ip, note, created_at)
                    VALUES (?, ?, ?)
                    """,
                    valid_ips
                )
                conn.commit()

            self._log(
                f"Migrated {len(ips)} excluded IPs from JSON to SQLite at {self.status_db_path}"
            )
        except Exception as e:
            self._log(f"Error migrating excluded IPs JSON to DB: {e}")

    def list_excluded_ips(self) -> List[Dict[str, Optional[str]]]:
        """Return all excluded IPs with metadata."""
        try:
            with sqlite3.connect(self.status_db_path) as conn:
                rows = conn.execute(
                    "SELECT ip, note, created_at FROM excluded_ips ORDER BY created_at"
                ).fetchall()
                return [
                    {"ip": row[0], "note": row[1], "created_at": row[2]} for row in rows
                ]
        except (sqlite3.Error, OSError) as e:
            self._log(f"Error listing excluded IPs: {e}")
            return []

    def add_excluded_ip(self, ip: str, note: Optional[str] = None) -> bool:
        """Add or update an excluded IP in SQLite and in-memory set."""
        if not self._validate_ip(ip):
            return False

        try:
            with self.exclude_lock:
                with sqlite3.connect(self.status_db_path) as conn:
                    existing = conn.execute(
                        "SELECT note, created_at FROM excluded_ips WHERE ip = ?", (ip,)
                    ).fetchone()
                    created_at = existing[1] if existing and existing[1] else datetime.utcnow().isoformat()
                    note_to_use = note if note is not None else (existing[0] if existing else None)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO excluded_ips (ip, note, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (ip, note_to_use, created_at),
                    )
                    conn.commit()
                self.exclude_ips.add(ip)
            return True
        except Exception as e:
            self._log(f"Error adding excluded IP {ip}: {e}")
            return False

    def remove_excluded_ip(self, ip: str) -> bool:
        """Remove an excluded IP from SQLite and in-memory set."""
        try:
            with self.exclude_lock:
                with sqlite3.connect(self.status_db_path) as conn:
                    conn.execute("DELETE FROM excluded_ips WHERE ip = ?", (ip,))
                    conn.commit()
                self.exclude_ips.discard(ip)
            return True
        except Exception as e:
            self._log(f"Error removing excluded IP {ip}: {e}")
            return False

    def _send_email_alert(self, subject: str, body: str) -> None:
        """Send an email alert."""
        if not self.email_enabled:
            self._log(f"Email alert skipped (email not enabled): {subject}")
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = ', '.join(self.email_to)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_smtp_server, self.email_smtp_port)
            if self.email_use_tls:
                server.starttls()
            server.login(self.email_username, self.email_password)
            server.send_message(msg)
            server.quit()
            
            self._log(f"Email alert sent: {subject}", "INFO")
        except (smtplib.SMTPException, OSError, IOError) as e:
            self._log(f"Failed to send email alert: {str(e)}", "ERROR")
    
    def _check_firewall_rule_exists(self, display_name: str) -> bool:
        """
        Check if a firewall rule with the given display name exists in Windows Firewall.
        Returns True if the rule exists, False otherwise.
        """
        if not is_windows():
            return False
        
        try:
            check_cmd = self._build_powershell_check_rule_cmd(display_name)
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and result.stdout.strip() != ""
        except (ValueError, subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            self._log(f"Error checking firewall rule existence: {e}", "WARNING")
            return False
    
    def _add_firewall_rule(self, entity: str, is_subnet: bool = False) -> Tuple[bool, bool, str]:
        """
        Add a Windows Firewall rule to block the given IP or subnet.
        Returns tuple: (success: bool, was_new_rule: bool, display_name: str)
        """
        display_name = self._get_firewall_display_name(entity)
        
        if not is_subnet:
            if self._is_ip_excluded(entity):
                if entity not in self.logged_skip_entities:
                    self._log(f"FIREWALL_SKIP {entity} (in excluded IPs list)")
                    self.logged_skip_entities.add(entity)
                return (True, False, display_name)
        else:
            subnet_prefix = self._get_subnet_prefix(entity)
            if subnet_prefix:
                for excluded_ip in self.exclude_ips:
                    excluded_prefix = self._get_subnet_prefix(excluded_ip)
                    if excluded_prefix and excluded_prefix == subnet_prefix:
                        if entity not in self.logged_skip_entities:
                            self._log(f"FIREWALL_SKIP {entity} (subnet contains excluded IP {excluded_ip})")
                            self.logged_skip_entities.add(entity)
                        return (True, False, display_name)
        
        if not is_windows():
            if entity not in self.logged_skip_entities:
                self._log(f"FIREWALL_SKIP {entity} (not Windows)")
                self.logged_skip_entities.add(entity)
            return (False, False, display_name)
        
        try:
            if is_subnet:
                remote_address = self._get_subnet_range(entity) or entity.split("/")[0]
            else:
                remote_address = entity
            
            # Check if rule already exists in Windows Firewall
            if self._check_firewall_rule_exists(display_name):
                if entity not in self.logged_skip_entities:
                    self._log(f"FIREWALL_SKIP {entity} (rule already exists in Windows Firewall, display_name={display_name})")
                    self.logged_skip_entities.add(entity)
                # Return tuple: (success, was_new_rule, display_name)
                return (True, False, display_name)
            
            # Create the firewall rule
            cmd = self._build_powershell_create_rule_cmd(display_name, remote_address)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self._log(f"FIREWALL_BLOCKED {entity} remote_address={remote_address} display_name={display_name}")
                # Return tuple: (success, was_new_rule, display_name)
                return (True, True, display_name)
            else:
                self._log(f"FIREWALL_ERROR {entity} stderr={result.stderr}")
                return (False, False, display_name)
                
        except subprocess.TimeoutExpired:
            self._log(f"FIREWALL_TIMEOUT {entity}", "WARNING")
            return (False, False, display_name)
        except (ValueError, subprocess.SubprocessError) as e:
            self._log(f"FIREWALL_EXCEPTION {entity} error={str(e)}", "ERROR")
            return (False, False, display_name)
    
    def list_firewall_rules(self, prefix: str = FIREWALL_PREFIX) -> List[Dict[str, Any]]:
        """List Windows Firewall rules matching the provided display name prefix."""
        if not is_windows():
            return []
        
        try:
            cmd = self._build_powershell_list_rules_cmd(prefix)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self._log(f"FIREWALL_LIST_ERROR stderr={result.stderr}")
                return []

            output = result.stdout.strip()
            if not output:
                return []

            parsed = json.loads(output)
            if isinstance(parsed, dict):
                parsed = [parsed]
            if not isinstance(parsed, list):
                return []
            
            # Normalize enum values for consistent frontend handling
            normalized = []
            for rule in parsed:
                norm_rule = dict(rule)
                # Normalize Direction: 1=Inbound, 2=Outbound
                if 'Direction' in norm_rule:
                    dir_val = norm_rule['Direction']
                    if isinstance(dir_val, str):
                        dir_lower = dir_val.lower()
                        if dir_lower == 'inbound':
                            norm_rule['Direction'] = 1
                        elif dir_lower == 'outbound':
                            norm_rule['Direction'] = 2
                    elif isinstance(dir_val, (int, float)):
                        norm_rule['Direction'] = int(dir_val)
                # Normalize Action: 0=NotConfigured, 1=Allow, 2=Block
                if 'Action' in norm_rule:
                    act_val = norm_rule['Action']
                    if isinstance(act_val, str):
                        act_lower = act_val.lower()
                        if act_lower in ('notconfigured', 'not configured'):
                            norm_rule['Action'] = 0
                        elif act_lower == 'allow':
                            norm_rule['Action'] = 1
                        elif act_lower == 'block':
                            norm_rule['Action'] = 2
                    elif isinstance(act_val, (int, float)):
                        norm_rule['Action'] = int(act_val)
                # Normalize Enabled: ensure boolean
                if 'Enabled' in norm_rule:
                    en_val = norm_rule['Enabled']
                    if isinstance(en_val, str):
                        norm_rule['Enabled'] = en_val.lower() in ('true', '1', 'yes')
                    elif isinstance(en_val, (int, float)):
                        norm_rule['Enabled'] = bool(en_val)
                normalized.append(norm_rule)
            return normalized
        except subprocess.TimeoutExpired:
            self._log("FIREWALL_LIST_TIMEOUT", "WARNING")
            return []
        except (ValueError, subprocess.SubprocessError, json.JSONDecodeError) as e:
            self._log(f"FIREWALL_LIST_EXCEPTION error={e}", "ERROR")
            return []

    def remove_firewall_rule(self, display_name: str) -> bool:
        """Remove a Windows Firewall rule by display name."""
        if not is_windows():
            return False
        try:
            cmd = self._build_powershell_remove_rule_cmd(display_name)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._log(f"FIREWALL_REMOVED display_name={display_name}")
                return True
            self._log(f"FIREWALL_REMOVE_ERROR display_name={display_name} stderr={result.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self._log(f"FIREWALL_REMOVE_TIMEOUT display_name={display_name}", "WARNING")
            return False
        except (ValueError, subprocess.SubprocessError) as e:
            self._log(f"FIREWALL_REMOVE_EXCEPTION display_name={display_name} error={e}", "ERROR")
            return False
    
    def _test_firewall_privileges(self) -> bool:
        """
        Test firewall rule creation/removal to verify Administrator privileges.
        Creates a test rule, verifies it exists, then removes it.
        Returns True if privileges are sufficient, False otherwise.
        """
        if not is_windows():
            return False
        
        test_ip = "192.0.2.1"  # Test-Net IP (RFC 5737) - safe to use for testing
        display_name = f"{FIREWALL_PREFIX}TEST_PRIV_CHECK"
        
        try:
            # Try to create a test firewall rule
            create_cmd = self._build_powershell_create_rule_cmd(display_name, test_ip)
            
            result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Rule created successfully, now verify it exists
                check_cmd = self._build_powershell_check_rule_cmd(display_name)
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                
                if check_result.returncode == 0 and check_result.stdout.strip():
                    # Rule exists, now remove it
                    remove_cmd = self._build_powershell_remove_rule_cmd(display_name)
                    remove_result = subprocess.run(remove_cmd, capture_output=True, text=True, timeout=10)
                    
                    if remove_result.returncode == 0:
                        self._log(f"FIREWALL_PRIV_CHECK SUCCESS (test rule created and removed)")
                        return True
                    else:
                        self._log(f"FIREWALL_PRIV_CHECK WARNING (rule created but removal failed: {remove_result.stderr})")
                        # Try to remove it anyway, but don't fail the check
                        return True
                else:
                    self._log(f"FIREWALL_PRIV_CHECK WARNING (rule created but verification failed)")
                    return True
            else:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                if "Access is denied" in error_msg or "PermissionDenied" in error_msg:
                    self._log(f"FIREWALL_PRIV_CHECK FAILED (Access denied - insufficient privileges)")
                else:
                    self._log(f"FIREWALL_PRIV_CHECK FAILED (error: {error_msg})")
                return False
                
        except subprocess.TimeoutExpired:
            self._log(f"FIREWALL_PRIV_CHECK FAILED (timeout)", "WARNING")
            return False
        except (ValueError, subprocess.SubprocessError) as e:
            self._log(f"FIREWALL_PRIV_CHECK FAILED (exception: {str(e)})", "ERROR")
            return False
    
    def _classify_severity(self, packet_count: int, unique_ports: int, suspicion_count: int) -> int:
        """
        Classify severity into 4 levels based only on history (suspicion count),
        with exponential growth starting from BASE_SUSPICION_COUNT.
        Level 0: below thresholds (no alert)
        Level 1-4: more windows flagged as suspicious => higher level.
        Exponential thresholds: BASE^(1), BASE^(3), BASE^(6), BASE^(9)
        """
        if suspicion_count < L1_THRESHOLD:
            return 0

        if suspicion_count >= L4_THRESHOLD:
            return 4
        if suspicion_count >= L3_THRESHOLD:
            return 3
        if suspicion_count >= L2_THRESHOLD:
            return 2
        return 1

    def _get_subnet_key(self, ip: str) -> Optional[str]:
        """Return a simple /16 subnet key (A.B.0.0/16) for IPv4 addresses, or None if not IPv4."""
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return f"{parts[0]}.{parts[1]}.0.0/{SUBNET_MASK}"
    
    def _get_subnet_prefix(self, entity: str) -> Optional[str]:
        """Extract the /16 subnet prefix (A.B) from an IP or subnet entity. Returns None if invalid."""
        if '/' in entity:
            base = entity.split("/")[0]
        else:
            base = entity
        parts = base.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return None
    
    def _get_subnet_range(self, subnet_entity: str) -> Optional[str]:
        """Convert a /16 subnet entity (A.B.0.0/16) to firewall range format (A.B.0.0-A.B.255.255)."""
        if '/' not in subnet_entity:
            return None
        base = subnet_entity.split("/")[0]
        parts = base.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.0.0-{parts[0]}.{parts[1]}.255.255"
        return None
    
    def _analyze_packet(self, packet: Any, src_ip: str, dst_ip: str, dst_port: Optional[int], proto: str) -> Dict[str, Any]:
        """Analyze a packet and extract relevant information."""
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "packet_size": len(packet) if hasattr(packet, '__len__') else 0,
        }
        
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                analysis["ip_version"] = ip_layer.version
                analysis["ip_ttl"] = ip_layer.ttl
                analysis["ip_flags"] = str(ip_layer.flags) if hasattr(ip_layer, 'flags') else None
                
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                analysis["tcp_flags"] = {
                    "SYN": bool(tcp_layer.flags & 0x02),
                    "ACK": bool(tcp_layer.flags & 0x10),
                    "FIN": bool(tcp_layer.flags & 0x01),
                    "RST": bool(tcp_layer.flags & 0x04),
                    "PSH": bool(tcp_layer.flags & 0x08),
                    "URG": bool(tcp_layer.flags & 0x20),
                }
                analysis["tcp_window"] = tcp_layer.window if hasattr(tcp_layer, 'window') else None
                analysis["tcp_seq"] = tcp_layer.seq if hasattr(tcp_layer, 'seq') else None
                
                # Check for payload
                if tcp_layer.payload and len(tcp_layer.payload) > 0:
                    payload_len = len(tcp_layer.payload)
                    analysis["has_payload"] = True
                    analysis["payload_size"] = payload_len
                    # Sample first 100 bytes of payload (if not encrypted)
                    if payload_len > 0:
                        try:
                            payload_bytes = bytes(tcp_layer.payload)[:100]
                            # Check if it looks like text
                            if all(32 <= b <= 126 or b in (9, 10, 13) for b in payload_bytes):
                                analysis["payload_preview"] = payload_bytes.decode('utf-8', errors='ignore')[:100]
                        except (UnicodeDecodeError, ValueError, AttributeError):
                            pass
                else:
                    analysis["has_payload"] = False
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                analysis["udp_length"] = udp_layer.len if hasattr(udp_layer, 'len') else None
                if udp_layer.payload and len(udp_layer.payload) > 0:
                    analysis["has_payload"] = True
                    analysis["payload_size"] = len(udp_layer.payload)
                else:
                    analysis["has_payload"] = False
                    
            # Check for common attack patterns
            if dst_port:
                if dst_port in [22, 23, 3389, 5900]:  # SSH, Telnet, RDP, VNC
                    analysis["suspicious_port"] = True
                if dst_port < 1024 and dst_port not in [80, 443, 53, 25, 110, 143]:  # Non-standard privileged ports
                    analysis["non_standard_privileged_port"] = True
                    
        except Exception as e:
            analysis["analysis_error"] = str(e)
            
        return analysis
    
    def _capture_sample_packet(self, packet: Any, entity: str, src_ip: str, dst_ip: str, dst_port: Optional[int], proto: str, now: datetime, packet_count_last_hour: int = 0) -> None:
        """Capture and analyze a sample packet for an entity (based on field uniqueness and rate limit)."""
        try:
            # Rate limit: only sample if packet count is above 500 in the last hour
            if packet_count_last_hour < 500:
                return  # Skip sampling - packet count too low
            
            # Create a unique key based on field combination
            # Normalize dst_port to handle None values
            dst_port_key = dst_port if dst_port is not None else 0
            combination_key = (src_ip, dst_ip, dst_port_key, proto)
            
            # Initialize sets if needed
            if entity not in self.sampled_combinations:
                self.sampled_combinations[entity] = set()
            
            # Only sample if this is a new unique combination
            if combination_key in self.sampled_combinations[entity]:
                return  # Already sampled this combination
            
            analysis = self._analyze_packet(packet, src_ip, dst_ip, dst_port, proto)
            
            if entity not in self.packet_samples:
                self.packet_samples[entity] = []
            
            self.packet_samples[entity].append(analysis)
            
            # Track this combination as sampled
            self.sampled_combinations[entity].add(combination_key)
            
            # Keep only last 10 samples per entity
            if len(self.packet_samples[entity]) > 10:
                # Remove oldest sample and its combination from tracking
                removed_sample = self.packet_samples[entity].pop(0)
                removed_key = (
                    removed_sample.get("src_ip", ""),
                    removed_sample.get("dst_ip", ""),
                    removed_sample.get("dst_port") if removed_sample.get("dst_port") is not None else 0,
                    removed_sample.get("protocol", "")
                )
                self.sampled_combinations[entity].discard(removed_key)
            
            # Queue IP for automatic IPinfo analysis (only for source IPs, not subnets)
            if not '/' in entity:  # Only IPs, not subnets
                try:
                    # Only queue public IPs (not private, loopback, link-local)
                    if not self._is_private_ip(entity):
                        if not self._is_ip_excluded(entity):
                            # Rate limiting: only queue if not analyzed recently (60 seconds)
                            last_analyze = self.last_auto_analyze_times.get(entity)
                            if not last_analyze or (now - last_analyze).total_seconds() >= 60:
                                with self.auto_analyze_lock:
                                    if entity not in [item['ip'] for item in self.auto_analyze_queue]:
                                        self.auto_analyze_queue.append({'ip': entity, 'timestamp': now})
                except (ValueError, AttributeError, KeyError):
                    pass  # Skip invalid IPs silently
                
        except Exception as e:
            self._log(f"Error capturing sample packet for {entity}: {e}")
    
    def get_packet_samples(self, entity: str) -> List[Dict[str, Any]]:
        """Get packet samples for an entity."""
        return self.packet_samples.get(entity, [])
    
    def _cleanup_old_packet_samples(self) -> None:
        """Remove packet samples older than configured days."""
        try:
            cutoff = datetime.utcnow() - timedelta(days=PACKET_SAMPLE_CLEANUP_DAYS)
            entities_to_remove = []
            
            for entity, samples in self.packet_samples.items():
                filtered_samples = []
                kept_combinations = set()
                
                for sample in samples:
                    try:
                        sample_time = datetime.fromisoformat(sample.get("timestamp", ""))
                        if sample_time >= cutoff:
                            filtered_samples.append(sample)
                            # Track which combinations are still in the filtered samples
                            combination_key = (
                                sample.get("src_ip", ""),
                                sample.get("dst_ip", ""),
                                sample.get("dst_port") if sample.get("dst_port") is not None else 0,
                                sample.get("protocol", "")
                            )
                            kept_combinations.add(combination_key)
                    except (ValueError, TypeError):
                        # Keep samples with invalid timestamps (shouldn't happen, but be safe)
                        filtered_samples.append(sample)
                        combination_key = (
                            sample.get("src_ip", ""),
                            sample.get("dst_ip", ""),
                            sample.get("dst_port") if sample.get("dst_port") is not None else 0,
                            sample.get("protocol", "")
                        )
                        kept_combinations.add(combination_key)
                
                if filtered_samples:
                    self.packet_samples[entity] = filtered_samples
                    # Update tracked combinations to only include those still in samples
                    self.sampled_combinations[entity] = kept_combinations
                else:
                    entities_to_remove.append(entity)
            
            for entity in entities_to_remove:
                self.packet_samples.pop(entity, None)
                self.sampled_combinations.pop(entity, None)
                
        except Exception as e:
            self._log(f"Error cleaning up old packet samples: {e}")

    def _process_entity_stats(
        self,
        stats: IpStats,
        entity: str,
        now: datetime,
        dst_port: Optional[int],
        detected_set: Set[str],
        firewall_suggestions: Dict[str, Dict[str, Any]],
        is_subnet: bool = False,
        packet: Optional[Any] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        proto: Optional[str] = None
    ) -> Tuple[int, bool]:
        """
        Process statistics for an entity (IP or subnet) and determine severity and alert status.
        Returns: (severity, should_alert)
        """
        with stats.lock:
            stats.packet_times.append(now)
            stats.packet_times_last_hour.append(now)
            if dst_port:
                stats.dst_ports.add(dst_port)
            
            # Clean old packet times (older than window)
            while stats.packet_times and now - stats.packet_times[0] > self.window:
                stats.packet_times.popleft()
            
            # Clean old packet times from last hour tracking (older than 1 hour)
            one_hour_ago = now - timedelta(hours=1)
            while stats.packet_times_last_hour and stats.packet_times_last_hour[0] < one_hour_ago:
                stats.packet_times_last_hour.popleft()
            
            packet_count = len(stats.packet_times)
            packet_count_last_hour = len(stats.packet_times_last_hour)
            unique_ports = len(stats.dst_ports)
            base_suspicious = packet_count >= self.max_packets or unique_ports >= self.max_ports
            window_start_sec = int(now.timestamp())
            
            # Detect significant packet count increase
            packet_count_increased = packet_count > stats.last_packet_count and packet_count >= self.max_packets
            stats.last_packet_count = packet_count
            
            # Capture sample packet if count increased significantly or first time suspicious
            # Skip sampling for subnets (only sample individual IPs)
            # Rate limit: only sample if packet count > 500 in last hour
            if not is_subnet and packet and src_ip and dst_ip and proto and (packet_count_increased or (base_suspicious and stats.first_suspicious is None)):
                self._capture_sample_packet(packet, entity, src_ip, dst_ip, dst_port, proto, now, packet_count_last_hour)
            
            severity = 0
            if base_suspicious:
                if stats.last_suspicious_window_start != window_start_sec:
                    stats.suspicion_count += 1
                    stats.last_suspicious_window_start = window_start_sec
                    if stats.first_suspicious is None:
                        stats.first_suspicious = now
                    stats.last_suspicious = now
            else:
                if stats.last_suspicious_window_start != window_start_sec and stats.suspicion_count > 0:
                    stats.suspicion_count -= 1
                    stats.last_suspicious_window_start = window_start_sec
            
            if stats.suspicion_count > 0:
                severity = self._classify_severity(packet_count, unique_ports, stats.suspicion_count)
            
            should_alert = False
            if severity > 0:
                if severity > stats.last_level:
                    should_alert = True
                elif stats.last_alert is None or now - stats.last_alert > self.alert_cooldown:
                    should_alert = True
            
            if should_alert:
                detected_set.add(entity)
                stats.last_alert = now
                stats.last_level = severity
                
                if severity >= L4_SEVERITY_LEVEL:
                    if entity not in firewall_suggestions:
                        firewall_suggestions[entity] = {
                            "added": now,
                            "is_subnet": is_subnet
                        }
                
                stats.dst_ports.clear()
            
            if stats.in_attack and severity < L3_SEVERITY_LEVEL:
                stats.in_attack = False
                first_ts = stats.first_suspicious.isoformat() if stats.first_suspicious else "unknown"
                last_ts = stats.last_suspicious.isoformat() if stats.last_suspicious else "unknown"
                duration_sec = 0.0
                if stats.first_suspicious and stats.last_suspicious:
                    duration_sec = (stats.last_suspicious - stats.first_suspicious).total_seconds()
                
                entity_type = "SUBNET" if is_subnet else "IP"
                self._log(
                    f"ATTACK_END {entity_type} {entity} last_level=L{stats.last_level} "
                    f"first_suspicious={first_ts} last_suspicious={last_ts} "
                    f"duration_sec={duration_sec:.2f}"
                )
            
            return severity, should_alert

    def _handle_firewall_block(self, entity: str, is_subnet: bool, now: datetime) -> None:
        """Handle firewall blocking and email alerts for L4 entities."""
        if not self.auto_block:
            return
        
        blocked, was_new_rule, display_name = self._add_firewall_rule(entity, is_subnet=is_subnet)
        
        if blocked and was_new_rule:
            if entity not in self.firewall_block_emails_sent:
                entity_type = "Subnet" if is_subnet else "IP"
                subject = f"🛡️ Firewall Block: {entity}"
                body = f"""Network Monitor Alert

Action: {entity_type} Blocked in Windows Firewall
{'Subnet' if is_subnet else 'IP Address'}: {entity}
Firewall Rule Name: {display_name}
Severity Level: L4
Time: {now.isoformat()}

The {entity_type.lower()} has been automatically blocked due to reaching L4 severity level.
"""
                self._send_email_alert(subject, body)
                self.firewall_block_emails_sent.add(entity)
        elif blocked and not was_new_rule:
            if entity not in self.email_skip_logged:
                self._log(f"Email alert skipped for {entity} (rule already existed)")
                self.email_skip_logged.add(entity)

    def process_packet(self, packet: Any) -> None:
        """Process a captured packet"""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Skip traffic sourced from excluded IPs (e.g., host's public IP or self IPs)
        if self._is_ip_excluded(src_ip):
            return

        dst_port = None
        proto = "OTHER"
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            proto = "TCP"
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            proto = "UDP"
        
        now = datetime.utcnow()

        stats_ip = self.stats[src_ip]
        subnet_key = self._get_subnet_key(src_ip)
        stats_subnet = self.subnet_stats[subnet_key] if subnet_key else None
        
        severity, should_alert = self._process_entity_stats(
            stats_ip, src_ip, now, dst_port,
            self.detected_ips, self.firewall_suggestions, is_subnet=False,
            packet=packet, src_ip=src_ip, dst_ip=dst_ip, proto=proto
        )
        
        if should_alert and severity >= L4_SEVERITY_LEVEL:
            self._handle_firewall_block(src_ip, is_subnet=False, now=now)

        if subnet_key and stats_subnet is not None:
            subnet_severity, subnet_alert = self._process_entity_stats(
                stats_subnet, subnet_key, now, dst_port,
                self.detected_subnets, self.firewall_suggestions, is_subnet=True,
                packet=packet, src_ip=src_ip, dst_ip=dst_ip, proto=proto
            )
            
            if subnet_alert and subnet_severity >= L4_SEVERITY_LEVEL:
                self._handle_firewall_block(subnet_key, is_subnet=True, now=now)
    
    def _check_entity_suspicious(self, stats: IpStats, now: datetime) -> Optional[Dict[str, Any]]:
        """Check if an entity (IP or subnet) is currently suspicious. Returns entity dict or None."""
        with stats.lock:
            while stats.packet_times and now - stats.packet_times[0] > self.window:
                stats.packet_times.popleft()
            
            packet_count = len(stats.packet_times)
            unique_ports = len(stats.dst_ports)

            base_suspicious = (
                packet_count >= self.max_packets
                or unique_ports >= self.max_ports
            )

            if base_suspicious and packet_count > 0:
                return {
                    'level': stats.last_level,
                    'packets': packet_count,
                    'ports': unique_ports,
                    'ports_set': stats.dst_ports.copy(),
                    'active': True,
                }
        return None

    def _get_current_suspicious(self) -> List[Dict[str, Any]]:
        """Get current suspicious IPs and subnets with their stats"""
        now = datetime.utcnow()
        suspicious = []
        
        for ip, stats in self.stats.items():
            entity_data = self._check_entity_suspicious(stats, now)
            if entity_data:
                entity_data['entity'] = ip
                entity_data['type'] = 'IP'
                suspicious.append(entity_data)
        
        for subnet, stats in self.subnet_stats.items():
            entity_data = self._check_entity_suspicious(stats, now)
            if entity_data:
                entity_data['entity'] = subnet
                entity_data['type'] = 'SUBNET'
                suspicious.append(entity_data)
        
        suspicious.sort(key=lambda x: (x['level'], x['packets']), reverse=True)
        return suspicious
    
    def _periodic_save(self) -> None:
        """Periodically save status to file"""
        while self.running:
            time.sleep(SAVE_INTERVAL_SECONDS)
            if self.running:
                self._save_status()
                self._cleanup_old_packet_samples()  # Cleanup old samples every minute
    
    def _display_table(self) -> None:
        """Display the dynamic table of suspicious IPs/subnets"""
        while self.running:
            time.sleep(DISPLAY_UPDATE_INTERVAL_SECONDS)
            
            suspicious = self._get_current_suspicious()
            
            with self.display_lock:
                # Clear screen using ANSI escape codes (cross-platform)
                print('\033[2J\033[H', end='')
                
                # Print header
                print("=" * 110)
                print(f"{'L1':<26} {'L2':<26} {'L3':<26} {'L4':<26}")
                print("=" * 110)

                if not suspicious:
                    print("No suspicious activity detected.")
                else:
                    for item in suspicious:
                        level = item['level']
                        packets = item['packets']
                        ports_set = item.get('ports_set', set())
                        is_active = item.get('active', False)

                        # Show port number with 'p' prefix if single port, otherwise show count
                        if len(ports_set) == 1:
                            single_port = list(ports_set)[0]
                            port_name = COMMON_PORTS.get(single_port, str(single_port))
                            port_display = f"p{port_name}"
                        else:
                            port_display = str(len(ports_set))

                        suffix = "" if is_active else " [inactive]"
                        cell = f"{item['entity']} {packets}({port_display}){suffix}"

                        l1_val = cell if level == 1 else ""
                        l2_val = cell if level == 2 else ""
                        l3_val = cell if level == 3 else ""
                        l4_val = cell if level == 4 else ""

                        print(
                            f"{l1_val:<26}"
                            f"{l2_val:<26}"
                            f"{l3_val:<26}"
                            f"{l4_val:<26}"
                        )

                print("=" * 110)
                
                # Display firewall suggestions for L4 entities
                if self.firewall_suggestions:
                    print("\nNew L4 Entries Added:")
                    print("-" * 110)
                    for entity, info in sorted(self.firewall_suggestions.items(), key=lambda x: x[1]["added"]):
                        added_time = info["added"].strftime("%Y-%m-%d %H:%M:%S UTC")
                        entity_type = "SUBNET" if info["is_subnet"] else "IP"
                        print(f"  [{added_time}] {entity_type}: {entity}")
                    print("-" * 110)
                
                print("\nPress Ctrl+C to stop.")
    
    def start(self, interface: Optional[str] = None, interface_id: Optional[str] = None) -> None:
        """Start monitoring on the specified interface"""
        if interface is None:
            interfaces = get_if_list()
            if not interfaces:
                print("No network interfaces found. Make sure Npcap is installed.")
                sys.exit(1)

            # On Windows, try to show friendly names and IPs using get_windows_if_list
            win_if_info = []
            if is_windows():
                try:
                    from scapy.arch.windows import get_windows_if_list  # type: ignore
                    win_if_info = get_windows_if_list()
                except (ImportError, AttributeError, OSError):
                    win_if_info = []

            print("Available interfaces:")
            indexed = []
            for i, iface in enumerate(interfaces):
                desc = iface
                ip_addr = ""

                # Try to match Npcap device to Windows info using GUID fragment
                if win_if_info:
                    for w in win_if_info:
                        guid = (w.get("guid") or "").strip("{}")
                        if guid and guid.lower() in iface.lower():
                            desc = w.get("description") or w.get("name") or iface
                            ip_addr = w.get("ip") or ""
                            break

                if ip_addr:
                    print(f"  {i}: {desc} [{ip_addr}] ({iface})")
                else:
                    print(f"  {i}: {desc} ({iface})")

                indexed.append(iface)

            # If interface_id was provided via command line, use it
            if interface_id is not None:
                try:
                    idx = int(interface_id)
                    if idx < 0 or idx >= len(indexed):
                        print(f"Invalid interface index: {idx}. Valid range: 0-{len(indexed)-1}")
                        sys.exit(1)
                    interface = indexed[idx]
                    print(f"\nUsing interface {idx}: {indexed[idx]}")
                except ValueError:
                    # Try to match by name/description
                    found = False
                    for i, iface in enumerate(indexed):
                        if interface_id.lower() in iface.lower():
                            interface = iface
                            print(f"\nUsing interface {i}: {iface}")
                            found = True
                            break
                    if not found:
                        print(f"Interface '{interface_id}' not found.")
                        sys.exit(1)
            else:
                # Interactive selection
                try:
                    choice = input("Select interface index (or press Enter for all): ").strip()
                    if choice:
                        idx = int(choice)
                        if idx < 0 or idx >= len(indexed):
                            print("Invalid index.")
                            sys.exit(1)
                        interface = indexed[idx]
                    else:
                        interface = None
                except (ValueError, KeyboardInterrupt):
                    print("Invalid selection or cancelled.")
                    sys.exit(1)
        
        print(f"\nMonitoring traffic on: {interface if interface else 'all interfaces'}")
        
        # Test firewall privileges if auto-block is enabled
        if self.auto_block:
            self._test_firewall_privileges()
        
        print("Starting dynamic display...\n")
        
        self.running = True
        display_thread = Thread(target=self._display_table, daemon=True)
        display_thread.start()
        save_thread = Thread(target=self._periodic_save, daemon=True)
        save_thread.start()
        
        try:
            sniff(iface=interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            self.running = False
            time.sleep(DISPLAY_SHUTDOWN_WAIT_SECONDS)
            print("\n\nStopping monitor...")
            self._save_status()  # Save status on shutdown
            print(f"\nTotal suspicious IPs detected: {len(self.detected_ips)}")
            if self.detected_ips:
                print("\nDetected IPs:")
                for ip in sorted(self.detected_ips):
                    print(f"  {ip}")


def _load_env_file(env_path: str) -> None:
    """Load environment variables from a .env file using python-dotenv when available."""
    if DOTENV_AVAILABLE:
        if os.path.exists(env_path):
            load_dotenv(env_path)
        return

    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and value and key not in os.environ:
                        os.environ[key] = value
    except (OSError, ValueError, KeyError):
        pass


def _collect_exclude_ips(args: argparse.Namespace) -> Optional[List[str]]:
    """Merge exclude IPs from CLI args and environment."""
    exclude_ips = None
    if args.exclude_ip:
        exclude_ips = []
        for ip_arg in args.exclude_ip:
            exclude_ips.extend([ip.strip() for ip in ip_arg.split(",") if ip.strip()])

    if exclude_ips is None:
        env_exclude = os.getenv("EXCLUDE_IP")
        if env_exclude:
            exclude_ips = [ip.strip() for ip in env_exclude.split(",") if ip.strip()]

    return exclude_ips


def _build_email_settings(args: argparse.Namespace) -> Dict[str, Any]:
    """Compose email configuration from args and environment."""
    smtp_server = args.email_smtp_server or os.getenv("EMAIL_SMTP_SERVER")
    smtp_port = args.email_smtp_port
    env_port = os.getenv("EMAIL_SMTP_PORT")
    if env_port:
        try:
            smtp_port = int(env_port)
        except ValueError:
            pass

    username = args.email_username or os.getenv("EMAIL_USERNAME")
    password = args.email_password or os.getenv("EMAIL_PASSWORD")
    sender = args.email_from or os.getenv("EMAIL_FROM")

    recipients = None
    if args.email_to:
        recipients = []
        for email_arg in args.email_to:
            recipients.extend([email.strip() for email in email_arg.split(",") if email.strip()])
    elif os.getenv("EMAIL_TO"):
        recipients = [email.strip() for email in os.getenv("EMAIL_TO").split(",") if email.strip()]

    use_tls = not args.email_no_tls
    if os.getenv("EMAIL_USE_TLS", "").lower() in ("false", "0", "no"):
        use_tls = False

    return {
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "username": username,
        "password": password,
        "sender": sender,
        "recipients": recipients,
        "use_tls": use_tls,
    }


def get_port_name(port: int) -> str:
    """Get the protocol name for a port number, or return the port number as string."""
    return COMMON_PORTS.get(port, str(port))

def create_web_app(monitor: NetworkMonitor, interface_id: Optional[str] = None, firewall_prefix: str = FIREWALL_PREFIX) -> "FastAPI":
    """
    Build a FastAPI app around a NetworkMonitor instance.
    Only available when FastAPI/uvicorn are installed.
    """
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI/uvicorn are not installed. Install fastapi and uvicorn to use --web-ui mode.")

    app = FastAPI(title="net_monitor web UI", version="1.0.0")
    monitor_thread: Optional[Thread] = None
    # Store up to 24h of per-minute severity history (24 * 60 buckets)
    traffic_history = deque(maxlen=24 * 60)
    last_history_bucket: Optional[str] = None
    # Track last-seen entities for up to 24 hours (IP and SUBNET),
    # including approximate packet totals over that period.
    recent_entities = {}
    # Store rolling window data for traffic table, talkers, and ports (5-minute window)
    window_entries_history = deque(maxlen=300)  # 5 minutes at 1 second intervals
    window_talkers_history = deque(maxlen=300)
    window_ports_history = deque(maxlen=300)
    # Cache firewall rule names to avoid calling PowerShell on every WebSocket update
    cached_firewall_rule_names: Set[str] = set()
    last_firewall_cache_update: datetime = datetime.utcnow() - timedelta(seconds=60)

    def _require_windows():
        if not is_windows():
            raise HTTPException(status_code=400, detail="Firewall management is supported on Windows only")

    async def analyze_ip_info_only_internal(ip: str) -> None:
        """Internal function to analyze IP with IPinfo (same logic as endpoint but no return)."""
        try:
            is_private = monitor._is_private_ip(ip)
            is_excluded = monitor._is_ip_excluded(ip)

            # Skip private/excluded IPs
            if is_private or is_excluded:
                return
            
            # Check cache first
            cached_result = get_cached_analysis(ip)
            if cached_result:
                # Check if IPinfo service exists in cache
                for service in cached_result.get("services", []):
                    if service.get("service") == "IPinfo":
                        return  # Already cached
            
            if not HTTPX_AVAILABLE:
                return
            
            api_key = os.getenv("IPINFO_API_KEY")
            ipinfo_result = await query_ipinfo(ip, api_key)
            ipinfo_result["ip"] = ip
            
            # Save to cache
            cache_result = {
                "ip": ip,
                "is_private": False,
                "is_excluded": False,
                "status": "info" if ipinfo_result.get("status") == "info" else "unknown",
                "message": "Public IP",
                "services": [ipinfo_result]
            }
            save_analysis_result(ip, cache_result)
            
        except Exception as e:
            monitor._log(f"Error in internal IPinfo analysis for {ip}: {e}")
    
    async def process_auto_ipinfo_analysis():
        """Background task to automatically analyze IPs with IPinfo."""
        await asyncio.sleep(AUTO_ANALYZE_INITIAL_DELAY_SECONDS)
        while True:
            try:
                await asyncio.sleep(AUTO_ANALYZE_CHECK_INTERVAL_SECONDS)
                
                # Get IPs from queue (thread-safe)
                ips_to_analyze = []
                with monitor.auto_analyze_lock:
                    while monitor.auto_analyze_queue:
                        item = monitor.auto_analyze_queue.popleft()
                        ip = item['ip']
                        # Skip if analyzed recently (60 seconds rate limit)
                        last_analyze = monitor.last_auto_analyze_times.get(ip)
                        if not last_analyze or (datetime.utcnow() - last_analyze).total_seconds() >= 60:
                            ips_to_analyze.append(ip)
                
                # Process IPs in parallel (up to 20 at a time) for faster analysis
                if ips_to_analyze:
                    tasks = []
                    for ip in ips_to_analyze[:20]:
                        tasks.append(analyze_ip_info_only_internal(ip))
                        monitor.last_auto_analyze_times[ip] = datetime.utcnow()
                    
                    # Execute all tasks in parallel
                    await asyncio.gather(*tasks, return_exceptions=True)
                        
            except Exception as e:
                await asyncio.sleep(AUTO_ANALYZE_ERROR_WAIT_SECONDS)
    
    @app.on_event("startup")
    async def _startup():
        nonlocal monitor_thread
        cleanup_expired_analysis_cache()
        if not monitor.running:
            monitor_thread = Thread(target=monitor.start, kwargs={"interface_id": interface_id}, daemon=True)
            monitor_thread.start()
        
        # Start background task for auto IPinfo analysis
        if HTTPX_AVAILABLE:
            asyncio.create_task(process_auto_ipinfo_analysis())
            monitor._log("IPinfo auto-analysis background task started")
        else:
            monitor._log("IPinfo auto-analysis disabled (httpx not available)", "WARNING")

    @app.on_event("shutdown")
    def _shutdown():
        monitor.running = False
        try:
            monitor._save_status()
        except (sqlite3.Error, OSError):
            pass

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/exclusions")
    def list_exclusions():
        return monitor.list_excluded_ips()

    @app.post("/api/exclusions", status_code=201)
    def add_exclusion(payload: dict):
        ip = payload.get("ip") or ""
        note = payload.get("note")
        added = monitor.add_excluded_ip(ip, note)
        if not added:
            raise HTTPException(status_code=400, detail="Invalid IP or failed to save exclusion")
        return {"ip": ip, "note": note}

    @app.delete("/api/exclusions/{ip:path}")
    def delete_exclusion(ip: str):
        removed = monitor.remove_excluded_ip(ip)
        if not removed:
            raise HTTPException(status_code=404, detail="IP not found")
        return {"removed": ip}

    @app.get("/api/firewall-rules")
    def get_firewall_rules():
        _require_windows()
        rules = monitor.list_firewall_rules(prefix=firewall_prefix)
        # Update cache when explicitly requested
        nonlocal cached_firewall_rule_names, last_firewall_cache_update
        cached_firewall_rule_names.clear()
        for r in rules:
            name = r.get("DisplayName") or r.get("display_name")
            if name:
                cached_firewall_rule_names.add(name)
        last_firewall_cache_update = datetime.utcnow()
        return rules

    @app.post("/api/firewall-rules", status_code=201)
    def add_firewall_rule(payload: dict):
        _require_windows()
        entity = payload.get("entity") or ""
        is_subnet = bool(payload.get("is_subnet", False))
        success, was_new, display_name = monitor._add_firewall_rule(entity, is_subnet=is_subnet)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add firewall rule")
        # Update cache when rule is added
        if success and display_name:
            nonlocal cached_firewall_rule_names
            cached_firewall_rule_names.add(display_name)
        return {"display_name": display_name, "created": was_new}

    @app.delete("/api/firewall-rules/{display_name}")
    def delete_firewall_rule(display_name: str):
        _require_windows()
        removed = monitor.remove_firewall_rule(display_name)
        if not removed:
            raise HTTPException(status_code=404, detail="Firewall rule not found or could not be removed")
        # Update cache when rule is removed
        nonlocal cached_firewall_rule_names
        cached_firewall_rule_names.discard(display_name)
        return {"removed": display_name}

    @app.get("/api/packet-samples/{entity}")
    def get_packet_samples(entity: str):
        """Get packet samples for a specific entity."""
        samples = monitor.get_packet_samples(entity)
        # Add entity to each sample for display
        for sample in samples:
            sample["entity"] = entity
        return {"entity": entity, "samples": samples, "count": len(samples)}
    
    @app.get("/api/packet-samples")
    def list_packet_samples(page: int = 1, page_size: int = 25, search_query: Optional[str] = None):
        """List packet samples with pagination, search, and include IPinfo results."""
        all_samples = []
        ips_to_lookup = []
        sample_ip_map = []
        
        for entity, samples in monitor.packet_samples.items():
            for sample in samples:
                sample_copy = dict(sample)
                sample_copy["entity"] = entity
                src_ip = sample_copy.get("src_ip") or entity
                if src_ip and not '/' in src_ip:  # Only for IPs, not subnets
                    ips_to_lookup.append(src_ip)
                    sample_ip_map.append((len(all_samples), src_ip))
                all_samples.append(sample_copy)
        
        # Batch fetch all IPinfo cache entries in one query
        if ips_to_lookup:
            cached_results = get_batch_cached_analyses(ips_to_lookup)
            for sample_idx, src_ip in sample_ip_map:
                cached_result = cached_results.get(src_ip)
                if cached_result:
                    # Extract IPinfo service from cached result
                    for service in cached_result.get("services", []):
                        if service.get("service") == "IPinfo":
                            all_samples[sample_idx]["ipinfo"] = {
                                "status": service.get("status"),
                                "message": service.get("message", "")
                            }
                            break
        
        # Apply search filter if provided
        if search_query and search_query.strip():
            search_lower = search_query.lower().strip()
            filtered_samples = []
            for sample in all_samples:
                # Search across multiple fields
                searchable_text = " ".join([
                    str(sample.get("entity", "")),
                    str(sample.get("src_ip", "")),
                    str(sample.get("dst_ip", "")),
                    str(sample.get("protocol", "")),
                    str(sample.get("dst_port", "")),
                    str(sample.get("packet_size", "")),
                    str(sample.get("timestamp", "")),
                ]).lower()
                if search_lower in searchable_text:
                    filtered_samples.append(sample)
            all_samples = filtered_samples
        
        # Sort by timestamp descending (newest first)
        all_samples.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        total_samples = len(all_samples)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_samples = all_samples[start_idx:end_idx]
        
        total_pages = (total_samples + page_size - 1) // page_size if page_size > 0 else 0
        
        # For DataTables server-side processing, return in expected format
        return {
            "samples": paginated_samples,
            "total_samples": total_samples,
            "total_entities": len(monitor.packet_samples),
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            # DataTables format
            "recordsTotal": total_samples,
            "recordsFiltered": total_samples,
            "data": paginated_samples
        }
    
    async def query_abuseipdb(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        if not api_key:
            error_msg = "API key not configured"
            monitor._log(f"AbuseIPDB API for {ip}: {error_msg}")
            return {"service": "AbuseIPDB", "status": "no_key", "message": error_msg}
        
        if not HTTPX_AVAILABLE:
            error_msg = "httpx not available"
            monitor._log(f"AbuseIPDB API error for {ip}: {error_msg}")
            return {"service": "AbuseIPDB", "status": "error", "message": error_msg}
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers={"Key": api_key, "Accept": "application/json"}
                )
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data:
                        abuse_confidence = data["data"].get("abuseConfidencePercentage", 0)
                        usage_type = data["data"].get("usageType", "Unknown")
                        is_whitelisted = data["data"].get("isWhitelisted", False)
                        
                        if abuse_confidence >= 75:
                            status = "malicious"
                            message = f"{abuse_confidence}% abuse"
                        elif abuse_confidence >= 25:
                            status = "suspicious"
                            message = f"{abuse_confidence}% abuse"
                        elif is_whitelisted:
                            status = "safe"
                            message = "Whitelisted"
                        else:
                            status = "clean"
                            message = f"{usage_type} ({abuse_confidence}% abuse)"
                        
                        return {
                            "service": "AbuseIPDB",
                            "status": status,
                            "message": message,
                            "abuse_confidence": abuse_confidence,
                            "usage_type": usage_type
                        }
                
                # Log error response
                try:
                    error_data = response.json()
                    error_body = str(error_data)[:200]
                except (ValueError, AttributeError, KeyError):
                    error_body = response.text[:200] if hasattr(response, 'text') else "No response body"
                
                error_msg = f"HTTP {response.status_code}"
                monitor._log(f"AbuseIPDB API error for {ip}: {error_msg}, response: {error_body}")
                return {"service": "AbuseIPDB", "status": "error", "message": error_msg}
        except Exception as e:
            error_msg = str(e)[:100]
            monitor._log(f"AbuseIPDB API exception for {ip}: {error_msg}")
            return {"service": "AbuseIPDB", "status": "error", "message": error_msg[:50]}
    
    async def query_virustotal(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
        """Query VirusTotal for IP reputation."""
        if not api_key:
            error_msg = "API key not configured"
            monitor._log(f"VirusTotal API for {ip}: {error_msg}")
            return {"service": "VirusTotal", "status": "no_key", "message": error_msg}
        
        if not HTTPX_AVAILABLE:
            error_msg = "httpx not available"
            monitor._log(f"VirusTotal API error for {ip}: {error_msg}")
            return {"service": "VirusTotal", "status": "error", "message": error_msg}
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": api_key}
                )
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "attributes" in data["data"]:
                        attrs = data["data"]["attributes"]
                        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        suspicious = attrs.get("last_analysis_stats", {}).get("suspicious", 0)
                        total = sum(attrs.get("last_analysis_stats", {}).values())
                        
                        if malicious > 0:
                            status = "malicious"
                            message = f"{malicious}/{total} engines"
                        elif suspicious > 0:
                            status = "suspicious"
                            message = f"{suspicious}/{total} suspicious"
                        else:
                            status = "clean"
                            message = f"0/{total} detections"
                        
                        return {
                            "service": "VirusTotal",
                            "status": status,
                            "message": message,
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "total": total
                        }
                elif response.status_code == 404:
                    return {"service": "VirusTotal", "status": "clean", "message": "Not found"}
                
                # Log error response
                try:
                    error_data = response.json()
                    error_body = str(error_data)[:200]
                except (ValueError, AttributeError, KeyError):
                    error_body = response.text[:200] if hasattr(response, 'text') else "No response body"
                
                error_msg = f"HTTP {response.status_code}"
                monitor._log(f"VirusTotal API error for {ip}: {error_msg}, response: {error_body}")
                return {"service": "VirusTotal", "status": "error", "message": error_msg}
        except Exception as e:
            error_msg = str(e)[:100]
            monitor._log(f"VirusTotal API exception for {ip}: {error_msg}")
            return {"service": "VirusTotal", "status": "error", "message": error_msg[:50]}
    
    async def query_ipinfo(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
        """Query IPinfo for IP information."""
        if not HTTPX_AVAILABLE:
            error_msg = "httpx not available"
            return {"service": "IPinfo", "status": "error", "message": error_msg}
        
        try:
            url = f"https://ipinfo.io/{ip}/json"
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            
            # Use longer timeout for IPinfo (15s connect, 30s read) since it can be slow
            timeout = httpx.Timeout(15.0, connect=10.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    org = data.get("org", "Unknown")
                    country = data.get("country", "Unknown")
                    city = data.get("city", "")
                    
                    message_parts = [org]
                    if city:
                        message_parts.append(city)
                    if country:
                        message_parts.append(country)
                    
                    result = {
                        "service": "IPinfo",
                        "status": "info",
                        "message": ", ".join(message_parts[:2]),
                        "org": org,
                        "country": country,
                        "city": city
                    }
                    monitor._log(f"IPinfo API success for {ip}: {result['message']}")
                    return result
                
                # Log error response
                try:
                    error_data = response.json()
                    error_body = str(error_data)[:200]
                except (ValueError, AttributeError, KeyError):
                    error_body = response.text[:200] if hasattr(response, 'text') else "No response body"
                
                error_msg = f"HTTP {response.status_code}"
                return {"service": "IPinfo", "status": "error", "message": error_msg}
        except httpx.TimeoutException as e:
            error_msg = "Connection timeout (15s exceeded)"
            return {"service": "IPinfo", "status": "error", "message": error_msg, "error_type": "Timeout"}
        except httpx.ConnectError as e:
            error_msg = f"Connection failed - {str(e) if str(e) else 'Unable to reach server'}"
            return {"service": "IPinfo", "status": "error", "message": error_msg, "error_type": "Connection failed"}
        except httpx.HTTPError as e:
            error_msg = f"HTTP error - {str(e) if str(e) else repr(e)}"
            return {"service": "IPinfo", "status": "error", "message": error_msg[:50], "error_type": type(e).__name__}
        except Exception as e:
            error_msg = str(e) if str(e) else repr(e)
            error_msg = error_msg[:200]
            exception_type = type(e).__name__
            fallback_msg = error_msg[:50] if error_msg and error_msg.strip() else exception_type
            return {"service": "IPinfo", "status": "error", "message": fallback_msg, "error_type": exception_type}
    
    async def query_shodan(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
        """Query Shodan for IP information."""
        if not api_key:
            error_msg = "API key not configured"
            monitor._log(f"Shodan API for {ip}: {error_msg}")
            return {"service": "Shodan", "status": "no_key", "message": error_msg}
        
        if not HTTPX_AVAILABLE:
            error_msg = "httpx not available"
            monitor._log(f"Shodan API error for {ip}: {error_msg}")
            return {"service": "Shodan", "status": "error", "message": error_msg}
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": api_key}
                )
                if response.status_code == 200:
                    data = response.json()
                    org = data.get("org", "Unknown")
                    country = data.get("country_name", "Unknown")
                    vulns = data.get("vulns", [])
                    tags = data.get("tags", [])
                    
                    message_parts = [org]
                    if country:
                        message_parts.append(country)
                    
                    status = "info"
                    if vulns:
                        status = "suspicious"
                        message_parts.append(f"{len(vulns)} vulns")
                    elif "malware" in tags or "honeypot" in tags:
                        status = "suspicious"
                    
                    return {
                        "service": "Shodan",
                        "status": status,
                        "message": ", ".join(message_parts[:2]),
                        "org": org,
                        "country": country,
                        "vulns_count": len(vulns),
                        "tags": tags
                    }
                elif response.status_code == 404:
                    return {"service": "Shodan", "status": "clean", "message": "Not found"}
                
                # Log error response
                try:
                    error_data = response.json()
                    error_body = str(error_data)[:200]
                except (ValueError, AttributeError, KeyError):
                    error_body = response.text[:200] if hasattr(response, 'text') else "No response body"
                
                error_msg = f"HTTP {response.status_code}"
                monitor._log(f"Shodan API error for {ip}: {error_msg}, response: {error_body}")
                return {"service": "Shodan", "status": "error", "message": error_msg}
        except Exception as e:
            error_msg = str(e)[:100]
            monitor._log(f"Shodan API exception for {ip}: {error_msg}")
            return {"service": "Shodan", "status": "error", "message": error_msg[:50]}
    
    def get_cached_analysis(ip: str) -> Optional[Dict[str, Any]]:
        """Get cached IP analysis result if still valid."""
        try:
            with sqlite3.connect(monitor.status_db_path) as conn:
                conn.row_factory = sqlite3.Row
                now = datetime.utcnow().isoformat()
                row = conn.execute(
                    """
                    SELECT result_json, analyzed_at, expires_at 
                    FROM ip_analysis_cache 
                    WHERE ip = ? AND expires_at > ?
                    """,
                    (ip, now)
                ).fetchone()
                
                if row:
                    result = json.loads(row["result_json"])
                    result["cached"] = True
                    result["analyzed_at"] = row["analyzed_at"]
                    return result
        except Exception as e:
            monitor._log(f"Error reading IP analysis cache: {e}")
        return None
    
    def get_batch_cached_analyses(ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get cached IP analysis results for multiple IPs in a single query."""
        if not ips:
            return {}
        result_map = {}
        try:
            with sqlite3.connect(monitor.status_db_path) as conn:
                conn.row_factory = sqlite3.Row
                now = datetime.utcnow().isoformat()
                placeholders = ','.join('?' * len(ips))
                rows = conn.execute(
                    f"""
                    SELECT ip, result_json, analyzed_at, expires_at 
                    FROM ip_analysis_cache 
                    WHERE ip IN ({placeholders}) AND expires_at > ?
                    """,
                    tuple(ips) + (now,)
                ).fetchall()
                
                for row in rows:
                    try:
                        result = json.loads(row["result_json"])
                        result["cached"] = True
                        result["analyzed_at"] = row["analyzed_at"]
                        result_map[row["ip"]] = result
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception as e:
            monitor._log(f"Error reading batch IP analysis cache: {e}")
        return result_map
    
    def save_analysis_result(ip: str, result: Dict[str, Any]) -> None:
        """Save IP analysis result to cache and log it."""
        try:
            now = datetime.utcnow()
            expires_at = now + timedelta(days=IP_ANALYSIS_CACHE_EXPIRY_DAYS)
            
            result_copy = dict(result)
            result_copy.pop("cached", None)
            result_json = json.dumps(result_copy)
            
            with sqlite3.connect(monitor.status_db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ip_analysis_cache 
                    (ip, result_json, analyzed_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (ip, result_json, now.isoformat(), expires_at.isoformat())
                )
                conn.commit()
            
            services_summary = []
            for service in result.get("services", []):
                service_name = service.get("service", "Unknown")
                service_status = service.get("status", "unknown")
                service_msg = service.get("message", "")
                # Use error_type if message is empty and status is error
                if not service_msg or not service_msg.strip():
                    if service_status == "error":
                        service_msg = service.get("error_type", "Unknown error")
                    else:
                        service_msg = "N/A"
                services_summary.append(f"{service_name}:{service_status}({service_msg})")
            
            monitor._log(
                f"IP Analysis [{ip}]: status={result.get('status', 'unknown')}, "
                f"services=[{', '.join(services_summary)}]"
            )
        except Exception as e:
            monitor._log(f"Error saving IP analysis cache: {e}")
    
    def cleanup_expired_analysis_cache() -> None:
        """Remove expired analysis cache entries."""
        try:
            with sqlite3.connect(monitor.status_db_path) as conn:
                now = datetime.utcnow().isoformat()
                cursor = conn.execute(
                    "DELETE FROM ip_analysis_cache WHERE expires_at <= ?",
                    (now,)
                )
                deleted = cursor.rowcount
                if deleted > 0:
                    conn.commit()
                    monitor._log(f"Cleaned up {deleted} expired IP analysis cache entries")
        except Exception as e:
            monitor._log(f"Error cleaning up IP analysis cache: {e}")
    
    @app.get("/api/analyze-ip-info/{ip}")
    async def analyze_ip_info_only(ip: str):
        """Automatic IPinfo-only analysis (no API key required, free tier)."""
        try:
            is_private = monitor._is_private_ip(ip)
            is_excluded = ip in monitor.exclude_ips
            
            # Return immediately for private/excluded IPs without any analysis
            if is_private:
                return {
                    "ip": ip,
                    "service": "IPinfo",
                    "status": "safe",
                    "message": "Private/Local IP"
                }
            
            if is_excluded:
                return {
                    "ip": ip,
                    "service": "IPinfo",
                    "status": "safe",
                    "message": "Excluded IP"
                }
            
            # Check cache first
            cached_result = get_cached_analysis(ip)
            if cached_result:
                # Extract IPinfo service from cached result if available
                for service in cached_result.get("services", []):
                    if service.get("service") == "IPinfo":
                        return {
                            "ip": ip,
                            "service": "IPinfo",
                            "status": service.get("status", "info"),
                            "message": service.get("message", "")
                        }
            
            if not HTTPX_AVAILABLE:
                error_msg = "httpx not available"
                return {
                    "ip": ip,
                    "service": "IPinfo",
                    "status": "error",
                    "message": error_msg
                }
            
            api_key = os.getenv("IPINFO_API_KEY")
            ipinfo_result = await query_ipinfo(ip, api_key)
            ipinfo_result["ip"] = ip
            
            # Save to cache for future use (even if error, to avoid repeated failed queries)
            cache_result = {
                "ip": ip,
                "is_private": False,
                "is_excluded": False,
                "status": "info" if ipinfo_result.get("status") == "info" else "unknown",
                "message": "Public IP",
                "services": [ipinfo_result]
            }
            save_analysis_result(ip, cache_result)
            
            return ipinfo_result
        except ValueError as e:
            monitor._log(f"Invalid IP address in analyze_ip_info_only: {ip} - {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid IP address")
        except Exception as e:
            error_msg = str(e)[:100]
            monitor._log(f"Unexpected error in analyze_ip_info_only for {ip}: {error_msg}")
            return {
                "ip": ip,
                "service": "IPinfo",
                "status": "error",
                "message": "Internal error"
            }
    
    @app.get("/api/analyze-ip/{ip}")
    async def analyze_ip(ip: str):
        """Full analysis of an IP address using multiple threat intelligence services (with rate limiting).
        Only called when user explicitly requests analysis - no automatic API calls."""
        try:
            is_private = monitor._is_private_ip(ip)
            is_excluded = monitor._is_ip_excluded(ip)

            # Return immediately for private/excluded IPs without any analysis or cache operations
            if is_private:
                return {
                    "ip": ip,
                    "is_private": True,
                    "is_excluded": False,
                    "status": "safe",
                    "message": "Private/Local IP",
                    "services": []
                }
            
            if is_excluded:
                return {
                    "ip": ip,
                    "is_private": False,
                    "is_excluded": True,
                    "status": "safe",
                    "message": "Excluded IP",
                    "services": []
                }
            
            result = {
                "ip": ip,
                "is_private": False,
                "is_excluded": False,
                "status": "unknown",
                "services": []
            }
            
            cached_result = get_cached_analysis(ip)
            if cached_result:
                return cached_result
            
            # Rate limiting: check if we've analyzed this IP recently (even if not cached)
            now = datetime.utcnow()
            ANALYSIS_COOLDOWN = 60  # Minimum seconds between API calls for same IP
            last_analysis = recent_entities.get(f"_analysis_{ip}")
            if last_analysis:
                try:
                    if isinstance(last_analysis, datetime):
                        time_since_last = (now - last_analysis).total_seconds()
                    else:
                        time_since_last = (now - datetime.fromisoformat(last_analysis)).total_seconds()
                    if time_since_last < ANALYSIS_COOLDOWN:
                        # Return a rate-limited response instead of making API calls
                        result["message"] = "Public IP (rate limited)"
                        result["rate_limited"] = True
                        result["retry_after"] = int(ANALYSIS_COOLDOWN - time_since_last)
                        return result
                except (ValueError, TypeError):
                    pass
            
            if not HTTPX_AVAILABLE:
                result["message"] = "Public IP (httpx not available)"
                save_analysis_result(ip, result)
                return result
            
            result["message"] = "Public IP"
            
            api_keys = {
                "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
                "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
                "ipinfo": os.getenv("IPINFO_API_KEY"),
                "shodan": os.getenv("SHODAN_API_KEY")
            }
            
            tasks = [
                query_abuseipdb(ip, api_keys["abuseipdb"]),
                query_virustotal(ip, api_keys["virustotal"]),
                query_ipinfo(ip, api_keys["ipinfo"]),
                query_shodan(ip, api_keys["shodan"])
            ]
            
            service_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for service_result in service_results:
                if isinstance(service_result, Exception):
                    error_msg = str(service_result)[:100]
                    monitor._log(f"Service query exception for {ip}: {error_msg}")
                    continue
                result["services"].append(service_result)
                
                # Log service errors
                service_name = service_result.get("service", "Unknown")
                service_status = service_result.get("status", "unknown")
                if service_status == "error":
                    error_msg = service_result.get("message", "Unknown error")
                    monitor._log(f"{service_name} API error for {ip}: {error_msg}")
                elif service_status == "no_key":
                    monitor._log(f"{service_name} API key not configured for {ip}")
                
                if service_status == "malicious":
                    result["status"] = "malicious"
                elif service_status == "suspicious" and result["status"] != "malicious":
                    result["status"] = "suspicious"
            
            save_analysis_result(ip, result)
            cleanup_expired_analysis_cache()
            
            # Update rate limiter
            recent_entities[f"_analysis_{ip}"] = now
            
            return result
        except ValueError as e:
            monitor._log(f"Invalid IP address in analyze_ip: {ip} - {str(e)}")
            raise HTTPException(status_code=400, detail="Invalid IP address")
        except Exception as e:
            error_msg = str(e)[:100]
            monitor._log(f"Unexpected error in analyze_ip for {ip}: {error_msg}")
            raise HTTPException(status_code=500, detail="Internal server error")

    @app.get("/api/traffic-stream")
    async def traffic_stream():
        """Server-Sent Events stream for real-time traffic updates."""
        async def event_generator():
            nonlocal last_firewall_cache_update, cached_firewall_rule_names
            last_keepalive = datetime.utcnow()
            try:
                while True:
                    raw_entries = monitor._get_current_suspicious()
                    entries = []
                    port_counter: Counter[int] = Counter()
                    for item in raw_entries:
                        entry = dict(item)
                        ports_set = entry.get("ports_set") or []
                        if isinstance(ports_set, set):
                            ports_set = sorted(list(ports_set))
                        entry["ports_set"] = ports_set
                        entry["ports_named"] = [get_port_name(p) for p in ports_set]
                        entries.append(entry)
                        for port in ports_set:
                            port_counter[port] += 1

                    # Snapshot of current firewall rule names (to mark blocked entities)
                    # Only refresh cache periodically to avoid slow PowerShell calls
                    now_dt_ws = datetime.utcnow()
                    if (now_dt_ws - last_firewall_cache_update).total_seconds() >= FIREWALL_CACHE_REFRESH_INTERVAL_SECONDS:
                        try:
                            rules = monitor.list_firewall_rules(prefix=firewall_prefix)
                            cached_firewall_rule_names.clear()
                            for r in rules:
                                name = r.get("DisplayName") or r.get("display_name")
                                if name:
                                    cached_firewall_rule_names.add(name)
                            last_firewall_cache_update = now_dt_ws
                        except (UnicodeDecodeError, ValueError, AttributeError):
                            pass
                    rule_names = cached_firewall_rule_names

                    now_dt = datetime.utcnow()
                    now = now_dt.isoformat()
                    severity_counts = Counter(entry.get("level", 0) for entry in entries)
                    ip_count = sum(1 for e in entries if e.get("type") == "IP")
                    subnet_count = sum(1 for e in entries if e.get("type") == "SUBNET")

                    # Store current snapshot in rolling window history
                    window_entries_history.append({
                        "timestamp": now_dt.timestamp() * 1000,  # milliseconds for JS compatibility
                        "data": entries
                    })
                    window_talkers_history.append({
                        "timestamp": now_dt.timestamp() * 1000,
                        "data": entries
                    })
                    window_ports_history.append({
                        "timestamp": now_dt.timestamp() * 1000,
                        "data": [{"port": port, "count": count} for port, count in port_counter.items()]
                    })
                    
                    # Compute aggregated data over 5-minute window (300 seconds)
                    window_cutoff = now_dt - timedelta(seconds=300)
                    window_cutoff_ts = window_cutoff.timestamp() * 1000
                    
                    # Aggregate entries for traffic table (5-minute window)
                    aggregated_entries_map = {}
                    for snapshot in window_entries_history:
                        if snapshot["timestamp"] >= window_cutoff_ts:
                            for e in snapshot["data"]:
                                key = f"{e.get('entity')}_{e.get('type')}"
                                if key not in aggregated_entries_map:
                                    aggregated_entries_map[key] = {
                                        "entity": e.get("entity"),
                                        "type": e.get("type"),
                                        "level": e.get("level", 0),
                                        "packets": 0,
                                        "ports_set": set(),
                                    }
                                existing = aggregated_entries_map[key]
                                existing["packets"] += e.get("packets", 0)
                                existing["level"] = max(existing["level"], e.get("level", 0))
                                ports_set = e.get("ports_set", [])
                                if isinstance(ports_set, list):
                                    existing["ports_set"].update(ports_set)
                    
                    aggregated_entries = []
                    for item in aggregated_entries_map.values():
                        item["ports_set"] = sorted(list(item["ports_set"]))
                        aggregated_entries.append(item)
                    aggregated_entries.sort(key=lambda x: x["packets"], reverse=True)
                    
                    # Aggregate talkers for talkers chart (5-minute window)
                    talkers_entity_map = {}
                    for snapshot in window_talkers_history:
                        if snapshot["timestamp"] >= window_cutoff_ts:
                            for e in snapshot["data"]:
                                entity = e.get("entity")
                                entity_type = e.get("type", "")
                                if entity not in talkers_entity_map:
                                    talkers_entity_map[entity] = {
                                        "entity": entity,
                                        "packets": 0,
                                        "type": entity_type,
                                    }
                                talkers_entity_map[entity]["packets"] += e.get("packets", 0)
                    
                    top_talkers = sorted(
                        talkers_entity_map.values(),
                        key=lambda e: e.get("packets", 0),
                        reverse=True
                    )[:10]  # Top 10 for frontend to process
                    
                    # Aggregate ports for ports chart (5-minute window)
                    ports_aggregated = Counter()
                    for snapshot in window_ports_history:
                        if snapshot["timestamp"] >= window_cutoff_ts:
                            for p in snapshot["data"]:
                                ports_aggregated[p["port"]] += p.get("count", 0)
                    
                    top_ports = [
                        {"port": port, "port_name": get_port_name(port), "count": count}
                        for port, count in ports_aggregated.most_common(10)  # Top 10 for frontend
                    ]
                    
                    # Compact per-entity snapshot for history (used by per-IP charts)
                    per_entity = {}
                    for e in entries:
                        entity = e.get("entity")
                        if not entity:
                            continue
                        if e.get("type") != "IP":
                            continue
                        per_entity[entity] = per_entity.get(entity, 0) + (e.get("packets", 0) or 0)
                    entries_summary = [
                        {"entity": k, "packets": v} for k, v in per_entity.items()
                    ]

                    # Per-minute aggregation for history (with IP/subnet counts and per-IP packets)
                    nonlocal last_history_bucket
                    bucket = now_dt.replace(second=0, microsecond=0).isoformat()
                    if bucket != last_history_bucket:
                        traffic_history.append(
                            {
                                "ts": bucket,
                                "severity": dict(severity_counts),
                                "ip_count": ip_count,
                                "subnet_count": subnet_count,
                                "entries": entries_summary,
                            }
                        )
                        last_history_bucket = bucket

                    # Maintain last-seen entities for the last 24 hours
                    cutoff = now_dt - timedelta(hours=24)
                    to_delete = []
                    for key, info in recent_entities.items():
                        try:
                            ts = datetime.fromisoformat(info.get("last_seen", ""))
                        except (ValueError, TypeError, AttributeError):
                            ts = None
                        packets_24h = info.get("packets_24h", 0) or 0
                        if not ts or ts < cutoff or packets_24h == 0:
                            to_delete.append(key)
                    for key in to_delete:
                        recent_entities.pop(key, None)

                    for e in entries:
                        entity_key = e.get("entity")
                        if not entity_key:
                            continue
                        packets_now = e.get("packets", 0) or 0
                        display_name = monitor._get_firewall_display_name(entity_key)
                        prev_info = recent_entities.get(entity_key, {})
                        prev_packets = prev_info.get("packets_24h", 0)
                        recent_entities[entity_key] = {
                            "entity": entity_key,
                            "type": e.get("type", ""),
                            "last_seen": now,
                            "last_level": e.get("level", 0),
                            "packets_24h": prev_packets + packets_now,
                            "has_rule": display_name in rule_names,
                        }

                    recent_list = sorted(
                        recent_entities.values(),
                        key=lambda x: (x.get("last_level", 0), x.get("last_seen", "")),
                        reverse=True,
                    )[:200]

                    # Limit severity history to last 500 entries for performance (frontend will limit further)
                    history_list = list(traffic_history)
                    if len(history_list) > 500:
                        history_list = history_list[-500:]
                    
                    data = {
                        "timestamp": now,
                        "window_seconds": monitor.window.total_seconds(),
                        "max_packets": monitor.max_packets,
                        "max_ports": monitor.max_ports,
                        "entries": aggregated_entries,  # Use aggregated entries over 5-minute window
                        "severity_counts": dict(severity_counts),
                        "severity_history": history_list,
                        "top_talkers": [
                            {
                                "entity": t["entity"],
                                "packets": t.get("packets", 0),
                                "type": t.get("type", ""),
                            }
                            for t in top_talkers
                        ],
                        "top_ports": top_ports,
                        "recent_entities": recent_list,
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                    
                    # Send keep-alive ping to prevent connection timeout
                    now_check = datetime.utcnow()
                    if (now_check - last_keepalive).total_seconds() >= SSE_KEEPALIVE_INTERVAL_SECONDS:
                        yield ": keepalive\n\n"
                        last_keepalive = now_check
                    
                    await asyncio.sleep(SSE_UPDATE_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                yield ": connection closed\n\n"
                raise
            except Exception as e:
                monitor._log(f"SSE stream error: {e}", "ERROR")
                # Send error as comment and continue
                yield f": error {str(e)[:100]}\n\n"
                await asyncio.sleep(1)
        
        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
                "Keep-Alive": "timeout=60",
            }
        )

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


def main():
    """Main entry point"""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    _load_env_file(env_path)

    parser = argparse.ArgumentParser(
        description="Network Monitor - Real-time malicious IP detection using Npcap"
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Interface ID (index number or name) to monitor. Omit to see list and select interactively."
    )
    parser.add_argument(
        "--auto-block",
        action="store_true",
        help="Automatically add Windows Firewall rules for L4 IPs/subnets (requires Administrator privileges)"
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=1,
        help="Time window in seconds for analysis (default: 1)"
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=20,
        help="Maximum packets per window to trigger suspicion (default: 20)"
    )
    parser.add_argument(
        "--max-ports",
        type=int,
        default=50,
        help="Maximum unique destination ports per window to trigger suspicion (default: 50)"
    )
    parser.add_argument(
        "--alert-cooldown",
        type=int,
        default=30,
        help="Seconds between alerts for the same IP (default: 30)"
    )
    parser.add_argument(
        "--exclude-ip",
        type=str,
        action="append",
        default=None,
        help="IP address(es) to exclude from monitoring (optional, overrides excluded_ips.json). Can be specified multiple times or comma-separated. By default, excluded IPs are loaded from excluded_ips.json file."
    )
    parser.add_argument(
        "--email-smtp-server",
        type=str,
        default=None,
        help="SMTP server for email alerts (e.g., smtp.gmail.com, smtp.office365.com)"
    )
    parser.add_argument(
        "--email-smtp-port",
        type=int,
        default=587,
        help="SMTP server port (default: 587 for TLS, use 465 for SSL)"
    )
    parser.add_argument(
        "--email-username",
        type=str,
        default=None,
        help="SMTP username/email address for authentication"
    )
    parser.add_argument(
        "--email-password",
        type=str,
        default=None,
        help="SMTP password (or app password for Gmail/Office365). Can also be set via EMAIL_PASSWORD environment variable."
    )
    parser.add_argument(
        "--email-from",
        type=str,
        default=None,
        help="From email address for alerts"
    )
    parser.add_argument(
        "--email-to",
        type=str,
        action="append",
        default=None,
        help="Recipient email address(es) for alerts. Can be specified multiple times or comma-separated."
    )
    parser.add_argument(
        "--email-no-tls",
        action="store_true",
        help="Disable TLS/SSL for SMTP (not recommended)"
    )
    parser.add_argument(
        "--web-ui",
        action="store_true",
        help="Run FastAPI-based web UI instead of console display (suitable for Windows service).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8080,
        help="HTTP port for web UI (when --web-ui is enabled, default: 8080).",
    )
    args = parser.parse_args()

    exclude_ips = _collect_exclude_ips(args)
    email_settings = _build_email_settings(args)

    monitor = NetworkMonitor(
        window_seconds=args.window_seconds,
        max_packets=args.max_packets,
        max_ports=args.max_ports,
        alert_cooldown=args.alert_cooldown,
        auto_block=args.auto_block,
        exclude_ips=exclude_ips,
        email_smtp_server=email_settings["smtp_server"],
        email_smtp_port=email_settings["smtp_port"],
        email_username=email_settings["username"],
        email_password=email_settings["password"],
        email_from=email_settings["sender"],
        email_to=email_settings["recipients"],
        email_use_tls=email_settings["use_tls"],
    )

    if args.web_ui:
        if not FASTAPI_AVAILABLE:
            print("FastAPI/uvicorn are not installed. Install fastapi and uvicorn to use --web-ui mode.")
            sys.exit(1)
        app = create_web_app(monitor, interface_id=args.interface)
        uvicorn.run(app, host="0.0.0.0", port=args.web_port, log_level="info")
    else:
        monitor.start(interface_id=args.interface)


if __name__ == "__main__":
    main()

