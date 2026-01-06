#!/usr/bin/env python3
"""
Network Monitor - Real-time malicious IP detection using Npcap
Monitors all network traffic and detects suspicious behavior patterns.
"""

import sys
import platform
import os
import time
import argparse
import subprocess
import json
import socket
import ipaddress
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque, defaultdict
from datetime import datetime, timedelta
from threading import Lock, Thread
from scapy.all import get_if_list, sniff, IP, TCP, UDP

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


class IpStats:
    """Tracks statistics for a single IP address or subnet"""
    
    def __init__(self):
        self.lock = Lock()
        self.packet_times = deque()
        self.dst_ports = set()
        self.last_alert = None
        self.last_level = 0  # 0 = no alert yet, 1-4 = severity levels
        self.suspicion_count = 0  # how many windows this entity has been suspicious
        self.first_suspicious = None  # datetime of first suspicious window
        self.last_suspicious = None   # datetime of last suspicious window
        self.in_attack = False        # True while in an L3/L4 attack window
        self.last_suspicious_window_start = None  # track which window we last counted


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
        self.exclude_ips = set()  # Will be loaded from file or set from parameter
        
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

        # Log file (in the same directory as this script)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.log_path = os.path.join(base_dir, "net_monitor.log")
        self.log_dir = base_dir
        self.status_file = os.path.join(base_dir, "net_monitor_status.json")
        self.excluded_ips_file = os.path.join(base_dir, "excluded_ips.json")
        self.last_log_date = None  # Track the date of the current log file
        
        # Load excluded IPs from JSON file (if not provided via command line)
        if exclude_ips is None:
            self._load_excluded_ips()
        else:
            if isinstance(exclude_ips, str):
                self.exclude_ips = {exclude_ips}
            else:
                self.exclude_ips = set(exclude_ips) if exclude_ips else set()
        
        # Automatically detect and exclude local IPs and WAN IP
        self._auto_exclude_local_and_wan_ips()
        
        # Log email configuration status
        if self.email_enabled:
            self._log(f"Email alerts enabled: SMTP={self.email_smtp_server}:{self.email_smtp_port}, From={self.email_from}, To={', '.join(self.email_to)}")
        else:
            self._log("Email alerts disabled (email configuration not provided)")
        
        # Initialize log rotation (check if log file exists and get its date)
        self._initialize_log_rotation()
        
        # Load previous status if available
        self._load_status()

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
        except Exception:
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
        except Exception:
            # Log rotation failures should not break monitoring
            pass
    
    def _log(self, message: str) -> None:
        """Append a log line with UTC timestamp to the log file."""
        # Rotate log if needed (check daily)
        self._rotate_log_if_needed()
        
        timestamp = datetime.utcnow().isoformat()
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} {message}\n")
        except Exception:
            # Logging failures should not break monitoring
            pass
    
    def _load_excluded_ips(self) -> None:
        """Load excluded IPs from JSON file."""
        try:
            if os.path.exists(self.excluded_ips_file):
                with open(self.excluded_ips_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.exclude_ips = set(data.get("excluded_ips", []))
                    if self.exclude_ips:
                        self._log(f"Loaded {len(self.exclude_ips)} excluded IPs from {self.excluded_ips_file}: {', '.join(sorted(self.exclude_ips))}")
            else:
                self.exclude_ips = set()
        except Exception as e:
            self._log(f"Error loading excluded IPs: {e}")
            self.exclude_ips = set()
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is a private/local IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    def _get_all_server_ips(self) -> set:
        """Get all IP addresses (both private and public) from all network interfaces."""
        server_ips = set()
        
        # Get hostname IP
        try:
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            server_ips.add(host_ip)
        except Exception:
            pass
        
        # Get all IPs from network interfaces
        try:
            if platform.system().lower().startswith("win"):
                from scapy.arch.windows import get_windows_if_list
                win_if_info = get_windows_if_list()
                for w in win_if_info:
                    ip = w.get("ip")
                    if ip:
                        server_ips.add(ip)
            else:
                # On Linux/Unix, use socket to get interface IPs
                for iface in get_if_list():
                    try:
                        # Try to get IP from interface name
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                        server_ips.add(local_ip)
                        break
                    except Exception:
                        continue
        except Exception:
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
    
    def _get_local_ips(self) -> set:
        """Get all local/private IP addresses from network interfaces."""
        all_ips = self._get_all_server_ips()
        return {ip for ip in all_ips if self._is_private_ip(ip)}
    
    def _get_wan_ip(self) -> str:
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
                if platform.system().lower().startswith("win"):
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
                        try:
                            # Validate it's a proper IP address
                            ipaddress.ip_address(ip)
                            self._log(f"Detected WAN IP from {service}: {ip}")
                            return ip
                        except ValueError:
                            continue
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
    
    def _save_status(self) -> None:
        """Save current monitoring status to JSON file (only L4 entities persist between restarts)."""
        try:
            now = datetime.utcnow()
            status_data = {
                "last_updated": now.isoformat(),
                "ip_stats": {},
                "subnet_stats": {},
                "detected_ips": sorted(list(self.detected_ips)),
                "detected_subnets": sorted(list(self.detected_subnets)),
                "firewall_suggestions": {}
            }
            
            # Save firewall suggestions
            for entity, info in self.firewall_suggestions.items():
                status_data["firewall_suggestions"][entity] = {
                    "added": info["added"].isoformat(),
                    "is_subnet": info["is_subnet"]
                }
            
            # Save IP stats (only L4 entities - suspicion_count >= 1024)
            for ip, stats in self.stats.items():
                with stats.lock:
                    # Only save L4 entities (suspicion_count >= 1024, which is 16 * 4^3)
                    if stats.suspicion_count >= 1024:
                        status_data["ip_stats"][ip] = {
                            "suspicion_count": stats.suspicion_count,
                            "last_level": stats.last_level,
                            "first_suspicious": stats.first_suspicious.isoformat() if stats.first_suspicious else None,
                            "last_suspicious": stats.last_suspicious.isoformat() if stats.last_suspicious else None,
                            "in_attack": stats.in_attack
                        }
            
            # Save subnet stats (only L4 entities - suspicion_count >= 1024)
            for subnet, stats in self.subnet_stats.items():
                with stats.lock:
                    # Only save L4 entities (suspicion_count >= 1024, which is 16 * 4^3)
                    if stats.suspicion_count >= 1024:
                        status_data["subnet_stats"][subnet] = {
                            "suspicion_count": stats.suspicion_count,
                            "last_level": stats.last_level,
                            "first_suspicious": stats.first_suspicious.isoformat() if stats.first_suspicious else None,
                            "last_suspicious": stats.last_suspicious.isoformat() if stats.last_suspicious else None,
                            "in_attack": stats.in_attack
                        }
            
            with open(self.status_file, "w", encoding="utf-8") as f:
                json.dump(status_data, f, indent=2)
        except Exception as e:
            self._log(f"Error saving status: {e}")
    
    def _load_status(self) -> None:
        """Load previous monitoring status from JSON file."""
        try:
            if not os.path.exists(self.status_file):
                return
            
            with open(self.status_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Restore IP stats
            for ip, stats_data in data.get("ip_stats", {}).items():
                stats = self.stats[ip]
                with stats.lock:
                    stats.suspicion_count = stats_data.get("suspicion_count", 0)
                    stats.last_level = stats_data.get("last_level", 0)
                    if stats_data.get("first_suspicious"):
                        stats.first_suspicious = datetime.fromisoformat(stats_data["first_suspicious"])
                    if stats_data.get("last_suspicious"):
                        stats.last_suspicious = datetime.fromisoformat(stats_data["last_suspicious"])
                    stats.in_attack = stats_data.get("in_attack", False)
            
            # Restore subnet stats
            for subnet, stats_data in data.get("subnet_stats", {}).items():
                stats = self.subnet_stats[subnet]
                with stats.lock:
                    stats.suspicion_count = stats_data.get("suspicion_count", 0)
                    stats.last_level = stats_data.get("last_level", 0)
                    if stats_data.get("first_suspicious"):
                        stats.first_suspicious = datetime.fromisoformat(stats_data["first_suspicious"])
                    if stats_data.get("last_suspicious"):
                        stats.last_suspicious = datetime.fromisoformat(stats_data["last_suspicious"])
                    stats.in_attack = stats_data.get("in_attack", False)
            
            # Restore detected sets
            self.detected_ips = set(data.get("detected_ips", []))
            self.detected_subnets = set(data.get("detected_subnets", []))
            
            # Restore firewall suggestions
            for entity, info_data in data.get("firewall_suggestions", {}).items():
                self.firewall_suggestions[entity] = {
                    "added": datetime.fromisoformat(info_data["added"]),
                    "is_subnet": info_data.get("is_subnet", False)
                }
            
            loaded_ips = len(data.get("ip_stats", {}))
            loaded_subnets = len(data.get("subnet_stats", {}))
            loaded_firewall = len(data.get("firewall_suggestions", {}))
            self._log(f"Loaded status: {loaded_ips} IPs, {loaded_subnets} subnets, {len(self.detected_ips)} detected IPs, {len(self.detected_subnets)} detected subnets, {loaded_firewall} firewall suggestions")
        except Exception as e:
            self._log(f"Error loading status: {e}")
    
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
            
            self._log(f"Email alert sent: {subject}")
        except Exception as e:
            self._log(f"Failed to send email alert: {str(e)}")
    
    def _check_firewall_rule_exists(self, display_name: str) -> bool:
        """
        Check if a firewall rule with the given display name exists in Windows Firewall.
        Returns True if the rule exists, False otherwise.
        """
        if not platform.system().lower().startswith("win"):
            return False
        
        try:
            check_cmd = [
                "powershell", "-Command",
                f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
            ]
            result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and result.stdout.strip() != ""
        except Exception:
            return False
    
    def _add_firewall_rule(self, entity: str, is_subnet: bool = False):
        """
        Add a Windows Firewall rule to block the given IP or subnet.
        Returns tuple: (success: bool, was_new_rule: bool, display_name: str)
        """
        display_name = f"Block_Attacker_{entity.replace('/', '_').replace('.', '_')}"
        
        if not is_subnet:
            if entity in self.exclude_ips:
                if entity not in self.logged_skip_entities:
                    self._log(f"FIREWALL_SKIP {entity} (in excluded IPs list)")
                    self.logged_skip_entities.add(entity)
                return (True, False, display_name)
        else:
            subnet_base = entity.split("/")[0]
            octets = subnet_base.split(".")
            if len(octets) >= 2:
                subnet_prefix = f"{octets[0]}.{octets[1]}"
                for excluded_ip in self.exclude_ips:
                    excluded_octets = excluded_ip.split(".")
                    if len(excluded_octets) >= 2:
                        excluded_prefix = f"{excluded_octets[0]}.{excluded_octets[1]}"
                        if excluded_prefix == subnet_prefix:
                            if entity not in self.logged_skip_entities:
                                self._log(f"FIREWALL_SKIP {entity} (subnet contains excluded IP {excluded_ip})")
                                self.logged_skip_entities.add(entity)
                            return (True, False, display_name)
        
        if not platform.system().lower().startswith("win"):
            if entity not in self.logged_skip_entities:
                self._log(f"FIREWALL_SKIP {entity} (not Windows)")
                self.logged_skip_entities.add(entity)
            return (False, False, display_name)
        
        try:
            if is_subnet:
                # subnet_key format is expected to be 'A.B.0.0/16'
                base = entity.split("/")[0]
                octets = base.split(".")
                if len(octets) == 4:
                    start_ip = f"{octets[0]}.{octets[1]}.0.0"
                    end_ip = f"{octets[0]}.{octets[1]}.255.255"
                    remote_address = f"{start_ip}-{end_ip}"
                else:
                    remote_address = base
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
            cmd = [
                "powershell", "-Command",
                f"New-NetFirewallRule -DisplayName '{display_name}' "
                f"-Direction Inbound -Action Block -RemoteAddress '{remote_address}' "
                f"-Protocol Any -ErrorAction Stop"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self._log(f"FIREWALL_BLOCKED {entity} remote_address={remote_address} display_name={display_name}")
                # Return tuple: (success, was_new_rule, display_name)
                return (True, True, display_name)
            else:
                self._log(f"FIREWALL_ERROR {entity} stderr={result.stderr}")
                return (False, False, display_name)
                
        except subprocess.TimeoutExpired:
            self._log(f"FIREWALL_TIMEOUT {entity}")
            return (False, False, display_name)
        except Exception as e:
            self._log(f"FIREWALL_EXCEPTION {entity} error={str(e)}")
            return (False, False, display_name)
    
    def _test_firewall_privileges(self) -> bool:
        """
        Test firewall rule creation/removal to verify Administrator privileges.
        Creates a test rule, verifies it exists, then removes it.
        Returns True if privileges are sufficient, False otherwise.
        """
        if not platform.system().lower().startswith("win"):
            return False
        
        test_ip = "192.0.2.1"  # Test-Net IP (RFC 5737) - safe to use for testing
        display_name = f"Block_Attacker_TEST_PRIV_CHECK"
        
        try:
            # Try to create a test firewall rule
            create_cmd = [
                "powershell", "-Command",
                f"New-NetFirewallRule -DisplayName '{display_name}' "
                f"-Direction Inbound -Action Block -RemoteAddress '{test_ip}' "
                f"-Protocol Any -ErrorAction Stop"
            ]
            
            result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Rule created successfully, now verify it exists
                check_cmd = [
                    "powershell", "-Command",
                    f"Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"
                ]
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
                
                if check_result.returncode == 0 and check_result.stdout.strip():
                    # Rule exists, now remove it
                    remove_cmd = [
                        "powershell", "-Command",
                        f"Remove-NetFirewallRule -DisplayName '{display_name}' -ErrorAction Stop"
                    ]
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
            self._log(f"FIREWALL_PRIV_CHECK FAILED (timeout)")
            return False
        except Exception as e:
            self._log(f"FIREWALL_PRIV_CHECK FAILED (exception: {str(e)})")
            return False
    
    def _classify_severity(self, packet_count: int, unique_ports: int, suspicion_count: int) -> int:
        """
        Classify severity into 4 levels based only on history (suspicion count),
        with cubic growth starting from 16.
        Level 0: below thresholds (no alert)
        Level 1-4: more windows flagged as suspicious => higher level.
        Cubic thresholds: 16 * n^3 where n is the level multiplier
        """
        if suspicion_count < 16:
            return 0

        # Cubic escalation starting from 16:
        #  Base: 16
        #  L1: 16 * 1^3 = 16 suspicious windows
        #  L2: 16 * 2^3 = 128 suspicious windows
        #  L3: 16 * 3^3 = 432 suspicious windows
        #  L4: 16 * 4^3 = 1024 suspicious windows
        if suspicion_count >= 1024:  # 16 * 4^3
            return 4
        if suspicion_count >= 432:  # 16 * 3^3
            return 3
        if suspicion_count >= 128:  # 16 * 2^3
            return 2
        if suspicion_count >= 16:  # 16 * 1^3
            return 1
        return 0

    def _get_subnet_key(self, ip: str):
        """Return a simple /16 subnet key (A.B.0.0/16) for IPv4 addresses, or None if not IPv4."""
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        return f"{parts[0]}.{parts[1]}.0.0/16"

    def process_packet(self, packet):
        """Process a captured packet"""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Skip traffic sourced from excluded IPs (e.g., host's public IP or self IPs)
        if src_ip in self.exclude_ips:
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

        # Per-IP statistics
        stats_ip = self.stats[src_ip]
        subnet_key = self._get_subnet_key(src_ip)
        stats_subnet = self.subnet_stats[subnet_key] if subnet_key else None
        
        # Update per-IP stats and check
        with stats_ip.lock:
            stats_ip.packet_times.append(now)
            if dst_port:
                stats_ip.dst_ports.add(dst_port)
            
            while stats_ip.packet_times and now - stats_ip.packet_times[0] > self.window:
                stats_ip.packet_times.popleft()
            
            packet_count = len(stats_ip.packet_times)
            unique_ports = len(stats_ip.dst_ports)

            # Base condition for being considered suspicious in this window
            base_suspicious = (
                packet_count >= self.max_packets or unique_ports >= self.max_ports
            )

            # Calculate current window start time (rounded down to 1-second boundary)
            window_start_sec = int(now.timestamp())

            severity = 0
            if base_suspicious:
                # Only increment suspicion_count once per window, not per packet
                if stats_ip.last_suspicious_window_start != window_start_sec:
                    stats_ip.suspicion_count += 1
                    stats_ip.last_suspicious_window_start = window_start_sec
                    # Track first/last time this IP was seen as suspicious
                    if stats_ip.first_suspicious is None:
                        stats_ip.first_suspicious = now
                    stats_ip.last_suspicious = now
            else:
                # Decrement suspicion_count when not suspicious (decay mechanism)
                # Only decrement once per window, and only if suspicion_count > 0
                if stats_ip.last_suspicious_window_start != window_start_sec and stats_ip.suspicion_count > 0:
                    stats_ip.suspicion_count -= 1
                    stats_ip.last_suspicious_window_start = window_start_sec
            
            # Calculate severity based on current suspicion_count (can increase or decrease)
            if stats_ip.suspicion_count > 0:
                severity = self._classify_severity(
                    packet_count, unique_ports, stats_ip.suspicion_count
                )

            should_alert = False

            if severity > 0:
                # Escalate immediately if severity increased, otherwise respect cooldown
                if severity > stats_ip.last_level:
                    should_alert = True
                elif stats_ip.last_alert is None or now - stats_ip.last_alert > self.alert_cooldown:
                    should_alert = True

            if should_alert:
                self.detected_ips.add(src_ip)
                stats_ip.last_alert = now
                stats_ip.last_level = severity

                # If severity is at maximum, add to firewall suggestions
                if severity >= 4:
                    if src_ip not in self.firewall_suggestions:
                        self.firewall_suggestions[src_ip] = {
                            "added": now,
                            "is_subnet": False
                        }
                    
                    if self.auto_block:
                        blocked, was_new_rule, display_name = self._add_firewall_rule(src_ip, is_subnet=False)
                        if blocked and was_new_rule and src_ip not in self.firewall_block_emails_sent:
                            # Send email alert for firewall block (only for newly created rules)
                            subject = f"🛡️ Firewall Block: {src_ip}"
                            body = f"""Network Monitor Alert

Action: IP Blocked in Windows Firewall
IP Address: {src_ip}
Firewall Rule Name: {display_name}
Severity Level: L4
Time: {now.isoformat()}

The IP address has been automatically blocked due to reaching L4 severity level.
"""
                            self._send_email_alert(subject, body)
                            self.firewall_block_emails_sent.add(src_ip)
                
                stats_ip.dst_ports.clear()

            # Detect attack end when previously in attack, but severity has dropped below L3
            # Severity decreases as suspicion_count decreases (decay mechanism)
            if stats_ip.in_attack and severity < 3:
                stats_ip.in_attack = False
                first_ts = stats_ip.first_suspicious.isoformat() if stats_ip.first_suspicious else "unknown"
                last_ts = stats_ip.last_suspicious.isoformat() if stats_ip.last_suspicious else "unknown"
                duration_sec = 0.0
                if stats_ip.first_suspicious and stats_ip.last_suspicious:
                    duration_sec = (stats_ip.last_suspicious - stats_ip.first_suspicious).total_seconds()

                self._log(
                    f"ATTACK_END IP {src_ip} last_level=L{stats_ip.last_level} "
                    f"first_suspicious={first_ts} last_suspicious={last_ts} "
                    f"duration_sec={duration_sec:.2f}"
                )

        # Update per-subnet stats and check (to catch rotating IPs in same prefix)
        if subnet_key and stats_subnet is not None:
            with stats_subnet.lock:
                stats_subnet.packet_times.append(now)
                if dst_port:
                    stats_subnet.dst_ports.add(dst_port)

                while stats_subnet.packet_times and now - stats_subnet.packet_times[0] > self.window:
                    stats_subnet.packet_times.popleft()

                subnet_packet_count = len(stats_subnet.packet_times)
                subnet_unique_ports = len(stats_subnet.dst_ports)

                base_suspicious_subnet = (
                    subnet_packet_count >= self.max_packets
                    or subnet_unique_ports >= self.max_ports
                )

                # Calculate current window start time (rounded down to 1-second boundary)
                window_start_sec = int(now.timestamp())
                
                subnet_severity = 0
                if base_suspicious_subnet:
                    # Only increment suspicion_count once per window, not per packet
                    if stats_subnet.last_suspicious_window_start != window_start_sec:
                        stats_subnet.suspicion_count += 1
                        stats_subnet.last_suspicious_window_start = window_start_sec
                        if stats_subnet.first_suspicious is None:
                            stats_subnet.first_suspicious = now
                        stats_subnet.last_suspicious = now
                else:
                    # Decrement suspicion_count when not suspicious (decay mechanism)
                    # Only decrement once per window, and only if suspicion_count > 0
                    if stats_subnet.last_suspicious_window_start != window_start_sec and stats_subnet.suspicion_count > 0:
                        stats_subnet.suspicion_count -= 1
                        stats_subnet.last_suspicious_window_start = window_start_sec
                
                # Calculate severity based on current suspicion_count (can increase or decrease)
                if stats_subnet.suspicion_count > 0:
                    subnet_severity = self._classify_severity(
                        subnet_packet_count, subnet_unique_ports, stats_subnet.suspicion_count
                    )
                subnet_alert = False

                if subnet_severity > 0:
                    if subnet_severity > stats_subnet.last_level:
                        subnet_alert = True
                    elif stats_subnet.last_alert is None or now - stats_subnet.last_alert > self.alert_cooldown:
                        subnet_alert = True

                if subnet_alert:
                    self.detected_subnets.add(subnet_key)
                    stats_subnet.last_alert = now
                    stats_subnet.last_level = subnet_severity

                    # For a /16, add to firewall suggestions
                    if subnet_severity >= 4:
                        if subnet_key not in self.firewall_suggestions:
                            self.firewall_suggestions[subnet_key] = {
                                "added": now,
                                "is_subnet": True
                            }
                        
                        if self.auto_block:
                            blocked, was_new_rule, display_name = self._add_firewall_rule(subnet_key, is_subnet=True)
                            if blocked and was_new_rule:
                                if subnet_key not in self.firewall_block_emails_sent:
                                    # Send email alert for subnet firewall block (only for newly created rules)
                                    subject = f"🛡️ Firewall Block: {subnet_key}"
                                    body = f"""Network Monitor Alert

Action: Subnet Blocked in Windows Firewall
Subnet: {subnet_key}
Firewall Rule Name: {display_name}
Severity Level: L4
Time: {now.isoformat()}

The subnet has been automatically blocked due to reaching L4 severity level.
"""
                                    self._send_email_alert(subject, body)
                                    self.firewall_block_emails_sent.add(subnet_key)
                                else:
                                    if subnet_key not in self.email_skip_logged:
                                        self._log(f"Email alert skipped for {subnet_key} (already sent)")
                                        self.email_skip_logged.add(subnet_key)
                            elif blocked and not was_new_rule:
                                if subnet_key not in self.email_skip_logged:
                                    self._log(f"Email alert skipped for {subnet_key} (rule already existed)")
                                    self.email_skip_logged.add(subnet_key)

                    stats_subnet.dst_ports.clear()

                # Detect subnet attack end when previously in attack, but severity has dropped below L3
                # Severity decreases as suspicion_count decreases (decay mechanism)
                if stats_subnet.in_attack and subnet_severity < 3:
                    stats_subnet.in_attack = False
                    first_ts = stats_subnet.first_suspicious.isoformat() if stats_subnet.first_suspicious else "unknown"
                    last_ts = stats_subnet.last_suspicious.isoformat() if stats_subnet.last_suspicious else "unknown"
                    duration_sec = 0.0
                    if stats_subnet.first_suspicious and stats_subnet.last_suspicious:
                        duration_sec = (stats_subnet.last_suspicious - stats_subnet.first_suspicious).total_seconds()

                    self._log(
                        f"ATTACK_END SUBNET {subnet_key} last_level=L{stats_subnet.last_level} "
                        f"first_suspicious={first_ts} last_suspicious={last_ts} "
                        f"duration_sec={duration_sec:.2f}"
                    )
    
    def _get_current_suspicious(self):
        """Get current suspicious IPs and subnets with their stats"""
        now = datetime.utcnow()
        suspicious = []
        
        # Check IPs
        for ip, stats in self.stats.items():
            with stats.lock:
                # Clean old packets
                while stats.packet_times and now - stats.packet_times[0] > self.window:
                    stats.packet_times.popleft()
                
                packet_count = len(stats.packet_times)
                unique_ports = len(stats.dst_ports)

                base_suspicious = (
                    packet_count >= self.max_packets
                    or unique_ports >= self.max_ports
                )

                # Only show entries when currently suspicious
                if base_suspicious:
                    suspicious.append({
                        'entity': ip,
                        'level': stats.last_level,
                        'packets': packet_count,
                        'ports': unique_ports,
                        'ports_set': stats.dst_ports.copy(),
                        'type': 'IP',
                        'active': True,
                    })
        
        # Check subnets
        for subnet, stats in self.subnet_stats.items():
            with stats.lock:
                while stats.packet_times and now - stats.packet_times[0] > self.window:
                    stats.packet_times.popleft()
                
                packet_count = len(stats.packet_times)
                unique_ports = len(stats.dst_ports)

                base_suspicious = (
                    packet_count >= self.max_packets
                    or unique_ports >= self.max_ports
                )

                # Only show entries when currently suspicious
                if base_suspicious:
                    suspicious.append({
                        'entity': subnet,
                        'level': stats.last_level,
                        'packets': packet_count,
                        'ports': unique_ports,
                        'ports_set': stats.dst_ports.copy(),
                        'type': 'SUBNET',
                        'active': True,
                    })
        
        # Sort by level (descending), then by packets (descending)
        suspicious.sort(key=lambda x: (x['level'], x['packets']), reverse=True)
        return suspicious
    
    def _periodic_save(self):
        """Periodically save status to file"""
        while self.running:
            time.sleep(60)  # Save every 60 seconds
            if self.running:
                self._save_status()
    
    def _display_table(self):
        """Display the dynamic table of suspicious IPs/subnets"""
        while self.running:
            time.sleep(1)  # Update every second
            
            suspicious = self._get_current_suspicious()
            
            with self.display_lock:
                # Clear screen (Windows)
                if platform.system().lower().startswith("win"):
                    os.system('cls')
                else:
                    os.system('clear')
                
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
                            port_display = f"p{single_port}"
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
    
    def start(self, interface=None, interface_id=None):
        """Start monitoring on the specified interface"""
        if interface is None:
            interfaces = get_if_list()
            if not interfaces:
                print("No network interfaces found. Make sure Npcap is installed.")
                sys.exit(1)

            # On Windows, try to show friendly names and IPs using get_windows_if_list
            win_if_info = []
            if platform.system().lower().startswith("win"):
                try:
                    from scapy.arch.windows import get_windows_if_list  # type: ignore
                    win_if_info = get_windows_if_list()
                except Exception:
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
            time.sleep(1.5)  # Let display thread finish current update
            print("\n\nStopping monitor...")
            self._save_status()  # Save status on shutdown
            print(f"\nTotal suspicious IPs detected: {len(self.detected_ips)}")
            if self.detected_ips:
                print("\nDetected IPs:")
                for ip in sorted(self.detected_ips):
                    print(f"  {ip}")


def main():
    """Main entry point"""
    # Load environment variables from .env file if available
    if DOTENV_AVAILABLE:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        if os.path.exists(env_path):
            load_dotenv(env_path)
    else:
        # Fallback: manually load .env file if python-dotenv is not installed
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        if os.path.exists(env_path):
            try:
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key and value and key not in os.environ:
                                os.environ[key] = value
            except Exception:
                pass
    
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
    args = parser.parse_args()

    # Collect exclude IPs from command line arguments (if provided, overrides JSON file)
    exclude_ips = None
    if args.exclude_ip:
        exclude_ips = []
        for ip_arg in args.exclude_ip:
            # Support comma-separated IPs
            exclude_ips.extend([ip.strip() for ip in ip_arg.split(",") if ip.strip()])
    
    # Check for exclude IPs in environment variable if not provided via command line
    if exclude_ips is None:
        env_exclude = os.getenv("EXCLUDE_IP")
        if env_exclude:
            exclude_ips = [ip.strip() for ip in env_exclude.split(",") if ip.strip()]

    # Load email configuration from environment variables (with fallback to command-line args)
    email_smtp_server = args.email_smtp_server or os.getenv("EMAIL_SMTP_SERVER")
    email_smtp_port = args.email_smtp_port
    if os.getenv("EMAIL_SMTP_PORT"):
        try:
            email_smtp_port = int(os.getenv("EMAIL_SMTP_PORT"))
        except ValueError:
            pass
    email_username = args.email_username or os.getenv("EMAIL_USERNAME")
    email_password = args.email_password or os.getenv("EMAIL_PASSWORD")
    email_from = args.email_from or os.getenv("EMAIL_FROM")
    
    # Collect email recipients (from command-line or environment)
    email_to = None
    if args.email_to:
        email_to = []
        for email_arg in args.email_to:
            email_to.extend([email.strip() for email in email_arg.split(",") if email.strip()])
    elif os.getenv("EMAIL_TO"):
        email_to = [email.strip() for email in os.getenv("EMAIL_TO").split(",") if email.strip()]
    
    # Email TLS setting (default True, can be disabled via env var)
    email_use_tls = not args.email_no_tls
    if os.getenv("EMAIL_USE_TLS", "").lower() in ("false", "0", "no"):
        email_use_tls = False

    monitor = NetworkMonitor(
        window_seconds=args.window_seconds,
        max_packets=args.max_packets,
        max_ports=args.max_ports,
        alert_cooldown=args.alert_cooldown,
        auto_block=args.auto_block,
        exclude_ips=exclude_ips,
        email_smtp_server=email_smtp_server,
        email_smtp_port=email_smtp_port,
        email_username=email_username,
        email_password=email_password,
        email_from=email_from,
        email_to=email_to,
        email_use_tls=email_use_tls
    )
    monitor.start(interface_id=args.interface)


if __name__ == "__main__":
    main()

