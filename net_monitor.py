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

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from fastapi.staticfiles import StaticFiles
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


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
            self._log(f"Error loading excluded IPs from SQLite: {e}")
            return set()
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is a private/local IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    def _get_all_server_ips(self) -> Set[str]:
        """Get all IP addresses (both private and public) from all network interfaces."""
        server_ips = set()

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
                # On Linux/Unix, attempt a single outbound connect to discover primary IP
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    server_ips.add(local_ip)
                except Exception:
                    pass
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
    
    def _save_stats_to_db(
        self, conn: sqlite3.Connection, stats_dict: Dict[str, IpStats], table_name: str
    ) -> None:
        """Save stats dictionary to database table."""
        conn.execute(f"DELETE FROM {table_name}")
        for entity, stats in stats_dict.items():
            with stats.lock:
                if stats.suspicion_count >= L4_THRESHOLD:
                    conn.execute(
                        f"""
                        INSERT INTO {table_name} (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entity,
                            stats.suspicion_count,
                            stats.last_level,
                            stats.first_suspicious.isoformat() if stats.first_suspicious else None,
                            stats.last_suspicious.isoformat() if stats.last_suspicious else None,
                            1 if stats.in_attack else 0,
                        ),
                    )

    def _save_detected_entities(self, conn: sqlite3.Connection, entities: Set[str], table_name: str) -> None:
        """Save detected entities to database table."""
        conn.execute(f"DELETE FROM {table_name}")
        for entity in entities:
            conn.execute(f"INSERT INTO {table_name} (entity) VALUES (?)", (entity,))

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
                for entity, info in self.firewall_suggestions.items():
                    conn.execute(
                        """
                        INSERT INTO firewall_suggestions (entity, added, is_subnet)
                        VALUES (?, ?, ?)
                        """,
                        (
                            entity,
                            info["added"].isoformat(),
                            1 if info["is_subnet"] else 0,
                        ),
                    )
                conn.commit()
        except (sqlite3.Error, OSError) as e:
            self._log(f"Error saving status: {e}")

    def _load_stats_from_db(
        self, conn: sqlite3.Connection, stats_dict: Dict[str, IpStats], table_name: str
    ) -> None:
        """Load stats from database table into stats dictionary."""
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
                for ip, stats_data in data.get("ip_stats", {}).items():
                    conn.execute(
                        """
                        INSERT INTO ip_stats (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ip,
                            stats_data.get("suspicion_count", 0),
                            stats_data.get("last_level", 0),
                            stats_data.get("first_suspicious"),
                            stats_data.get("last_suspicious"),
                            1 if stats_data.get("in_attack", False) else 0,
                        ),
                    )

                conn.execute("DELETE FROM subnet_stats")
                for subnet, stats_data in data.get("subnet_stats", {}).items():
                    conn.execute(
                        """
                        INSERT INTO subnet_stats (entity, suspicion_count, last_level, first_suspicious, last_suspicious, in_attack)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            subnet,
                            stats_data.get("suspicion_count", 0),
                            stats_data.get("last_level", 0),
                            stats_data.get("first_suspicious"),
                            stats_data.get("last_suspicious"),
                            1 if stats_data.get("in_attack", False) else 0,
                        ),
                    )

                conn.execute("DELETE FROM detected_ips")
                for ip in data.get("detected_ips", []):
                    conn.execute("INSERT INTO detected_ips (entity) VALUES (?)", (ip,))

                conn.execute("DELETE FROM detected_subnets")
                for subnet in data.get("detected_subnets", []):
                    conn.execute("INSERT INTO detected_subnets (entity) VALUES (?)", (subnet,))

                conn.execute("DELETE FROM firewall_suggestions")
                for entity, info in data.get("firewall_suggestions", {}).items():
                    conn.execute(
                        """
                        INSERT INTO firewall_suggestions (entity, added, is_subnet)
                        VALUES (?, ?, ?)
                        """,
                        (
                            entity,
                            info.get("added"),
                            1 if info.get("is_subnet", False) else 0,
                        ),
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
                for ip in ips:
                    if not ip:
                        continue
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO excluded_ips (ip, note, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (ip, None, now_val),
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
        try:
            ipaddress.ip_address(ip)
        except ValueError:
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
    
    def _add_firewall_rule(self, entity: str, is_subnet: bool = False) -> Tuple[bool, bool, str]:
        """
        Add a Windows Firewall rule to block the given IP or subnet.
        Returns tuple: (success: bool, was_new_rule: bool, display_name: str)
        """
        display_name = f"{FIREWALL_PREFIX}{entity.replace('/', '_').replace('.', '_')}"
        
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
    
    def list_firewall_rules(self, prefix: str = FIREWALL_PREFIX) -> List[Dict[str, Any]]:
        """List Windows Firewall rules matching the provided display name prefix."""
        if not platform.system().lower().startswith("win"):
            return []
        
        try:
            cmd = [
                "powershell",
                "-Command",
                (
                    f"Get-NetFirewallRule -DisplayName '{prefix}*' | ForEach-Object {{ "
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
                ),
            ]
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
            self._log("FIREWALL_LIST_TIMEOUT")
            return []
        except Exception as e:
            self._log(f"FIREWALL_LIST_EXCEPTION error={e}")
            return []

    def remove_firewall_rule(self, display_name: str) -> bool:
        """Remove a Windows Firewall rule by display name."""
        if not platform.system().lower().startswith("win"):
            return False
        try:
            cmd = [
                "powershell",
                "-Command",
                f"Remove-NetFirewallRule -DisplayName '{display_name}' -ErrorAction Stop",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._log(f"FIREWALL_REMOVED display_name={display_name}")
                return True
            self._log(f"FIREWALL_REMOVE_ERROR display_name={display_name} stderr={result.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self._log(f"FIREWALL_REMOVE_TIMEOUT display_name={display_name}")
            return False
        except Exception as e:
            self._log(f"FIREWALL_REMOVE_EXCEPTION display_name={display_name} error={e}")
            return False
    
    def _test_firewall_privileges(self) -> bool:
        """
        Test firewall rule creation/removal to verify Administrator privileges.
        Creates a test rule, verifies it exists, then removes it.
        Returns True if privileges are sufficient, False otherwise.
        """
        if not platform.system().lower().startswith("win"):
            return False
        
        test_ip = "192.0.2.1"  # Test-Net IP (RFC 5737) - safe to use for testing
        display_name = f"{FIREWALL_PREFIX}TEST_PRIV_CHECK"
        
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

    def _process_entity_stats(
        self,
        stats: IpStats,
        entity: str,
        now: datetime,
        dst_port: Optional[int],
        detected_set: Set[str],
        firewall_suggestions: Dict[str, Dict[str, Any]],
        is_subnet: bool = False
    ) -> Tuple[int, bool]:
        """
        Process statistics for an entity (IP or subnet) and determine severity and alert status.
        Returns: (severity, should_alert)
        """
        with stats.lock:
            stats.packet_times.append(now)
            if dst_port:
                stats.dst_ports.add(dst_port)
            
            while stats.packet_times and now - stats.packet_times[0] > self.window:
                stats.packet_times.popleft()
            
            packet_count = len(stats.packet_times)
            unique_ports = len(stats.dst_ports)
            base_suspicious = packet_count >= self.max_packets or unique_ports >= self.max_ports
            window_start_sec = int(now.timestamp())
            
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

        stats_ip = self.stats[src_ip]
        subnet_key = self._get_subnet_key(src_ip)
        stats_subnet = self.subnet_stats[subnet_key] if subnet_key else None
        
        severity, should_alert = self._process_entity_stats(
            stats_ip, src_ip, now, dst_port,
            self.detected_ips, self.firewall_suggestions, is_subnet=False
        )
        
        if should_alert and severity >= L4_SEVERITY_LEVEL:
            self._handle_firewall_block(src_ip, is_subnet=False, now=now)

        if subnet_key and stats_subnet is not None:
            subnet_severity, subnet_alert = self._process_entity_stats(
                stats_subnet, subnet_key, now, dst_port,
                self.detected_subnets, self.firewall_suggestions, is_subnet=True
            )
            
            if subnet_alert and subnet_severity >= L4_SEVERITY_LEVEL:
                self._handle_firewall_block(subnet_key, is_subnet=True, now=now)
    
    def _get_current_suspicious(self) -> List[Dict[str, Any]]:
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
    
    def _periodic_save(self) -> None:
        """Periodically save status to file"""
        while self.running:
            time.sleep(60)  # Save every 60 seconds
            if self.running:
                self._save_status()
    
    def _display_table(self) -> None:
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
    
    def start(self, interface: Optional[str] = None, interface_id: Optional[str] = None) -> None:
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
    except Exception:
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

    def _require_windows():
        if not platform.system().lower().startswith("win"):
            raise HTTPException(status_code=400, detail="Firewall management is supported on Windows only")

    @app.on_event("startup")
    def _startup():
        nonlocal monitor_thread
        if monitor.running:
            return
        monitor_thread = Thread(target=monitor.start, kwargs={"interface_id": interface_id}, daemon=True)
        monitor_thread.start()

    @app.on_event("shutdown")
    def _shutdown():
        monitor.running = False
        try:
            monitor._save_status()
        except Exception:
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

    @app.delete("/api/exclusions/{ip}")
    def delete_exclusion(ip: str):
        removed = monitor.remove_excluded_ip(ip)
        if not removed:
            raise HTTPException(status_code=404, detail="IP not found")
        return {"removed": ip}

    @app.get("/api/firewall-rules")
    def get_firewall_rules():
        _require_windows()
        return monitor.list_firewall_rules(prefix=firewall_prefix)

    @app.post("/api/firewall-rules", status_code=201)
    def add_firewall_rule(payload: dict):
        _require_windows()
        entity = payload.get("entity") or ""
        is_subnet = bool(payload.get("is_subnet", False))
        success, was_new, display_name = monitor._add_firewall_rule(entity, is_subnet=is_subnet)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to add firewall rule")
        return {"display_name": display_name, "created": was_new}

    @app.delete("/api/firewall-rules/{display_name}")
    def delete_firewall_rule(display_name: str):
        _require_windows()
        removed = monitor.remove_firewall_rule(display_name)
        if not removed:
            raise HTTPException(status_code=404, detail="Firewall rule not found or could not be removed")
        return {"removed": display_name}

    @app.websocket("/ws/traffic")
    async def traffic_socket(websocket: WebSocket):
        await websocket.accept()
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
                    entries.append(entry)
                    for port in ports_set:
                        port_counter[port] += 1

                # Snapshot of current firewall rule names (to mark blocked entities)
                rule_names = set()
                try:
                    rules = monitor.list_firewall_rules(prefix=firewall_prefix)
                    for r in rules:
                        name = r.get("DisplayName") or r.get("display_name")
                        if name:
                            rule_names.add(name)
                except Exception:
                    rule_names = set()

                now_dt = datetime.utcnow()
                now = now_dt.isoformat()
                severity_counts = Counter(entry.get("level", 0) for entry in entries)
                ip_count = sum(1 for e in entries if e.get("type") == "IP")
                subnet_count = sum(1 for e in entries if e.get("type") == "SUBNET")

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
                top_talkers = sorted(entries, key=lambda e: e.get("packets", 0), reverse=True)[:5]
                top_ports = [
                    {"port": port, "count": count} for port, count in port_counter.most_common(5)
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
                    except Exception:
                        ts = None
                    if not ts or ts < cutoff:
                        to_delete.append(key)
                for key in to_delete:
                    recent_entities.pop(key, None)

                for e in entries:
                    entity_key = e.get("entity")
                    if not entity_key:
                        continue
                    display_name = f"{FIREWALL_PREFIX}{entity_key.replace('/', '_').replace('.', '_')}"
                    prev_info = recent_entities.get(entity_key, {})
                    prev_packets = prev_info.get("packets_24h", 0)
                    packets_now = e.get("packets", 0) or 0
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

                await websocket.send_json(
                    {
                        "timestamp": now,
                        "window_seconds": monitor.window.total_seconds(),
                        "max_packets": monitor.max_packets,
                        "max_ports": monitor.max_ports,
                        "entries": entries,
                        "severity_counts": dict(severity_counts),
                        "severity_history": list(traffic_history),
                        "top_talkers": [
                            {
                                "entity": t["entity"],
                                "packets": t.get("packets", 0),
                                "ports": t.get("ports", 0),
                                "level": t.get("level", 0),
                                "type": t.get("type", ""),
                            }
                            for t in top_talkers
                        ],
                        "top_ports": top_ports,
                        "recent_entities": recent_list,
                    }
                )
                await asyncio.sleep(1)
        except WebSocketDisconnect:
            return
        except Exception:
            await asyncio.sleep(1)

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

