#!/usr/bin/env python3
"""
Dark Web RSS Feed Monitor - V3.1
Alex Dumas
"""

import feedparser
import requests
import time
import json
import hashlib
import re
import logging
import secrets
import socket
import tempfile
import shutil
import signal
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Pattern
from enum import IntEnum
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __str__(self): return self.name

@dataclass
class MonitorConfig:
    """
    Central Configuration Class.
    Fields marked [USER INPUT REQUIRED] are deisgnated for your own preferred settings.
    """
    
    # --- [USER INPUT REQUIRED] INFRASTRUCTURE ---
    # TOR Service Address 
    # Standard is 9050 for system daemon, 9150 for Tor Browser bundle.
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    
    # Port for sending control signals (NEWNYM) to rotate IP.
    # Ensure 'ControlPort 9051' is uncommented in your torrc file.
    tor_control_port: int = 9051
    
    # If your torrc has 'HashedControlPassword', put the raw password here.
    # If using CookieAuthentication or no auth, leave as None.
    tor_control_password: Optional[str] = None 
    
    # --- [USER INPUT REQUIRED] LOGGING & STATE ---
    # Where to store the duplication history and logs.
    state_file: Path = Path("monitor_state.json")
    alert_log_file: Path = Path("alerts.jsonl") # JSON Lines format for SIEM
    app_log_file: Path = Path("monitor.log")    # Human readable logs
    
    # --- [USER INPUT REQUIRED] TUNING ---
    # How often to scan all feeds (in seconds). Default: 30 minutes.
    scan_interval_seconds: int = 1800
    
    # Time to wait for a Tor request to complete.
    request_timeout: int = 45
    
    # Jitter: Random sleep between requests (min, max) to avoid bot detection patterns.
    request_delay_range: Tuple[int, int] = (5, 15)
    
    # How long to remember seen posts to prevent duplicate alerts.
    retention_days: int = 14
    
    # Safety valve: Stop alerting if this many hits occur in one cycle (DoS protection).
    max_alerts_per_cycle: int = 100
    
    # --- [USER INPUT REQUIRED] TARGET FEEDS ---
    # List of .onion RSS URLs to monitor. 
    # NOTE: Replace these examples with live dark web feed URLs.
    # I do not accept any responsability for information returned by your own use of this scraper.
    feeds: List[str] = field(default_factory=lambda: [
        "http://breach-forums.onion/syndication.php?limit=20",
        "http://exploit_in.onion/external.php?type=RSS2",
        "http://xss_forum.onion/forums/-/index.rss"
    ])
    
    # --- [USER INPUT REQUIRED] DETECTION RULES ---
    # format: (Regex Pattern, Severity Level)
    # Use raw strings (r"...") for regex.
    keywords: List[Tuple[str, Severity]] = field(default_factory=lambda: [
        # Example: Detect your company name
        (r"\bMyCompanyName\b", Severity.HIGH),
        
        # Example: Detect your domain
        (r"mycompany\.com", Severity.CRITICAL),
        
        # Example: Detect specific project leaks
        (r"ProjectAlpha[_\-\s]?Leak", Severity.HIGH),
        
        # Example: Generic high-noise keywords (Lower severity)
        (r"(?:database|db)\s+(?:dump|leak|breach)", Severity.MEDIUM),
    ])
    
    # User Agents to rotate through (Standard Firefox/Chrome on various OS)
    # Add as many relevant user agents as you wish, however performence is impacted above 200 agents.
        "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    ])

    def __post_init__(self):
        # Create directories if they don't exist
        for path in [self.state_file, self.alert_log_file, self.app_log_file]:
            path.parent.mkdir(parents=True, exist_ok=True)

# ============================================================================
# UTILITIES & INFRASTRUCTURE (DO NOT MODIFY)
# ============================================================================

class TorController:
    """Manages Tor identity rotation using raw sockets to avoid dependencies."""
    def __init__(self, port: int, password: Optional[str] = None):
        self.port = port
        self.password = password

    def renew_circuit(self) -> bool:
        """Sends SIGNAL NEWNYM to Tor Control Port to get a new IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect(('127.0.0.1', self.port))
                
                # Authenticate
                auth_cmd = f'AUTHENTICATE "{self.password}"\r\n' if self.password else 'AUTHENTICATE ""\r\n'
                s.sendall(auth_cmd.encode())
                resp = s.recv(1024).decode()
                
                if "250" not in resp:
                    logging.getLogger("DarkWebMonitor").warning(f"Tor Control Auth Failed: {resp.strip()}")
                    return False

                # Send Signal
                s.sendall(b'SIGNAL NEWNYM\r\n')
                resp = s.recv(1024).decode()
                
                if "250" in resp:
                    logging.getLogger("DarkWebMonitor").info("Tor Circuit Rotated (NEWNYM sent)")
                    time.sleep(2) # Allow circuit rebuild
                    return True
                    
        except Exception as e:
            logging.getLogger("DarkWebMonitor").warning(f"Tor Control Port Error: {e}")
        return False

class Utils:
    # Regex to strip dangerous control characters from logs
    CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\ufeff]')
    
    @staticmethod
    def atomic_write(filepath: Path, data: dict) -> bool:
        """Safely writes JSON to disk. Prevents corruption if script crashes during write."""
        try:
            with tempfile.NamedTemporaryFile('w', dir=filepath.parent, delete=False, encoding='utf-8') as tf:
                json.dump(data, tf, indent=2)
                temp_name = tf.name
            Path(temp_name).replace(filepath)
            return True
        except Exception as e:
            logging.getLogger("DarkWebMonitor").error(f"Atomic write failed: {e}")
            if 'temp_name' in locals():
                Path(temp_name).unlink(missing_ok=True)
            return False

    @staticmethod
    def sanitize(text: str, max_length: int = 2000) -> str:
        """Cleans input for safe logging."""
        if not text: return ""
        cleaned = Utils.CONTROL_CHARS.sub('', text)
        return cleaned[:max_length]

    @staticmethod
    def compute_hash(entry: Dict, feed_url: str) -> str:
        """Generates a unique ID for deduplication."""
        # Combines feed URL + Entry ID to avoid collisions between forums
        uid = entry.get('link') or entry.get('id') or f"{entry.get('title','')}{entry.get('published','')}"
        return hashlib.sha256(f"{feed_url}|{uid}".encode('utf-8')).hexdigest()

class StateManager:
    """Tracks which posts have already been analyzed."""
    def __init__(self, filepath: Path, retention: int):
        self.filepath = filepath
        self.retention = retention
        self.state: Dict[str, float] = self._load()
        self._last_save = time.time()

    def _load(self) -> Dict[str, float]:
        if not self.filepath.exists(): return {}
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # Backup corrupt state for manual inspection
            if self.filepath.exists():
                shutil.copy(self.filepath, self.filepath.with_suffix('.bak'))
            return {}

    def is_seen(self, entry_hash: str) -> bool:
        return entry_hash in self.state

    def mark_seen(self, entry_hash: str):
        self.state[entry_hash] = datetime.now(timezone.utc).timestamp()

    def prune_and_save(self, force: bool = False):
        # Remove old entries
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention)).timestamp()
        self.state = {k: v for k, v in self.state.items() if v > cutoff}
        
        # Save to disk (Throttled to max once per minute unless forced)
        if force or (time.time() - self._last_save > 60):
            if Utils.atomic_write(self.filepath, self.state):
                self._last_save = time.time()

# ============================================================================
# MAIN LOGIC
# ============================================================================

class DarkWebMonitor:
    def __init__(self, config: MonitorConfig):
        self.cfg = config
        self.op_logger, self.alert_logger = self._setup_logging()
        self.state = StateManager(config.state_file, config.retention_days)
        self.tor = TorController(config.tor_control_port, config.tor_control_password)
        self.session = self._build_session()
        # Pre-compile regex patterns for performance
        self.patterns = [(re.compile(p, re.IGNORECASE), s) for p, s in config.keywords]
        
        # Graceful Shutdown Handling
        self.running = True
        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _setup_logging(self):
        # 1. Operational Log (For the Admin)
        op = logging.getLogger("DarkWebMonitor")
        op.setLevel(logging.INFO)
        op.addHandler(logging.StreamHandler(sys.stdout))
        op.addHandler(RotatingFileHandler(self.cfg.app_log_file, maxBytes=10*1024*1024, backupCount=5))
        
        # 2. Alert Log (For the SIEM - JSONL Format)
        alert = logging.getLogger("Alerts")
        alert.setLevel(logging.INFO)
        handler = logging.FileHandler(self.cfg.alert_log_file)
        handler.setFormatter(logging.Formatter('%(message)s'))
        alert.addHandler(handler)
        alert.propagate = False
        return op, alert

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.proxies = {'http': self.cfg.tor_proxy, 'https': self.cfg.tor_proxy}
        s.headers.update({'Connection': 'keep-alive'})
        # Resilience: Retry automatically on network failures
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[408, 429, 500, 502, 503, 504])
        s.mount('http://', HTTPAdapter(max_retries=retry))
        s.mount('https://', HTTPAdapter(max_retries=retry))
        return s

    def _stop(self, signum, frame):
        self.op_logger.warning("Shutdown signal received. Finishing current tasks...")
        self.running = False

    def _rotate_identity(self):
        # 1. Switch User-Agent
        self.session.headers.update({"User-Agent": secrets.choice(self.cfg.user_agents)})
        # 2. (Optional) Switch IP. Uncomment next line if ControlPort is configured.
        # self.tor.renew_circuit()

    def _process_entry(self, entry: Any, url: str, source_title: str) -> bool:
        """Analyzes a single post for keywords."""
        entry_hash = Utils.compute_hash(entry, url)
        
        # Deduplication check
        if self.state.is_seen(entry_hash):
            return False
        
        self.state.mark_seen(entry_hash)
        
        # Extract and normalize content
        content = " ".join([
            entry.get('title', ''),
            entry.get('summary', ''),
            entry.get('description', ''),
            str(entry.get('content', ''))
        ]).lower()

        # Regex Scan
        matches = []
        for regex, severity in self.patterns:
            if m := regex.search(content):
                matches.append({
                    "pattern": regex.pattern, 
                    "severity": severity,
                    "snippet": Utils.sanitize(m.group(0))
                })

        # Alert if matches found
        if matches:
            self._emit_alert(entry, url, source_title, matches)
            return True
        return False

    def _emit_alert(self, entry, url, source, matches):
        """Writes the structured alert to JSONL and console."""
        max_sev = max(m['severity'] for m in matches)
        
        # Structured JSON for SIEM
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "darkweb_hit",
            "severity_level": str(max_sev),
            "severity_score": int(max_sev),
            "source": {"url": url, "name": Utils.sanitize(source)},
            "entry": {
                "title": Utils.sanitize(entry.get('title', '')),
                "link": Utils.sanitize(entry.get('link', '')),
                "published": str(entry.get('published', ''))
            },
            "matches": [{k: str(v) for k, v in m.items()} for m in matches]
        }
        self.alert_logger.info(json.dumps(alert))
        self.op_logger.warning(f"🚨 ALERT: {len(matches)} matches in {url} (Severity: {max_sev})")

    def _verify_tor(self) -> bool:
        """Ensures traffic is actually routed through Tor."""
        try:
            ip = self.session.get("http://httpbin.org/ip", timeout=20).json()['origin']
            self.op_logger.info(f"Tor Connection Verified. Exit IP: {ip}")
            return True
        except Exception as e:
            self.op_logger.critical(f"Tor Connectivity Failed: {e}. Check your 'tor_proxy' setting.")
            return False

    def run(self):
        self.op_logger.info("Initializing Dark Web Monitor...")
        if not self._verify_tor():
            return

        while self.running:
            self.op_logger.info(f"Starting scan cycle at {datetime.now().strftime('%H:%M:%S')}...")
            alerts_count = 0
            
            for url in self.cfg.feeds:
                if not self.running: break
                
                self._rotate_identity()
                
                try:
                    # Random Jitter to evade bot detection
                    time.sleep(secrets.randbelow(self.cfg.request_delay_range[1]) + self.cfg.request_delay_range[0])
                    
                    resp = self.session.get(url, timeout=self.cfg.request_timeout)
                    feed = feedparser.parse(resp.content)
                    
                    if feed.bozo:
                        self.op_logger.debug(f"Feed Parsing Warning {url}: {feed.bozo_exception}")

                    for entry in feed.entries:
                        if self._process_entry(entry, url, feed.feed.get('title', 'Unknown')):
                            alerts_count += 1
                            if alerts_count >= self.cfg.max_alerts_per_cycle:
                                self.op_logger.warning("Max alerts per cycle reached. Skipping remaining feeds.")
                                break
                                
                except Exception as e:
                    self.op_logger.error(f"Error scanning {url}: {e}")
                    # If network error, try rotating circuit to get a new path
                    if "SOCKS" in str(e) or "Connection" in str(e):
                        self.tor.renew_circuit()

            self.state.prune_and_save(force=False)
            
            # Sleep Loop (Interruptible)
            if self.running:
                self.op_logger.info(f"Cycle done. Sleeping {self.cfg.scan_interval_seconds}s")
                for _ in range(self.cfg.scan_interval_seconds // 2):
                    if not self.running: break
                    time.sleep(2)
        
        # Cleanup on exit
        self.state.prune_and_save(force=True)
        self.op_logger.info("Monitor Stopped.")

if __name__ == "__main__":
    # Load Config and Run
    DarkWebMonitor(MonitorConfig()).run()
