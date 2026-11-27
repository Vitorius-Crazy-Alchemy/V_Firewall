"""
Vitorius Firewall - Honeypot Telemetry & Incident Store
Persists honeypot hit telemetry, captured credentials, and exfiltration attempts.
"""

import os
import json
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger('vitorius.honeypot.telemetry')

BASE_STORAGE = Path(__file__).resolve().parent.parent.parent / '.storage'

try:
    DEFAULT_LOG_DIR = Path.home() / '.local' / 'share' / 'vitorius-firewall' / 'honeypot'
    DEFAULT_LOG_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    DEFAULT_LOG_DIR = BASE_STORAGE / 'honeypot'

LOG_FILE = DEFAULT_LOG_DIR / 'honeypot_events.jsonl'


class HoneypotTelemetry:
    """Manages recording and querying honeypot security events."""

    def __init__(self, log_path: Optional[Path] = None, max_entries: int = 5000):
        self._lock = threading.RLock()
        self.log_path = log_path or LOG_FILE
        self.max_entries = max_entries
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: list[dict] = []
        self._load_cache()

    def _load_cache(self):
        """Read existing lines from JSONL log."""
        with self._lock:
            if not self.log_path.exists():
                return
            try:
                entries = []
                with open(self.log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except Exception:
                                pass
                self._cache = entries[-self.max_entries:]
            except Exception as e:
                logger.error(f"Error loading honeypot telemetry: {e}")

    def record_incident(
        self,
        source_ip: str,
        source_port: int,
        target_port: int,
        decoy_name: str,
        event_type: str,
        details: str,
        threat_score: int,
        payload: Optional[dict] = None
    ) -> dict:
        """Record an incident, append to log file, and update cache."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'source_port': source_port,
            'target_port': target_port,
            'decoy_name': decoy_name,
            'event_type': event_type,
            'details': details,
            'threat_score': threat_score,
            'payload': payload or {},
        }

        with self._lock:
            self._cache.append(event)
            if len(self._cache) > self.max_entries:
                self._cache = self._cache[-self.max_entries:]

            try:
                with open(self.log_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(event) + '\n')
            except Exception as e:
                logger.error(f"Error appending to honeypot telemetry log: {e}")

        return event

    def get_recent_incidents(self, limit: int = 100) -> list[dict]:
        """Return most recent incidents (newest first)."""
        with self._lock:
            return list(reversed(self._cache[-limit:]))

    def get_metrics_summary(self) -> dict:
        """Calculate metrics: hits 24h, unique attackers, canary downloads, credentials captured."""
        with self._lock:
            snapshot = list(self._cache)
        cutoff_24h = datetime.now() - timedelta(hours=24)
        hits_24h = 0
        unique_ips = set()
        canary_downloads = 0
        captured_creds = []

        for e in snapshot:
            ip = e.get('source_ip', '')
            if ip:
                unique_ips.add(ip)

            try:
                t = datetime.fromisoformat(e.get('timestamp', ''))
                if t >= cutoff_24h:
                    hits_24h += 1
            except Exception:
                pass

            if e.get('event_type') == 'canary_download':
                canary_downloads += 1

            cred = e.get('payload', {}).get('credentials')
            if cred and isinstance(cred, dict):
                captured_creds.append(cred)

        return {
            'total_incidents': len(snapshot),
            'hits_24h': hits_24h,
            'unique_attackers': len(unique_ips),
            'canary_downloads': canary_downloads,
            'captured_credentials_count': len(captured_creds),
            'captured_credentials': captured_creds[-20:],
        }

    def clear_incidents(self):
        """Purge incident log."""
        with self._lock:
            self._cache.clear()
            try:
                with open(self.log_path, 'w', encoding='utf-8') as f:
                    f.write('')
            except Exception as e:
                logger.error(f"Error clearing honeypot log: {e}")
