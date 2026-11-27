"""
Vitorius Firewall - IDS Kernel Denied-Packet Stream Monitor
Parses netfilter/firewalld denied packet logs (journalctl -k) to detect port scans
and repeated hostile probes when Corporate / Maximum Security IDS mode is enabled.
"""

import logging
import re
import subprocess
import threading
import time
from collections import defaultdict
from typing import Callable, Optional

logger = logging.getLogger('vitorius.ids')

_SRC_RE = re.compile(r'\bSRC=([^\s]+)')
_DPT_RE = re.compile(r'\bDPT=(\d+)')
_PROTO_RE = re.compile(r'\bPROTO=([^\s]+)')
_DENY_MARKERS = ('VitoriusFW_', 'FINAL_REJECT', 'STATE_INVALID_DROP', 'DROP', 'REJECT')


class IdsLogMonitor:
    """Streams kernel denied-packet events and raises alerts on port scan bursts."""

    def __init__(
        self,
        fw_logger=None,
        notify_callback: Optional[Callable[[str], None]] = None,
        burst_threshold: int = 5,
        window_sec: float = 10.0,
        alert_cooldown_sec: float = 60.0,
    ):
        self.fw_logger = fw_logger
        self.notify = notify_callback
        self.burst_threshold = burst_threshold
        self.window_sec = window_sec
        self.alert_cooldown_sec = alert_cooldown_sec

        self._lock = threading.RLock()
        self._hits_by_ip: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._last_alert_by_ip: dict[str, float] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None

    def analyze_log_line(self, line: str, now: Optional[float] = None) -> Optional[dict]:
        """Inspect a single kernel log line; return an alert dict if a scan burst is detected."""
        if not line or not any(m in line for m in _DENY_MARKERS):
            return None
        if 'IN=' not in line and 'OUT=' not in line:
            return None

        src_m = _SRC_RE.search(line)
        if not src_m:
            return None
        src_ip = src_m.group(1)
        if src_ip in ('127.0.0.1', '::1'):
            return None

        dpt_m = _DPT_RE.search(line)
        proto_m = _PROTO_RE.search(line)
        dpt = dpt_m.group(1) if dpt_m else '?'
        proto = proto_m.group(1) if proto_m else 'PKT'
        ts = now if now is not None else time.time()

        with self._lock:
            cutoff = ts - self.window_sec
            if len(self._hits_by_ip) > 2048:
                for k in list(self._hits_by_ip.keys()):
                    kept = [(t, p) for (t, p) in self._hits_by_ip[k] if t >= cutoff]
                    if kept:
                        self._hits_by_ip[k] = kept
                    else:
                        del self._hits_by_ip[k]
                self._last_alert_by_ip = {
                    k: v for k, v in self._last_alert_by_ip.items()
                    if (ts - v) < self.alert_cooldown_sec
                }
            recent = [(t, p) for (t, p) in self._hits_by_ip[src_ip] if t >= cutoff]
            recent.append((ts, dpt))
            self._hits_by_ip[src_ip] = recent

            unique_ports = {p for _, p in recent if p != '?'}
            is_scan = len(unique_ports) >= self.burst_threshold or len(recent) >= (self.burst_threshold * 2)
            if not is_scan:
                return None

            last_alert = self._last_alert_by_ip.get(src_ip, 0.0)
            if (ts - last_alert) < self.alert_cooldown_sec:
                return None
            self._last_alert_by_ip[src_ip] = ts

        event_type = 'port_scan_detected' if len(unique_ports) >= self.burst_threshold else 'ids_alert'
        details = (
            f"IDS detected {proto} probe burst from {src_ip} "
            f"({len(recent)} drops across {len(unique_ports) or 1} port(s) in {int(self.window_sec)}s)"
        )
        alert = {
            'source_ip': src_ip,
            'event_type': event_type,
            'ports': sorted(unique_ports),
            'hit_count': len(recent),
            'details': details,
        }

        if self.fw_logger:
            self.fw_logger.log_event(event_type, 'alert', details, extra={'ports': alert['ports']})
        if self.notify:
            try:
                self.notify(f"🛡️ IDS Alert: {details}")
            except Exception:
                pass
        return alert

    def start(self):
        """Start background journalctl -k listener if available."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(target=self._stream_loop, daemon=True, name="ids-log-monitor")
            self._thread.start()
            logger.info("IDS kernel log monitor started")

    def stop(self):
        """Stop background log listener cleanly."""
        with self._lock:
            self._running = False
            proc = self._proc
            self._proc = None
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None

    def is_running(self) -> bool:
        return self._running

    def _stream_loop(self):
        try:
            proc = subprocess.Popen(
                ['journalctl', '-k', '-f', '-n', '0', '-o', 'cat'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            with self._lock:
                self._proc = proc
            if proc.stdout:
                for line in proc.stdout:
                    if not self._running:
                        break
                    self.analyze_log_line(line)
        except Exception as e:
            logger.debug(f"IDS journalctl stream unavailable: {e}")
        finally:
            with self._lock:
                self._running = False
                self._proc = None
