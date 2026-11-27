"""
Vitorius Firewall - Honeypot Quarantine & Active Defense Engine
Evaluates real-time threat scores, safeguards whitelisted infrastructure,
and automatically isolates aggressive attackers across all firewall zones.
"""

import ipaddress
import os
import subprocess
import threading
import logging
from collections import defaultdict
from typing import Callable, Optional

logger = logging.getLogger('vitorius.honeypot.quarantine')


class QuarantineEngine:
    """Calculates threat score, tracks repeat offenders, and triggers auto-bans."""

    def __init__(
        self,
        firewall_core,
        fw_logger,
        telemetry,
        notify_callback: Optional[Callable[[str, bool], None]] = None,
        ban_threshold: int = 75,
        auto_ban_enabled: bool = True,
        async_ban: bool = False,
    ):
        self.core = firewall_core
        self.fw_logger = fw_logger
        self.telemetry = telemetry
        self.notify = notify_callback
        self.ban_threshold = ban_threshold
        self.auto_ban_enabled = auto_ban_enabled
        self.async_ban = async_ban

        self._lock = threading.RLock()
        self.ip_scores: dict[str, int] = defaultdict(int)
        self.banned_ips: set[str] = set()
        self._isolating_ips: set[str] = set()
        self.whitelist: set[str] = {'127.0.0.1', '::1'}
        self._load_network_whitelist()

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        """Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)."""
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        except ValueError:
            return ip

    def _load_network_whitelist(self):
        """Safeguard local gateway, broadcast, and active DNS servers from auto-ban."""
        try:
            # Query default gateway via 'ip route show default'
            res = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=2.0
            )
            for part in res.stdout.split():
                try:
                    ipaddress.ip_address(part)
                    self.whitelist.add(part)
                except ValueError:
                    pass
        except Exception:
            pass

        # Query DNS nameservers from /etc/resolv.conf
        try:
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    ipaddress.ip_address(parts[1])
                                    self.whitelist.add(parts[1])
                                except ValueError:
                                    pass
        except Exception:
            pass

    def add_whitelist_ip(self, ip_str: str):
        try:
            norm = self._normalize_ip(ip_str)
            ipaddress.ip_address(norm)
            with self._lock:
                self.whitelist.add(norm)
        except ValueError:
            pass

    def record_interaction(
        self,
        ip: str,
        source_port: int,
        target_port: int,
        decoy_name: str,
        event_type: str,
        details: str,
        payload: Optional[dict] = None
    ) -> int:
        """
        Record a decoy interaction, adjust score, log telemetry, and trigger auto-containment.
        Returns the updated threat score.
        """
        norm_ip = self._normalize_ip(ip)
        with self._lock:
            if norm_ip in self.whitelist:
                logger.debug(f"Honeypot hit from whitelisted address {norm_ip} ignored.")
                return 0

            score_increment = {
                'port_probe': 15,
                'port_scan_multiple': 30,
                'credential_attempt': 25,
                'exploit_url_probe': 40,
                'canary_download': 50,
            }.get(event_type, 15)

            self.ip_scores[norm_ip] += score_increment
            current_score = self.ip_scores[norm_ip]
            already_handled = (norm_ip in self.banned_ips or norm_ip in self._isolating_ips)
            should_isolate = (
                self.auto_ban_enabled
                and current_score >= self.ban_threshold
                and not already_handled
            )
            if should_isolate and self.async_ban:
                self._isolating_ips.add(norm_ip)

        self.telemetry.record_incident(
            source_ip=norm_ip,
            source_port=source_port,
            target_port=target_port,
            decoy_name=decoy_name,
            event_type=event_type,
            details=details,
            threat_score=current_score,
            payload=payload
        )

        if self.fw_logger:
            self.fw_logger.log_event(
                event_type='honeypot_hit',
                severity='warning' if current_score < self.ban_threshold else 'critical',
                details=f"Decoy [{decoy_name}] hit by {norm_ip} ({event_type}): {details} (Score: {current_score})",
                extra=payload or {}
            )

        if self.notify:
            is_critical = (current_score >= self.ban_threshold)
            msg = f"⚠️ Deception Alert: {norm_ip} probed {decoy_name} ({details})"
            self.notify(msg, is_critical)

        if should_isolate:
            reason = f"Honeypot threat score {current_score} exceeded threshold {self.ban_threshold}"
            if self.async_ban:
                threading.Thread(
                    target=self.isolate_host,
                    args=(norm_ip, reason),
                    daemon=True,
                    name=f"quarantine-{norm_ip}",
                ).start()
            else:
                self.isolate_host(norm_ip, reason=reason)

        return current_score

    def isolate_host(self, ip: str, reason: str) -> bool:
        """Sever all sockets and enforce permanent/temporary drop rule."""
        norm_ip = self._normalize_ip(ip)
        with self._lock:
            if norm_ip in self.whitelist:
                self._isolating_ips.discard(norm_ip)
                return False

        try:
            success = self.core.block_ip(norm_ip)
        finally:
            with self._lock:
                self._isolating_ips.discard(norm_ip)

        if success:
            with self._lock:
                self.banned_ips.add(norm_ip)
            logger.warning(f"Host {norm_ip} isolated via FirewallCore.block_ip(). Reason: {reason}")
            if self.fw_logger:
                self.fw_logger.log_event(
                    event_type='honeypot_auto_ban',
                    severity='alert',
                    details=f"Auto-quarantined hostile IP {norm_ip}. Reason: {reason}"
                )
            if self.notify:
                self.notify(f"🛡️ Auto-Quarantine: Blocked {norm_ip} across all firewall zones", True)
            return True
        return False

    def release_host(self, ip: str) -> bool:
        """Remove host from quarantine."""
        norm_ip = self._normalize_ip(ip)
        ok = self.core.unblock_ip(norm_ip)
        with self._lock:
            self.banned_ips.discard(norm_ip)
            self._isolating_ips.discard(norm_ip)
            self.ip_scores.pop(norm_ip, None)
        return ok

    def get_banned_hosts(self) -> list[str]:
        with self._lock:
            return sorted(list(self.banned_ips))
