"""
Vitorius Firewall - Honeypot Quarantine & Active Defense Engine
Evaluates real-time threat scores, safeguards whitelisted infrastructure,
and automatically isolates aggressive attackers across all firewall zones.
"""

import ipaddress
import subprocess
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
        auto_ban_enabled: bool = True
    ):
        self.core = firewall_core
        self.fw_logger = fw_logger
        self.telemetry = telemetry
        self.notify = notify_callback
        self.ban_threshold = ban_threshold
        self.auto_ban_enabled = auto_ban_enabled

        self.ip_scores: dict[str, int] = defaultdict(int)
        self.banned_ips: set[str] = set()
        self.whitelist: set[str] = {'127.0.0.1', '::1'}
        self._load_network_whitelist()

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
            ipaddress.ip_address(ip_str)
            self.whitelist.add(ip_str)
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
        if ip in self.whitelist:
            logger.debug(f"Honeypot hit from whitelisted address {ip} ignored.")
            return 0

        score_increment = {
            'port_probe': 15,
            'port_scan_multiple': 30,
            'credential_attempt': 25,
            'exploit_url_probe': 40,
            'canary_download': 50,  # Accessing or downloading encrypted honey-files
        }.get(event_type, 15)

        self.ip_scores[ip] += score_increment
        current_score = self.ip_scores[ip]

        # Record in honeypot telemetry log
        self.telemetry.record_incident(
            source_ip=ip,
            source_port=source_port,
            target_port=target_port,
            decoy_name=decoy_name,
            event_type=event_type,
            details=details,
            threat_score=current_score,
            payload=payload
        )

        # Log in structured central audit trail
        if self.fw_logger:
            self.fw_logger.log_event(
                event_type='honeypot_hit',
                severity='warning' if current_score < self.ban_threshold else 'critical',
                details=f"Decoy [{decoy_name}] hit by {ip} ({event_type}): {details} (Score: {current_score})",
                extra=payload or {}
            )

        # Dispatch UI / Tray notification
        if self.notify:
            is_critical = (current_score >= self.ban_threshold)
            msg = f"⚠️ Deception Alert: {ip} probed {decoy_name} ({details})"
            self.notify(msg, is_critical)

        # Trigger Auto-Containment if threshold reached
        if self.auto_ban_enabled and current_score >= self.ban_threshold and ip not in self.banned_ips:
            self.isolate_host(ip, reason=f"Honeypot threat score {current_score} exceeded threshold {self.ban_threshold}")

        return current_score

    def isolate_host(self, ip: str, reason: str) -> bool:
        """Sever all sockets and enforce permanent/temporary drop rule."""
        if ip in self.whitelist:
            return False

        self.banned_ips.add(ip)
        success = self.core.block_ip(ip)

        if success:
            logger.warning(f"Host {ip} isolated via FirewallCore.block_ip(). Reason: {reason}")
            if self.fw_logger:
                self.fw_logger.log_event(
                    event_type='honeypot_auto_ban',
                    severity='alert',
                    details=f"Auto-quarantined hostile IP {ip}. Reason: {reason}"
                )
            if self.notify:
                self.notify(f"🛡️ Auto-Quarantine: Blocked {ip} across all firewall zones", True)
            return True
        return False

    def release_host(self, ip: str) -> bool:
        """Remove host from quarantine."""
        if ip in self.banned_ips:
            self.banned_ips.discard(ip)
        self.ip_scores.pop(ip, None)
        return self.core.unblock_ip(ip)

    def get_banned_hosts(self) -> list[str]:
        return sorted(list(self.banned_ips))
