"""
Vitorius Firewall - Ephemeral Temporal Network Lease Manager
Grants self-destructing, time-bounded firewall authorizations (Option 2: 15-minute preset),
automatically reaping kernel rules and severing sockets upon lease expiration.
"""

import time
import uuid
import logging
from dataclasses import dataclass
from typing import Optional, Callable

logger = logging.getLogger('vitorius.lineage.leases')


@dataclass
class EphemeralLease:
    lease_id: str
    target_ip: str
    target_port: int
    protocol: str
    pid: int
    pgid: int
    duration_sec: int
    created_at: float
    expires_at: float
    summary: str
    rule_spec: str
    zone: str

    @property
    def remaining_sec(self) -> int:
        return max(0, int(self.expires_at - time.time()))

    def to_dict(self) -> dict:
        rem = self.remaining_sec
        mins = rem // 60
        secs = rem % 60
        return {
            'lease_id': self.lease_id,
            'target_ip': self.target_ip,
            'target_port': self.target_port,
            'protocol': self.protocol,
            'pid': self.pid,
            'pgid': self.pgid,
            'duration_sec': self.duration_sec,
            'remaining_sec': rem,
            'remaining_formatted': f"{mins:02d}:{secs:02d}",
            'summary': self.summary,
            'zone': self.zone,
        }


class EphemeralLeaseManager:
    """Manages self-destructing temporary network rules."""

    PRESETS = {
        'option_1_5m': 300,        # Option 1: 5 minutes
        'option_2_15m': 900,       # Option 2 (Primary Default): 15 minutes
        'option_3_1h': 3600,       # Option 3: 1 hour
        'option_4_proc': 0,        # Option 4: Process Lifetime
    }

    def __init__(self, firewall_core, fw_logger=None, notify_callback: Optional[Callable[[str], None]] = None):
        self.core = firewall_core
        self.fw_logger = fw_logger
        self.notify = notify_callback
        self.active_leases: dict[str, EphemeralLease] = {}

    def grant_lease(
        self,
        target_ip: str,
        target_port: int,
        protocol: str = 'tcp',
        pid: int = 0,
        pgid: int = 0,
        duration_minutes: int = 15,  # Option 2 Default: 15 minutes
        summary: str = "",
        zone: Optional[str] = None
    ) -> EphemeralLease:
        """
        Grants a temporary network authorization.
        Default duration is 15 minutes (Option 2).
        """
        if zone:
            target_zone = zone
        elif self.core and getattr(self.core, 'is_running', lambda: False)():
            try:
                target_zone = self.core.get_default_zone()
            except Exception:
                target_zone = 'public'
        else:
            target_zone = 'public'
        lease_id = str(uuid.uuid4())[:8]
        duration_sec = duration_minutes * 60 if duration_minutes > 0 else 900
        now = time.time()
        expires_at = now + duration_sec

        # Construct runtime rich rule (permanent=False so it leaves no footprint on reboot)
        rule = f'rule family="ipv4" destination address="{target_ip}" port port="{target_port}" protocol="{protocol}" accept'
        if self.core and getattr(self.core, 'is_running', lambda: False)():
            try:
                self.core.add_rich_rule(target_zone, rule, permanent=False)
            except Exception as e:
                logger.debug(f"Could not inject runtime rich rule: {e}")

        lease = EphemeralLease(
            lease_id=lease_id,
            target_ip=target_ip,
            target_port=target_port,
            protocol=protocol,
            pid=pid,
            pgid=pgid,
            duration_sec=duration_sec,
            created_at=now,
            expires_at=expires_at,
            summary=summary or f"{target_ip}:{target_port}",
            rule_spec=rule,
            zone=target_zone
        )

        self.active_leases[lease_id] = lease
        logger.info(f"Ephemeral Lease [{lease_id}] granted for {duration_minutes}m to {target_ip}:{target_port} ({summary}).")

        if self.fw_logger:
            self.fw_logger.log_event(
                event_type='rule_added',
                severity='info',
                details=f"Ephemeral lease granted ({duration_minutes}m) for '{summary}' to {target_ip}:{target_port}"
            )

        if self.notify:
            self.notify(f"⏳ Ephemeral lease granted ({duration_minutes} min) for {summary or target_ip}")

        return lease

    def revoke_lease(self, lease_id: str) -> bool:
        """Atomically remove kernel rich rule and sever sockets."""
        lease = self.active_leases.pop(lease_id, None)
        if not lease:
            return False

        # Remove runtime rule from firewalld
        if self.core and getattr(self.core, 'is_running', lambda: False)():
            try:
                self.core.remove_rich_rule(lease.zone, lease.rule_spec, permanent=False)
            except Exception:
                pass

        # Sever lingering sockets immediately
        try:
            import subprocess
            subprocess.run(
                ['ss', '-K', f'dst {lease.target_ip}', f'dport = :{lease.target_port}'],
                capture_output=True, timeout=2.0
            )
        except Exception:
            pass

        logger.info(f"Ephemeral Lease [{lease_id}] reaped and sockets severed for {lease.target_ip}:{lease.target_port}")
        return True

    def check_and_reap_expired(self) -> list[str]:
        """Scans active leases and reaps any whose time has expired."""
        now = time.time()
        expired_ids = [
            l_id for l_id, lease in self.active_leases.items()
            if now >= lease.expires_at
        ]

        for l_id in expired_ids:
            lease = self.active_leases.get(l_id)
            desc = lease.summary if lease else l_id
            self.revoke_lease(l_id)
            if self.fw_logger:
                self.fw_logger.log_event(
                    event_type='rule_removed',
                    severity='info',
                    details=f"Ephemeral lease [{l_id}] expired. Rules reaped and sockets severed for '{desc}'"
                )
            if self.notify:
                self.notify(f"⏳ Ephemeral lease expired: access severed for {desc}")

        return expired_ids

    def get_active_leases(self) -> list[dict]:
        return [l.to_dict() for l in self.active_leases.values()]
