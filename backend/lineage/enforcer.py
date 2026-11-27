"""
Vitorius Firewall - LineageGuard Live Enforcement Hook
Evaluates newly observed outbound socket connections against process ancestry trees,
optionally micro-freezes anomalous process groups, and raises operator triage alerts.
"""

import ipaddress
import os
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from backend.lineage.freezer import ProcessFreezer
from backend.lineage.policy import LineagePolicyEngine
from backend.lineage.resolver import LineageResolver, LineageTree

logger = logging.getLogger('vitorius.lineage.enforcer')

HIGH_RISK_ANOMALIES = {
    'DEV_SUPPLY_CHAIN_ANOMALY',
    'BROWSER_ESCAPE_SPAWN',
    'HIDDEN_EXEC_ANOMALY',
}


@dataclass
class LineageAlert:
    pid: int
    pgid: int
    process_name: str
    remote_ip: str
    remote_port: int
    anomaly_type: str
    description: str
    tree: LineageTree
    frozen: bool = False
    timestamp: float = field(default_factory=time.time)


class LineageEnforcer:
    """Monitors live connection snapshots for anomalous process ancestry."""

    def __init__(
        self,
        resolver: LineageResolver,
        policy: LineagePolicyEngine,
        freezer: ProcessFreezer,
        fw_logger=None,
        alert_callback: Optional[Callable[[LineageAlert], None]] = None,
        enabled: bool = True,
        freeze_enabled: bool = True,
    ):
        self.resolver = resolver
        self.policy = policy
        self.freezer = freezer
        self.fw_logger = fw_logger
        self.alert_callback = alert_callback
        self.enabled = enabled
        self.freeze_enabled = freeze_enabled

        self._lock = threading.RLock()
        self._seen_events: dict[tuple, float] = {}
        self._own_pid = os.getpid()
        self._own_uid = os.getuid()
        self._max_seen = 4096

    @staticmethod
    def _is_external_ip(ip_str: str) -> bool:
        if not ip_str or ip_str in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return not (addr.is_loopback or addr.is_unspecified)
        except ValueError:
            return False

    def _prune_seen(self, now: float):
        if len(self._seen_events) > self._max_seen:
            cutoff = now - 300.0
            self._seen_events = {k: ts for k, ts in self._seen_events.items() if ts >= cutoff}
            if len(self._seen_events) > self._max_seen:
                # Keep newest half
                items = sorted(self._seen_events.items(), key=lambda kv: kv[1], reverse=True)
                self._seen_events = dict(items[: self._max_seen // 2])

    def inspect_connections(self, connections: list) -> list[LineageAlert]:
        """Evaluate a snapshot of ConnectionInfo objects and return any triggered alerts."""
        if not self.enabled:
            return []

        now = time.time()
        alerts: list[LineageAlert] = []
        with self._lock:
            self._prune_seen(now)

        for conn in connections:
            pid = getattr(conn, 'pid', 0) or 0
            if pid <= 1 or pid == self._own_pid:
                continue
            state = getattr(conn, 'state', '')
            if state not in ('ESTABLISHED', 'SYN_SENT', 'ACTIVE'):
                continue
            remote_ip = getattr(conn, 'remote_ip', '')
            remote_port = int(getattr(conn, 'remote_port', 0) or 0)
            if remote_port <= 0 or not self._is_external_ip(remote_ip):
                continue

            tree = self.resolver.resolve_tree(pid)
            if not tree or not tree.nodes:
                continue

            leaf = tree.leaf
            # Only enforce automatically on current user processes to avoid freezing system services
            if leaf.uid != self._own_uid:
                continue

            dedup_key = (pid, leaf.starttime, remote_ip, remote_port)
            with self._lock:
                if dedup_key in self._seen_events:
                    continue
                self._seen_events[dedup_key] = now

            is_trusted, anomaly_type, desc = self.policy.evaluate_lineage(tree, remote_ip, remote_port)
            if is_trusted or anomaly_type not in HIGH_RISK_ANOMALIES:
                continue

            frozen = False
            if self.freeze_enabled and leaf.pgid and leaf.pgid != os.getpgid(0):
                frozen = self.freezer.freeze_process_group(
                    pid=pid,
                    pgid=leaf.pgid,
                    metadata={
                        'process_name': leaf.name,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'anomaly_type': anomaly_type,
                        'summary': tree.summary,
                    },
                )

            if self.fw_logger:
                self.fw_logger.log_event(
                    event_type='ids_alert',
                    severity='critical',
                    details=f"LineageGuard [{anomaly_type}] PID {pid} ({leaf.name}) -> {remote_ip}:{remote_port}: {desc}",
                    extra={'signature_hash': tree.signature_hash, 'frozen': frozen},
                )

            alert = LineageAlert(
                pid=pid,
                pgid=leaf.pgid,
                process_name=leaf.name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                anomaly_type=anomaly_type,
                description=desc,
                tree=tree,
                frozen=frozen,
            )
            alerts.append(alert)

            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.debug(f"Lineage alert callback error: {e}")

        return alerts
