"""
Vitorius Firewall - Honeypot Collision Arbiter & Port Redirection
Validates port safety against legitimate system daemons, preventing collisions,
and orchestrates kernel-level packet redirection via firewalld / nftables.
"""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger('vitorius.honeypot.arbiter')


class HoneypotArbiter:
    """Arbitrates port allocation and manages firewalld kernel forwarding rules."""

    def __init__(self, firewall_core, scanner, monitor):
        self.core = firewall_core
        self.scanner = scanner
        self.monitor = monitor

    def is_port_in_use_by_system(self, port: int, proto: str = 'tcp') -> tuple[bool, str]:
        """
        Verify that NO legitimate local daemon or user app is listening on target port.
        Returns (is_in_use, service_name).
        """
        # 1. Check ServiceAppScanner cached inventory
        if self.scanner:
            for item in self.scanner.get_cached_items():
                if item.is_running:
                    for p_str, p_proto in item.ports:
                        if p_proto.lower() == proto.lower() and p_str == str(port):
                            return True, item.name

        # 2. Check /proc/net and active connections from NetworkMonitor
        if self.monitor:
            for conn in self.monitor.get_cached_connections():
                if conn.state == 'LISTEN' and conn.local_port == port:
                    return True, conn.program or "Listening Process"

        # 3. Direct socket audit using 'ss -Htlun'
        try:
            res = subprocess.run(
                ['ss', '-Htlun', f'sport = :{port}'],
                capture_output=True, text=True, timeout=1.0
            )
            out = res.stdout.strip()
            # If a process is actively listening on this external port, report clash
            if out:
                return True, "Active System Listener"
        except Exception:
            pass

        return False, ""

    def build_redirection_commands(self, active_decoys: list[dict], zone: str) -> list[str]:
        """Build batched firewall-cmd commands to redirect external ports to internal decoy ports."""
        commands = []
        for decoy in active_decoys:
            ext_port = decoy['external_port']
            int_port = decoy['internal_port']
            proto = decoy.get('proto', 'tcp')

            # Ensure collision check passes
            in_use, svc = self.is_port_in_use_by_system(ext_port, proto)
            if in_use:
                logger.warning(f"Arbiter: Skipping port {ext_port} redirect — system service '{svc}' is listening!")
                continue

            # Open external port
            commands.append(f'firewall-cmd --zone="{zone}" --add-port="{ext_port}/{proto}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-port="{ext_port}/{proto}" 2>/dev/null || true')

            # Forward external port to unprivileged internal listener
            fwd = f'port={ext_port}:proto={proto}:toport={int_port}'
            commands.append(f'firewall-cmd --zone="{zone}" --add-forward-port="{fwd}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --add-forward-port="{fwd}" 2>/dev/null || true')

        return commands

    def build_teardown_commands(self, active_decoys: list[dict], zone: str) -> list[str]:
        """Build batched firewall-cmd commands to remove port redirections and close decoy ports."""
        commands = []
        for decoy in active_decoys:
            ext_port = decoy['external_port']
            int_port = decoy['internal_port']
            proto = decoy.get('proto', 'tcp')
            fwd = f'port={ext_port}:proto={proto}:toport={int_port}'

            commands.append(f'firewall-cmd --zone="{zone}" --remove-forward-port="{fwd}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --remove-forward-port="{fwd}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --zone="{zone}" --remove-port="{ext_port}/{proto}" 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone="{zone}" --remove-port="{ext_port}/{proto}" 2>/dev/null || true')

        return commands

    def activate_redirections(self, active_decoys: list[dict], zone: str) -> tuple[bool, str]:
        commands = self.build_redirection_commands(active_decoys, zone)
        if not commands:
            return True, "No active redirections required"
        commands.append('firewall-cmd --reload 2>/dev/null || true')
        return self.core.execute_batch(commands)

    def deactivate_redirections(self, active_decoys: list[dict], zone: str) -> tuple[bool, str]:
        commands = self.build_teardown_commands(active_decoys, zone)
        if not commands:
            return True, "No redirections to tear down"
        commands.append('firewall-cmd --reload 2>/dev/null || true')
        return self.core.execute_batch(commands)
