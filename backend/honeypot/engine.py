"""
Vitorius Firewall - Deception Engine
Orchestrates background decoy listeners, honey-files, collision arbiter,
and real-time active defense in an asynchronous event loop.
"""

import asyncio
import threading
import logging
from typing import Optional, Callable
from pathlib import Path

from backend.honeypot.honeyfiles import HoneyFileManager
from backend.honeypot.telemetry import HoneypotTelemetry
from backend.honeypot.quarantine import QuarantineEngine
from backend.honeypot.arbiter import HoneypotArbiter
from backend.honeypot.decoys.ssh import SshDecoy
from backend.honeypot.decoys.http import HttpDecoy
from backend.honeypot.decoys.smb import SmbDecoy
from backend.honeypot.decoys.telnet import TelnetDecoy
from backend.honeypot.decoys.database import MySqlDecoy, RedisDecoy
from backend.honeypot.decoys.tarpit import TarpitDecoy
from backend.honeypot.morph import OSMorpher
from backend.honeypot.liquid import LiquidProtocolDecoy

logger = logging.getLogger('vitorius.honeypot.engine')


class DeceptionEngine:
    """Master controller for honeypots, canary vaults, and containment."""

    def __init__(
        self,
        firewall_core,
        fw_logger,
        scanner=None,
        monitor=None,
        notify_callback: Optional[Callable[[str, bool], None]] = None,
        profile_mgr=None,
    ):
        self.core = firewall_core
        self.fw_logger = fw_logger
        self.scanner = scanner
        self.monitor = monitor
        self.notify = notify_callback
        self.profile_mgr = profile_mgr

        morph_mode = profile_mgr.get_setting('honeypot_morph_mode', 'polymorphic') if profile_mgr else 'polymorphic'
        self.morpher = OSMorpher(mode=morph_mode)
        self.deflator_enabled = profile_mgr.get_setting('honeypot_deflator_enabled', True) if profile_mgr else True
        self.honeyfiles = HoneyFileManager()
        self.telemetry = HoneypotTelemetry()
        ban_threshold = profile_mgr.get_setting('honeypot_ban_threshold', 75) if profile_mgr else 75
        auto_ban = profile_mgr.get_setting('honeypot_auto_ban', True) if profile_mgr else True
        self.quarantine = QuarantineEngine(
            firewall_core=self.core,
            fw_logger=self.fw_logger,
            telemetry=self.telemetry,
            notify_callback=self.notify,
            ban_threshold=ban_threshold,
            auto_ban_enabled=auto_ban,
            async_ban=True,
        )
        self.arbiter = HoneypotArbiter(self.core, self.scanner, self.monitor)

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._enabled = False

        # Initialize available static & liquid dynamic decoys
        self.decoys: dict[str, any] = {
            'ssh': SshDecoy(self.quarantine, internal_port=12022, external_port=22),
            'http': HttpDecoy(self.quarantine, self.honeyfiles, internal_port=12080, external_port=80),
            'smb': SmbDecoy(self.quarantine, self.honeyfiles, internal_port=12445, external_port=445),
            'telnet': TelnetDecoy(self.quarantine, internal_port=12023, external_port=23),
            'mysql': MySqlDecoy(self.quarantine, internal_port=12306, external_port=3306),
            'redis': RedisDecoy(self.quarantine, internal_port=12379, external_port=6379),
            'tarpit': TarpitDecoy(self.quarantine, internal_port=12000, external_port=8888),
            'ftp': LiquidProtocolDecoy('Liquid-FTP', 'ftp', internal_port=12021, external_port=21, quarantine_engine=self.quarantine, morpher=self.morpher),
            'smtp': LiquidProtocolDecoy('Liquid-SMTP', 'smtp', internal_port=12025, external_port=25, quarantine_engine=self.quarantine, morpher=self.morpher),
            'vnc': LiquidProtocolDecoy('Liquid-VNC', 'vnc', internal_port=12590, external_port=5900, quarantine_engine=self.quarantine, morpher=self.morpher),
            'rdp': LiquidProtocolDecoy('Liquid-RDP', 'rdp', internal_port=12389, external_port=3389, quarantine_engine=self.quarantine, morpher=self.morpher),
        }

        saved_decoys = profile_mgr.get_setting('honeypot_decoys', ['ssh', 'http', 'telnet', 'ftp']) if profile_mgr else ['ssh', 'http', 'telnet', 'ftp']
        self.enabled_decoy_keys: set[str] = set(k for k in saved_decoys if k in self.decoys) or {'ssh', 'http', 'telnet'}
        self.decoys['http'].deflator_enabled = self.deflator_enabled

    def start(self, apply_kernel_redirection: bool = False, zone: Optional[str] = None):
        """Start async event loop in a dedicated background worker thread."""
        if self._running:
            return

        self._running = True
        self._enabled = True
        self._thread = threading.Thread(target=self._run_event_loop, daemon=True, name="deception-engine")
        self._thread.start()

        # Apply kernel port forwarding rules if requested
        if apply_kernel_redirection and self.core.is_running():
            target_zone = zone or self.core.get_default_zone()
            decoy_configs = [
                {'external_port': d.external_port, 'internal_port': d.internal_port, 'proto': 'tcp'}
                for k, d in self.decoys.items() if k in self.enabled_decoy_keys
            ]
            threading.Thread(
                target=lambda: self.arbiter.activate_redirections(decoy_configs, target_zone),
                daemon=True,
                name="arbiter-activate"
            ).start()

        logger.info("Deception Engine started successfully.")

    def stop(self, teardown_kernel_redirection: bool = False, zone: Optional[str] = None):
        """Stop all decoy servers and teardown kernel forwardings."""
        if not self._running:
            return

        self._running = False
        self._enabled = False

        if self._loop and self._loop.is_running():
            try:
                future = asyncio.run_coroutine_threadsafe(self._stop_all_decoys(), self._loop)
                future.result(timeout=1.5)
            except Exception:
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)

        if teardown_kernel_redirection and self.core.is_running():
            target_zone = zone or self.core.get_default_zone()
            decoy_configs = [
                {'external_port': d.external_port, 'internal_port': d.internal_port, 'proto': 'tcp'}
                for k, d in self.decoys.items()
            ]
            threading.Thread(
                target=lambda: self.arbiter.deactivate_redirections(decoy_configs, target_zone),
                daemon=True,
                name="arbiter-deactivate"
            ).start()

        logger.info("Deception Engine stopped.")

    def _run_event_loop(self):
        """Worker thread entry point."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_enabled_decoys())
            self._loop.run_forever()
        except Exception:
            pass
        finally:
            try:
                self._loop.run_until_complete(self._stop_all_decoys())
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.close()
            except Exception:
                pass

    async def _start_enabled_decoys(self):
        for key in list(self.enabled_decoy_keys):
            decoy = self.decoys.get(key)
            if decoy:
                await decoy.start()

    async def _stop_all_decoys(self):
        for decoy in self.decoys.values():
            await decoy.stop()

    def set_decoy_enabled(self, key: str, enabled: bool):
        """Dynamically toggle an individual decoy."""
        if key not in self.decoys:
            return

        decoy = self.decoys[key]
        if enabled:
            self.enabled_decoy_keys.add(key)
            if self._running and self._loop and not decoy.is_running:
                asyncio.run_coroutine_threadsafe(decoy.start(), self._loop)
        else:
            self.enabled_decoy_keys.discard(key)
            if self._running and self._loop and decoy.is_running:
                asyncio.run_coroutine_threadsafe(decoy.stop(), self._loop)

        if self.profile_mgr:
            self.profile_mgr.update_settings({'honeypot_decoys': sorted(self.enabled_decoy_keys)})

    def is_decoy_enabled(self, key: str) -> bool:
        return key in self.enabled_decoy_keys

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> dict:
        """Returns consolidated deception system state."""
        metrics = self.telemetry.get_metrics_summary()
        staged = self.honeyfiles.list_files()
        active_decoys = [k for k, d in self.decoys.items() if d.is_running]

        return {
            'running': self._running,
            'enabled': self._enabled,
            'active_decoys': active_decoys,
            'total_decoys': len(self.decoys),
            'morph_mode': self.morpher.mode,
            'deflator_enabled': self.deflator_enabled,
            'staged_files_count': len(staged),
            'banned_hosts_count': len(self.quarantine.banned_ips),
            'banned_hosts': self.quarantine.get_banned_hosts(),
            'metrics': metrics,
            'staged_files': staged,
        }
