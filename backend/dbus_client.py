"""
Vitorius Firewall - Native firewalld D-Bus Client
Provides low-latency read-only queries against org.fedoraproject.FirewallD1
via Gio.DBusProxy, returning None on unavailability so FirewallCore falls back to CLI.
"""

import logging
import time
from typing import Optional

logger = logging.getLogger('vitorius.dbus')

try:
    from gi.repository import Gio, GLib
    HAS_GIO = True
except Exception:
    HAS_GIO = False


FW_BUS_NAME = 'org.fedoraproject.FirewallD1'
FW_OBJ_PATH = '/org/fedoraproject/FirewallD1'
FW_IFACE = 'org.fedoraproject.FirewallD1'
FW_ZONE_IFACE = 'org.fedoraproject.FirewallD1.zone'


class FirewallDbusClient:
    """Thin wrapper over firewalld's system D-Bus interface for fast read queries."""

    def __init__(self):
        self._main_proxy = None
        self._zone_proxy = None
        self._last_init_attempt = 0.0

    def _ensure_proxies(self) -> bool:
        if not HAS_GIO:
            return False
        if self._main_proxy is not None and self._zone_proxy is not None:
            return True
        now = time.time()
        if (now - self._last_init_attempt) < 30.0:
            return False
        self._last_init_attempt = now
        try:
            self._main_proxy = Gio.DBusProxy.new_for_bus_sync(
                Gio.BusType.SYSTEM,
                Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES | Gio.DBusProxyFlags.DO_NOT_CONNECT_SIGNALS,
                None,
                FW_BUS_NAME,
                FW_OBJ_PATH,
                FW_IFACE,
                None,
            )
            self._zone_proxy = Gio.DBusProxy.new_for_bus_sync(
                Gio.BusType.SYSTEM,
                Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES | Gio.DBusProxyFlags.DO_NOT_CONNECT_SIGNALS,
                None,
                FW_BUS_NAME,
                FW_OBJ_PATH,
                FW_ZONE_IFACE,
                None,
            )
            return True
        except Exception as e:
            logger.debug(f"firewalld D-Bus proxy unavailable, falling back to CLI: {e}")
            self._main_proxy = None
            self._zone_proxy = None
            return False

    def _call(self, proxy, method: str, params=None):
        try:
            res = proxy.call_sync(method, params, Gio.DBusCallFlags.NONE, 1500, None)
            return res.unpack()
        except Exception as e:
            logger.debug(f"D-Bus call {method} failed: {e}")
            return None

    def get_default_zone(self) -> Optional[str]:
        if not self._ensure_proxies():
            return None
        res = self._call(self._main_proxy, 'getDefaultZone')
        return str(res[0]) if res else None

    def query_panic(self) -> Optional[bool]:
        if not self._ensure_proxies():
            return None
        res = self._call(self._main_proxy, 'queryPanicMode')
        return bool(res[0]) if res is not None else None

    def get_zones(self) -> Optional[list[str]]:
        if not self._ensure_proxies():
            return None
        res = self._call(self._zone_proxy, 'getZones')
        return list(res[0]) if res else None

    def get_active_zones(self) -> Optional[dict]:
        if not self._ensure_proxies():
            return None
        res = self._call(self._zone_proxy, 'getActiveZones')
        if not res:
            return None
        raw = res[0]
        return {
            str(zone): {
                'interfaces': list(info.get('interfaces', [])),
                'sources': list(info.get('sources', [])),
            }
            for zone, info in raw.items()
        }

    def get_zone_settings(self, zone: str) -> Optional[dict]:
        if not self._ensure_proxies():
            return None
        res = self._call(self._zone_proxy, 'getZoneSettings2', GLib.Variant('(s)', (zone,)))
        if not res:
            return None
        raw = res[0]
        ports = [{'port': str(p[0]), 'protocol': str(p[1])} for p in raw.get('ports', [])]
        fwd_ports = [
            f"port={fp[0]}:proto={fp[1]}:toport={fp[2]}:toaddr={fp[3]}"
            for fp in raw.get('forward_ports', raw.get('forward-ports', []))
        ]
        return {
            'zone': zone,
            'target': str(raw.get('target', 'default')),
            'interfaces': list(raw.get('interfaces', [])),
            'sources': list(raw.get('sources', [])),
            'services': list(raw.get('services', [])),
            'ports': ports,
            'protocols': list(raw.get('protocols', [])),
            'masquerade': bool(raw.get('masquerade', False)),
            'forward_ports': fwd_ports,
            'source_ports': [f"{sp[0]}/{sp[1]}" for sp in raw.get('source_ports', raw.get('source-ports', []))],
            'icmp_blocks': list(raw.get('icmp_blocks', raw.get('icmp-blocks', []))),
            'rich_rules': list(raw.get('rules_str', [])),
        }
