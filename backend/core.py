"""
Vitorius Firewall - Core Backend
Interfaces with firewalld via firewall-cmd and nftables via nft.
Provides all firewall operations: zones, ports, services, rich rules, IP blocking.
"""

import subprocess
import json
import os
import re
import copy
import shlex
import ipaddress
import logging
import time
import getpass
import threading
from typing import Optional
import pwd

from backend.dbus_client import FirewallDbusClient
from backend.privileged_helper import execute_operations

logger = logging.getLogger('vitorius.core')

HELPER_BIN = '/usr/libexec/v-firewall-helper'
HELPER_POLICY = '/usr/share/polkit-1/actions/com.v.firewall.policy'



def _run(cmd: list[str], check: bool = True, timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a command, return CompletedProcess."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=check
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}\n  stderr: {e.stderr.strip()}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        raise


def _query_fw(*args) -> bool:
    """Run firewall-cmd query safely without throwing CalledProcessError."""
    try:
        res = subprocess.run(['firewall-cmd'] + list(args), capture_output=True, text=True, timeout=4)
        return res.returncode == 0
    except Exception:
        return False


def _fw(*args, permanent: bool = False) -> str:
    """Run firewall-cmd with optional --permanent flag. Returns stdout."""
    cmd = ['firewall-cmd']
    if permanent:
        cmd.append('--permanent')
    cmd.extend(args)
    return _run(cmd).stdout.strip()


def _run_pkexec_bash(script_content: str, timeout: int = 45) -> subprocess.CompletedProcess:
    """Run bash script via pkexec. Handles cancellations (126, 127) cleanly."""
    try:
        res = subprocess.run(
            ['pkexec', 'bash', '-c', script_content],
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        logger.error("Privileged command timed out")
        raise
    except FileNotFoundError:
        logger.error("pkexec binary not found")
        raise

    if res.returncode in (126, 127):
        logger.info("PolicyKit authorization was cancelled or dismissed by user")
        raise PermissionError("Authorization cancelled by user")
    elif res.returncode != 0:
        logger.error(f"Privileged command failed (code {res.returncode}): {res.stderr.strip()}")
        raise subprocess.CalledProcessError(res.returncode, ['pkexec', 'bash'], output=res.stdout, stderr=res.stderr)
    return res


def _pkexec_fw(*args, permanent: bool = False) -> str:
    """Run firewall-cmd via pkexec for single privileged operations."""
    parts = ['firewall-cmd']
    if permanent:
        parts.append('--permanent')
    parts.extend(str(a) for a in args)
    cmd_str = shlex.join(parts)
    res = _run_pkexec_bash(cmd_str)
    return res.stdout.strip()


KNOWN_APP_DEFINITIONS = {
    'ssh': {
        'services': ['ssh'],
        'ports': [('22', 'tcp')],
        'process_names': ['sshd', 'ssh'],
    },
    'samba': {
        'services': ['samba', 'samba-client'],
        'ports': [('137', 'udp'), ('138', 'udp'), ('139', 'tcp'), ('445', 'tcp')],
        'process_names': ['smbd', 'nmbd'],
    },
    'cockpit': {
        'services': ['cockpit'],
        'ports': [('9090', 'tcp')],
        'process_names': ['cockpit-ws', 'cockpit-tls'],
    },
    'syncthing': {
        'services': ['syncthing', 'syncthing-gui'],
        'ports': [('22000', 'tcp'), ('22000', 'udp'), ('21027', 'udp')],
        'process_names': ['syncthing'],
    },
    'cups': {
        'services': ['cups', 'ipp', 'ipp-client'],
        'ports': [('631', 'tcp'), ('631', 'udp')],
        'process_names': ['cupsd'],
    },
    'http': {
        'services': ['http'],
        'ports': [('80', 'tcp')],
        'process_names': ['nginx', 'httpd', 'apache2', 'caddy'],
    },
    'https': {
        'services': ['https'],
        'ports': [('443', 'tcp')],
        'process_names': ['nginx', 'httpd', 'apache2', 'caddy'],
    },
    'mysql': {
        'services': ['mysql'],
        'ports': [('3306', 'tcp')],
        'process_names': ['mariadbd', 'mysqld'],
    },
    'postgresql': {
        'services': ['postgresql'],
        'ports': [('5432', 'tcp')],
        'process_names': ['postgres'],
    },
    'libvirt': {
        'services': ['libvirt', 'libvirt-tls'],
        'ports': [('16509', 'tcp'), ('16514', 'tcp')],
        'process_names': ['libvirtd', 'virtqemud'],
    },
    'wireguard': {
        'services': ['wireguard'],
        'ports': [('51820', 'udp')],
        'process_names': ['wg-crypt'],
    },
    'openvpn': {
        'services': ['openvpn'],
        'ports': [('1194', 'udp')],
        'process_names': ['openvpn'],
    },
    'plex': {
        'services': ['plex'],
        'ports': [('32400', 'tcp')],
        'process_names': ['Plex Media Server', 'plexmediaserver'],
    },
    'jellyfin': {
        'services': ['jellyfin'],
        'ports': [('8096', 'tcp')],
        'process_names': ['jellyfin'],
    },
    'transmission': {
        'services': ['transmission-client'],
        'ports': [('51413', 'tcp'), ('51413', 'udp'), ('9091', 'tcp')],
        'process_names': ['transmission-daemon', 'transmission-gtk'],
    },
    'qbittorrent': {
        'services': [],
        'ports': [('6881', 'tcp'), ('6881', 'udp'), ('8080', 'tcp')],
        'flatpak_ids': ['org.qbittorrent.qBittorrent'],
        'process_names': ['qbittorrent'],
    },
    'steam': {
        'services': [],
        'ports': [('27015-27030', 'udp'), ('27015-27030', 'tcp'), ('3478', 'udp'), ('4380', 'udp'), ('27036', 'udp'), ('27036', 'tcp')],
        'flatpak_ids': ['com.valvesoftware.Steam'],
        'process_names': ['steam', 'steamwebhelper', 'steam.sh', 'gameoverlayui'],
    },
    'discord': {
        'services': [],
        'ports': [('50001', 'udp')],
        'flatpak_ids': ['com.discordapp.Discord'],
        'process_names': ['discord', 'Discord'],
    },
    'firefox': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['org.mozilla.firefox'],
        'process_names': ['firefox', 'firefox-bin'],
    },
    'chrome': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.google.Chrome'],
        'process_names': ['chrome', 'google-chrome', 'google-chrome-stable'],
    },
    'brave': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.brave.Browser'],
        'process_names': ['brave', 'brave-browser'],
    },
    'spotify': {
        'services': [],
        'ports': [],
        'flatpak_ids': ['com.spotify.Client'],
        'process_names': ['spotify'],
    },
}


def get_installed_flatpaks() -> dict[str, str]:
    """Returns {app_name_lower: app_id} for installed flatpaks."""
    result = {}
    try:
        proc = subprocess.run(
            ['flatpak', 'list', '--app', '--columns=name,application'],
            capture_output=True, text=True, timeout=2.0
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    name, app_id = parts[0].strip(), parts[1].strip()
                    result[name.lower()] = app_id
                    result[app_id.lower()] = app_id
    except Exception:
        pass
    return result


def _match_app_definition(app_name: str) -> Optional[dict]:
    name_clean = app_name.lower().strip()
    for key, defn in KNOWN_APP_DEFINITIONS.items():
        if key == name_clean or key in name_clean or name_clean in key:
            return defn
        for proc in defn.get('process_names', []):
            if proc.lower() in name_clean or name_clean in proc.lower():
                return defn
    return None


class FirewallCore:
    """Core firewall interface wrapping firewalld and nftables with caching."""

    def __init__(self, use_dbus: bool = True):
        self._use_pkexec = True  # Use pkexec for write operations
        self._running = False
        self._lock = threading.RLock()
        self._cache = {}
        self._cache_time = {}
        self._dbus = FirewallDbusClient() if use_dbus else None
        # Track UID based rich rules
        self._app_rules: set[tuple[str, int]] = set()
        self._uid_cache: dict[str, int] = {}
        self._check_firewalld()

    def execute_structured(self, operations: list[dict]) -> tuple[bool, str]:
        """Execute validated JSON operations via Polkit helper when installed, or in-process/fallback."""
        if not operations:
            return True, "No operations"
        try:
            if not self._use_pkexec:
                ok, msg = execute_operations({'operations': operations})
                if ok:
                    self.invalidate_cache()
                return ok, msg

            if os.path.isfile(HELPER_BIN) and os.path.isfile(HELPER_POLICY):
                res = subprocess.run(
                    ['pkexec', HELPER_BIN],
                    input=json.dumps({'operations': operations}),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode in (126, 127):
                    return False, "Authorization was cancelled by user"
                if res.returncode == 0:
                    self.invalidate_cache()
                    return True, "Configuration successfully applied"
                return False, (res.stderr or res.stdout or "Helper failed").strip()
        except Exception as e:
            logger.debug(f"Structured helper path failed: {e}")
        return False, "Structured helper unavailable"

    def invalidate_cache(self):
        """Invalidate all cached firewall responses."""
        with self._lock:
            self._cache.clear()
            self._cache_time.clear()

    def empty_caches(self):
        """Flushes internal memory caches, kernel routing caches, and system resolver caches."""
        self.invalidate_cache()
        for cmd in ['resolvectl flush-caches', 'ip route flush cache']:
            try:
                subprocess.run(['bash', '-c', f'{cmd} 2>/dev/null || true'], capture_output=True, timeout=2.0)
            except Exception:
                pass

    def execute_batch(self, commands: list[str]) -> tuple[bool, str]:
        """Execute a batch of firewall-cmd commands in ONE single privileged transaction."""
        if not commands:
            return True, "No commands to execute"

        # Ensure firewalld daemon is started first
        full_commands = []
        if not any('systemctl start firewalld' in c for c in commands):
            full_commands.append('systemctl start firewalld 2>/dev/null || true')
        full_commands.extend(commands)
        script = "\n".join(full_commands)
        try:
            if self._use_pkexec:
                _run_pkexec_bash(script, timeout=60)
            else:
                subprocess.run(['bash', '-c', script], capture_output=True, text=True, check=True, timeout=60)
            self.invalidate_cache()
            return True, "Configuration successfully applied"
        except PermissionError:
            logger.info("Batch firewall operation cancelled by user")
            return False, "Authorization was cancelled by user"
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.output or str(e)).strip()
            logger.error(f"Batch execution failed: {err}")
            return False, f"Failed: {err}"
        except Exception as e:
            logger.error(f"Batch execution failed: {e}")
            return False, f"Failed to apply configuration: {e}"

    # ── Status ──────────────────────────────────────────────────────

    def _uid_for_user(self, username: str) -> Optional[int]:
        """Return the numeric UID for *username* (cached). Returns None if not found."""
        with self._lock:
            if username in self._uid_cache:
                return self._uid_cache[username]
        try:
            uid = pwd.getpwnam(username).pw_uid
            with self._lock:
                self._uid_cache[username] = uid
            return uid
        except KeyError:
            logger.debug(f"UID lookup failed for user '{username}'")
            return None

    def block_app(self, app_name: str) -> bool:
        """Block traffic for a dedicated service user UID or fall back to application-layer blocking."""
        uid = None
        flatpak_id = self._resolve_flatpak_id(app_name)
        if flatpak_id:
            uid = self._uid_for_user(flatpak_id)
        if uid is None:
            uid = self._uid_for_user(app_name.lower().strip())
        # Never block the interactive user's own UID globally
        if uid is None or uid == os.getuid():
            ok, _ = self.block_application(app_name)
            return ok
        cmds = [
            f'iptables -I OUTPUT 1 -m owner --uid-owner {int(uid)} -j REJECT 2>/dev/null || true',
            f'ip6tables -I OUTPUT 1 -m owner --uid-owner {int(uid)} -j REJECT 2>/dev/null || true',
            f'ss -K uid {int(uid)} 2>/dev/null || true',
        ]
        ok, _ = self.execute_batch(cmds)
        if ok:
            with self._lock:
                self._app_rules.add((app_name, uid))
            logger.info(f"Blocked app '{app_name}' (uid={uid}) via owner match.")
        return ok

    def unblock_app(self, app_name: str) -> bool:
        """Remove the UID-based or application-level block for *app_name*."""
        uid = None
        with self._lock:
            for name, stored_uid in list(self._app_rules):
                if name == app_name:
                    uid = stored_uid
                    break
        if uid is None:
            ok, _ = self.unblock_application(app_name)
            return ok
        cmds = [
            f'iptables -D OUTPUT -m owner --uid-owner {int(uid)} -j REJECT 2>/dev/null || true',
            f'ip6tables -D OUTPUT -m owner --uid-owner {int(uid)} -j REJECT 2>/dev/null || true',
        ]
        ok, _ = self.execute_batch(cmds)
        if ok:
            with self._lock:
                self._app_rules.discard((app_name, uid))
            logger.info(f"Unblocked app '{app_name}' (uid={uid}).")
        return ok

    def _resolve_flatpak_id(self, app_name: str) -> Optional[str]:
        """Map a user‑visible app name to a flatpak ID using get_installed_flatpaks()."""
        flatpaks = get_installed_flatpaks()
        key = app_name.lower().strip()
        return flatpaks.get(key)

    def _check_firewalld(self) -> None:
        """Check if firewalld daemon is active and update internal state.
        For unit tests we simply query the state; any failure marks it as not running.
        """
        try:
            res = subprocess.run(['firewall-cmd', '--state'], capture_output=True, text=True, timeout=1.5)
            self._running = (res.returncode == 0)
        except Exception:
            self._running = False
        with self._lock:
            self._cache['is_running'] = self._running
            self._cache_time['is_running'] = time.time()

    def is_running(self) -> bool:
        now = time.time()
        with self._lock:
            if 'is_running' in self._cache and (now - self._cache_time.get('is_running', 0)) < 10.0:
                return self._cache['is_running']
        self._check_firewalld()
        with self._lock:
            self._cache['is_running'] = self._running
            self._cache_time['is_running'] = now
            return self._running

    def get_state(self) -> str:
        """Return 'running' or 'not running'."""
        if not self.is_running():
            return 'not running'
        try:
            return _fw('--state')
        except Exception:
            return 'not running'

    # ── Zones ───────────────────────────────────────────────────────

    def get_zones(self) -> list[str]:
        """Get all available zones."""
        now = time.time()
        with self._lock:
            if 'zones' in self._cache and (now - self._cache_time.get('zones', 0)) < 30.0:
                return list(self._cache['zones'])
        if not self.is_running():
            return ['public', 'home', 'work', 'drop', 'trusted']
        try:
            zones = self._dbus.get_zones() if self._dbus else None
            if zones is None:
                zones = _fw('--get-zones').split()
            if not zones:
                zones = ['public', 'home', 'work', 'drop', 'trusted', 'internal', 'external', 'dmz', 'block']
            with self._lock:
                self._cache['zones'] = list(zones)
                self._cache_time['zones'] = now
            return zones
        except Exception:
            return ['public', 'home', 'work', 'drop', 'trusted']

    def get_active_zones(self) -> dict:
        """Get active zones and their interfaces."""
        now = time.time()
        with self._lock:
            if 'active_zones' in self._cache and (now - self._cache_time.get('active_zones', 0)) < 15.0:
                return copy.deepcopy(self._cache['active_zones'])
        if not self.is_running():
            return {}

        dbus_active = self._dbus.get_active_zones() if self._dbus else None
        if dbus_active is not None:
            with self._lock:
                self._cache['active_zones'] = copy.deepcopy(dbus_active)
                self._cache_time['active_zones'] = now
            return dbus_active

        result = {}
        try:
            output = _fw('--get-active-zones')
            current_zone = None
            for line in output.splitlines():
                if not line.strip():
                    continue
                if not line.startswith(' ') and not line.startswith('\t'):
                    tokens = line.strip().split()
                    if tokens:
                        current_zone = tokens[0]
                        result[current_zone] = {'interfaces': [], 'sources': []}
                elif current_zone:
                    sline = line.strip()
                    if sline.startswith('interfaces:'):
                        result[current_zone]['interfaces'] = sline.split(':', 1)[1].strip().split()
                    elif sline.startswith('sources:'):
                        result[current_zone]['sources'] = sline.split(':', 1)[1].strip().split()
        except Exception as e:
            logger.debug(f"Error getting active zones: {e}")

        with self._lock:
            self._cache['active_zones'] = copy.deepcopy(result)
            self._cache_time['active_zones'] = now
        return result

    def get_default_zone(self) -> str:
        now = time.time()
        with self._lock:
            if 'default_zone' in self._cache and (now - self._cache_time.get('default_zone', 0)) < 30.0:
                return self._cache['default_zone']
        if not self.is_running():
            return 'public'
        try:
            dz = (self._dbus.get_default_zone() if self._dbus else None) or _fw('--get-default-zone') or 'public'
        except Exception:
            dz = 'public'
        with self._lock:
            self._cache['default_zone'] = dz
            self._cache_time['default_zone'] = now
        return dz

    def set_default_zone(self, zone: str) -> bool:
        if not self.is_running():
            return False
        try:
            if self._use_pkexec:
                _pkexec_fw('--set-default-zone=' + zone)
            else:
                _fw('--set-default-zone=' + zone)
            self.invalidate_cache()
            return True
        except Exception as e:
            logger.error(f"Failed to set default zone: {e}")
            return False

    def get_zone_settings(self, zone: str) -> dict:
        """Get comprehensive settings for a zone in 1 single fast call."""
        now = time.time()
        cache_key = f'zone_{zone}'
        with self._lock:
            if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < 15.0:
                return copy.deepcopy(self._cache[cache_key])

        if self.is_running() and self._dbus:
            dbus_settings = self._dbus.get_zone_settings(zone)
            if dbus_settings is not None:
                active = self.get_active_zones()
                if zone in active:
                    if not dbus_settings['interfaces']:
                        dbus_settings['interfaces'] = list(active[zone].get('interfaces', []))
                    if not dbus_settings['sources']:
                        dbus_settings['sources'] = list(active[zone].get('sources', []))
                with self._lock:
                    self._cache[cache_key] = copy.deepcopy(dbus_settings)
                    self._cache_time[cache_key] = now
                return dbus_settings

        settings = {
            'zone': zone,
            'target': 'default',
            'interfaces': [],
            'sources': [],
            'services': [],
            'ports': [],
            'protocols': [],
            'masquerade': False,
            'forward_ports': [],
            'source_ports': [],
            'icmp_blocks': [],
            'rich_rules': [],
        }

        if not self.is_running():
            with self._lock:
                self._cache[cache_key] = copy.deepcopy(settings)
                self._cache_time[cache_key] = now
            return settings

        try:
            out = _fw('--zone=' + zone, '--list-all')
            section = None
            for line in out.splitlines():
                sline = line.strip()
                if not sline:
                    continue
                if sline.startswith('target:'):
                    section = None
                    settings['target'] = sline.split(':', 1)[1].strip()
                elif sline.startswith('interfaces:'):
                    section = None
                    settings['interfaces'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('sources:'):
                    section = None
                    settings['sources'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('services:'):
                    section = None
                    settings['services'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('ports:'):
                    section = None
                    for p in sline.split(':', 1)[1].strip().split():
                        parts = p.split('/')
                        if len(parts) == 2:
                            settings['ports'].append({'port': parts[0], 'protocol': parts[1]})
                elif sline.startswith('protocols:'):
                    section = None
                    settings['protocols'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('masquerade:'):
                    section = None
                    settings['masquerade'] = sline.split(':', 1)[1].strip().lower() == 'yes'
                elif sline.startswith('forward-ports:'):
                    section = 'forward_ports'
                    val = sline.split(':', 1)[1].strip()
                    if val:
                        settings['forward_ports'].append(val)
                elif sline.startswith('source-ports:'):
                    section = 'source_ports'
                    for p in sline.split(':', 1)[1].strip().split():
                        settings['source_ports'].append(p)
                elif sline.startswith('icmp-blocks:'):
                    section = None
                    settings['icmp_blocks'] = sline.split(':', 1)[1].strip().split()
                elif sline.startswith('rich rules:'):
                    section = 'rich_rules'
                elif sline.startswith('rule '):
                    settings['rich_rules'].append(sline)
                elif section == 'forward_ports' and line.startswith(('\t', '  ')):
                    settings['forward_ports'].append(sline)
        except Exception as e:
            logger.debug(f"Error parsing zone {zone} via list-all: {e}")

        # Add active interfaces
        active = self.get_active_zones()
        if zone in active:
            if not settings['interfaces']:
                settings['interfaces'] = list(active[zone].get('interfaces', []))
            if not settings['sources']:
                settings['sources'] = list(active[zone].get('sources', []))

        with self._lock:
            self._cache[cache_key] = copy.deepcopy(settings)
            self._cache_time[cache_key] = now
        return settings


    # ── Services ────────────────────────────────────────────────────

    def get_available_services(self) -> list[str]:
        """Get all available service definitions."""
        try:
            return sorted(_fw('--get-services').split())
        except Exception:
            return []

    def _can_use_helper(self) -> bool:
        return self._use_pkexec and os.path.isfile(HELPER_BIN) and os.path.isfile(HELPER_POLICY)

    def _exec_fw_action(self, args: list[str], permanent: bool = True, ignore_runtime_err: bool = False) -> bool:
        """Execute a firewall-cmd action cleanly across runtime and optional permanent scope."""
        q_args = " ".join(shlex.quote(str(a)) for a in args)
        if permanent:
            sep = "2>/dev/null || true;" if ignore_runtime_err else "&&"
            cmd = f"firewall-cmd {q_args} {sep} firewall-cmd --permanent {q_args}"
            if self._use_pkexec:
                _run_pkexec_bash(cmd)
            else:
                subprocess.run(['bash', '-c', cmd], check=True, capture_output=True)
        else:
            if self._use_pkexec:
                _run_pkexec_bash(f"firewall-cmd {q_args}")
            else:
                _fw(*args)
        self.invalidate_cache()
        return True

    def add_service(self, zone: str, service: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'add_service', 'zone': zone, 'service': service, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', f'--add-service={service}'], permanent=permanent)
        except PermissionError:
            logger.info(f"Add service {service} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add service {service}: {e}")
            return False

    def remove_service(self, zone: str, service: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'remove_service', 'zone': zone, 'service': service, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action(
                [f'--zone={zone}', f'--remove-service={service}'],
                permanent=permanent, ignore_runtime_err=True
            )
        except PermissionError:
            logger.info(f"Remove service {service} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove service {service}: {e}")
            return False

    # ── Ports ───────────────────────────────────────────────────────

    def add_port(self, zone: str, port: str, protocol: str = 'tcp', permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'add_port', 'zone': zone, 'port': port, 'protocol': protocol, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', f'--add-port={port}/{protocol}'], permanent=permanent)
        except PermissionError:
            logger.info(f"Add port {port}/{protocol} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add port {port}/{protocol}: {e}")
            return False

    def remove_port(self, zone: str, port: str, protocol: str = 'tcp', permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'remove_port', 'zone': zone, 'port': port, 'protocol': protocol, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action(
                [f'--zone={zone}', f'--remove-port={port}/{protocol}'],
                permanent=permanent, ignore_runtime_err=True
            )
        except PermissionError:
            logger.info(f"Remove port {port}/{protocol} cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove port {port}/{protocol}: {e}")
            return False

    # ── Rich Rules ──────────────────────────────────────────────────

    def add_rich_rule(self, zone: str, rule: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'add_rich_rule', 'zone': zone, 'rule': rule, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', f'--add-rich-rule={rule}'], permanent=permanent)
        except PermissionError:
            logger.info("Add rich rule cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add rich rule: {e}")
            return False

    def remove_rich_rule(self, zone: str, rule: str, permanent: bool = True) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'remove_rich_rule', 'zone': zone, 'rule': rule, 'permanent': permanent}])
            return ok
        try:
            return self._exec_fw_action(
                [f'--zone={zone}', f'--remove-rich-rule={rule}'],
                permanent=permanent, ignore_runtime_err=True
            )
        except PermissionError:
            logger.info("Remove rich rule cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to remove rich rule: {e}")
            return False

    # ── IP Blocking ─────────────────────────────────────────────────

    @staticmethod
    def _parse_ip_family(ip: str) -> Optional[str]:
        """Validate an IP or CIDR string and return 'ipv4' or 'ipv6', or None if invalid."""
        try:
            obj = ipaddress.ip_address(ip)
            return 'ipv6' if obj.version == 6 else 'ipv4'
        except ValueError:
            try:
                obj = ipaddress.ip_network(ip, strict=False)
                return 'ipv6' if obj.version == 6 else 'ipv4'
            except ValueError:
                return None

    def block_ip(self, ip: str, zone: str = None) -> bool:
        """Block an IPv4/IPv6 address or CIDR (inbound and outbound) and terminate active sockets."""
        family = self._parse_ip_family(ip)
        if not family:
            logger.error(f"Invalid IP/CIDR: {ip}")
            return False

        target_zone = zone or self.get_default_zone()
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'block_ip', 'zone': target_zone, 'ip': ip}])
            return ok
        q_zone = shlex.quote(target_zone)
        q_ip = shlex.quote(ip)
        src_rule = shlex.quote(f'rule family="{family}" source address="{ip}" reject')
        dst_rule = shlex.quote(f'rule family="{family}" destination address="{ip}" reject')
        commands = [
            f'ss -K dst {q_ip} 2>/dev/null || true',
            f'firewall-cmd --zone={q_zone} --add-rich-rule={src_rule} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_zone} --add-rich-rule={src_rule} 2>/dev/null || true',
            f'firewall-cmd --zone={q_zone} --add-rich-rule={dst_rule} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_zone} --add-rich-rule={dst_rule} 2>/dev/null || true',
            f'firewall-cmd --direct --add-rule {family} filter OUTPUT 0 -d {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --permanent --direct --add-rule {family} filter OUTPUT 0 -d {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --direct --add-rule {family} filter INPUT 0 -s {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --permanent --direct --add-rule {family} filter INPUT 0 -s {q_ip} -j REJECT 2>/dev/null || true',
        ]
        ok, _ = self.execute_batch(commands)
        return ok

    def unblock_ip(self, ip: str, zone: str = None) -> bool:
        family = self._parse_ip_family(ip) or 'ipv4'
        target_zone = zone or self.get_default_zone()
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'block_ip', 'zone': target_zone, 'ip': ip}])
            return ok
        q_zone = shlex.quote(target_zone)
        q_ip = shlex.quote(ip)
        src_rule = shlex.quote(f'rule family="{family}" source address="{ip}" reject')
        dst_rule = shlex.quote(f'rule family="{family}" destination address="{ip}" reject')
        commands = [
            f'firewall-cmd --zone={q_zone} --remove-rich-rule={src_rule} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_zone} --remove-rich-rule={src_rule} 2>/dev/null || true',
            f'firewall-cmd --zone={q_zone} --remove-rich-rule={dst_rule} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_zone} --remove-rich-rule={dst_rule} 2>/dev/null || true',
            f'firewall-cmd --direct --remove-rule {family} filter OUTPUT 0 -d {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --permanent --direct --remove-rule {family} filter OUTPUT 0 -d {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --direct --remove-rule {family} filter INPUT 0 -s {q_ip} -j REJECT 2>/dev/null || true',
            f'firewall-cmd --permanent --direct --remove-rule {family} filter INPUT 0 -s {q_ip} -j REJECT 2>/dev/null || true',
        ]
        ok, _ = self.execute_batch(commands)
        return ok

    def get_blocked_ips(self, zone: str = None) -> list[str]:
        """Get list of blocked IPs from rich rules."""
        target_zone = zone or self.get_default_zone()
        settings = self.get_zone_settings(target_zone)
        blocked = set()
        pattern_src = re.compile(r'source address="([^"]+)".*(?:reject|drop)')
        pattern_dst = re.compile(r'destination address="([^"]+)".*(?:reject|drop)')
        for rule in settings.get('rich_rules', []):
            m = pattern_src.search(rule) or pattern_dst.search(rule)
            if m:
                blocked.add(m.group(1))
        return sorted(list(blocked))

    # ── Application Control ─────────────────────────────────────────

    _PROTECTED_UNITS = (
        'init.scope', 'systemd-', 'dbus', 'NetworkManager', 'polkit',
        'firewalld', 'session-', 'user@', 'graphical-session', 'wayland',
    )

    @staticmethod
    def _proc_matches_targets(pname: str, pexe: str, pcmd: str, target_names: set[str]) -> bool:
        """Match process against target binary/app names without false-positive short-name matches."""
        exe_base = os.path.basename(pexe) if pexe else ''
        for t in target_names:
            if not t:
                continue
            if pname == t or exe_base == t:
                return True
            if len(t) >= 3 and (t in pname or t in exe_base or re.search(rf'(?<![\w-]){re.escape(t)}(?![\w-])', pcmd)):
                return True
        return False

    def _discover_app_processes(self, app_name: str, defn: Optional[dict], initial_pids: Optional[list[int]] = None):
        """Discover matching processes, descendants, and active sockets for an application."""
        app_clean = app_name.lower().strip()
        target_names = {app_clean}
        if defn:
            for pn in defn.get('process_names', []):
                target_names.add(pn.lower())

        all_pids = set(initial_pids or [])
        matched_procs = []
        try:
            import psutil
            for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    pname = (p.info.get('name') or '').lower()
                    pexe = (p.info.get('exe') or '').lower()
                    pcmd = ' '.join(p.info.get('cmdline') or []).lower()
                    if self._proc_matches_targets(pname, pexe, pcmd, target_names):
                        all_pids.add(p.info['pid'])
                        matched_procs.append(p)
                except Exception:
                    pass

            for p in list(matched_procs):
                try:
                    for child in p.children(recursive=True):
                        all_pids.add(child.pid)
                        matched_procs.append(child)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Error enumerating app processes for {app_name}: {e}")
        return all_pids, matched_procs

    def _collect_cgroup_commands(self, all_pids: set[int], block: bool) -> list[str]:
        """Build iptables cgroup and systemd IPAddressDeny commands for a set of PIDs."""
        commands = []
        seen_cg_paths = set()
        seen_units = set()
        for pid in all_pids:
            try:
                cg_file = f'/proc/{pid}/cgroup'
                if not os.path.exists(cg_file):
                    continue
                with open(cg_file, 'r') as f:
                    cg_content = f.read().strip()
                for line in cg_content.splitlines():
                    parts = line.split(':')
                    if len(parts) < 3:
                        continue
                    cg_path = parts[2].strip('/')
                    if cg_path and cg_path not in seen_cg_paths:
                        seen_cg_paths.add(cg_path)
                        q_cg = shlex.quote(cg_path)
                        if block:
                            commands.append(f'iptables -I OUTPUT 1 -m cgroup --path {q_cg} -j REJECT 2>/dev/null || true')
                            commands.append(f'iptables -I INPUT 1 -m cgroup --path {q_cg} -j REJECT 2>/dev/null || true')
                        else:
                            commands.append(f'iptables -D OUTPUT -m cgroup --path {q_cg} -j REJECT 2>/dev/null || true')
                            commands.append(f'iptables -D INPUT -m cgroup --path {q_cg} -j REJECT 2>/dev/null || true')

                    unit_name = os.path.basename(cg_path)
                    if (
                        unit_name
                        and (unit_name.endswith('.scope') or unit_name.endswith('.service'))
                        and unit_name not in seen_units
                        and not any(unit_name.startswith(p) for p in self._PROTECTED_UNITS)
                    ):
                        seen_units.add(unit_name)
                        q_unit = shlex.quote(unit_name)
                        if block:
                            try:
                                subprocess.run(['systemctl', '--user', 'set-property', '--runtime', unit_name, 'IPAddressDeny=any'], capture_output=True, timeout=2.0)
                            except Exception:
                                pass
                            commands.append(f'systemctl set-property --runtime {q_unit} IPAddressDeny=any 2>/dev/null || true')
                            commands.append(f'systemctl --user set-property --runtime {q_unit} IPAddressDeny=any 2>/dev/null || true')
                        else:
                            try:
                                subprocess.run(['systemctl', '--user', 'set-property', '--runtime', unit_name, 'IPAddressAllow=any', 'IPAddressDeny='], capture_output=True, timeout=2.0)
                            except Exception:
                                pass
                            commands.append(f'systemctl set-property --runtime {q_unit} IPAddressAllow=any IPAddressDeny= 2>/dev/null || true')
                            commands.append(f'systemctl --user set-property --runtime {q_unit} IPAddressAllow=any IPAddressDeny= 2>/dev/null || true')
            except Exception as e:
                logger.debug(f"Error resolving cgroup for pid {pid}: {e}")
        return commands

    def block_application(self, app_name: str, pids: list[int] = None, remote_ips: list[str] = None, local_ports: list[int] = None) -> tuple[bool, str]:
        """Completely sever connections and block an application across all network layers."""
        zone = self.get_default_zone()
        q_zone = shlex.quote(zone)
        commands = []
        app_clean = app_name.lower().strip()
        defn = _match_app_definition(app_name)

        all_pids, matched_procs = self._discover_app_processes(app_name, defn, pids)
        active_remote_ips = set(remote_ips or [])

        for p in matched_procs:
            try:
                for conn in p.net_connections(kind='inet'):
                    if conn.raddr:
                        active_remote_ips.add(conn.raddr.ip)
                        commands.append(f'ss -K dst {shlex.quote(conn.raddr.ip)} dport = :{int(conn.raddr.port)} 2>/dev/null || true')
                    if conn.laddr:
                        commands.append(f'ss -K sport = :{int(conn.laddr.port)} 2>/dev/null || true')
            except Exception:
                pass

        for ip in active_remote_ips:
            commands.append(f'ss -K dst {shlex.quote(ip)} 2>/dev/null || true')
        if local_ports:
            for lp in local_ports:
                commands.append(f'ss -K sport = :{int(lp)} 2>/dev/null || true')

        services_to_remove = list(defn.get('services', [])) if defn else []
        ports_to_reject = list(defn.get('ports', [])) if defn else []
        flatpak_ids = list(defn.get('flatpak_ids', [])) if defn else []

        installed_flatpaks = get_installed_flatpaks()
        if app_clean in installed_flatpaks:
            fid = installed_flatpaks[app_clean]
            if fid not in flatpak_ids:
                flatpak_ids.append(fid)

        for fid in flatpak_ids:
            try:
                subprocess.run(['flatpak', 'override', '--user', '--unshare=network', fid], capture_output=True, timeout=2.0)
                subprocess.run(['flatpak', 'kill', fid], capture_output=True, timeout=2.0)
            except Exception:
                pass
            q_fid = shlex.quote(fid)
            commands.append(f'flatpak override --system --unshare=network {q_fid} 2>/dev/null || true')
            commands.append(f'flatpak kill {q_fid} 2>/dev/null || true')

        commands.extend(self._collect_cgroup_commands(all_pids, block=True))

        for svc in services_to_remove:
            q_svc = shlex.quote(svc)
            commands.append(f'firewall-cmd --zone={q_zone} --remove-service={q_svc} 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone={q_zone} --remove-service={q_svc} 2>/dev/null || true')

        for port, proto in ports_to_reject:
            q_pp = shlex.quote(f'{port}/{proto}')
            rich = shlex.quote(f'rule port port="{port}" protocol="{proto}" reject')
            commands.append(f'firewall-cmd --zone={q_zone} --add-rich-rule={rich} 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone={q_zone} --add-rich-rule={rich} 2>/dev/null || true')
            if str(port) not in ('80', '443', '53', '22', '123', '67', '68', '5353'):
                commands.append(f'firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p {shlex.quote(proto)} --dport {shlex.quote(str(port))} -j REJECT 2>/dev/null || true')
                commands.append(f'firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p {shlex.quote(proto)} --dport {shlex.quote(str(port))} -j REJECT 2>/dev/null || true')
            commands.append(f'ss -K sport = :{shlex.quote(str(port))} 2>/dev/null || true')
            commands.append(f'ss -K dport = :{shlex.quote(str(port))} 2>/dev/null || true')

        for ip in active_remote_ips:
            family = self._parse_ip_family(ip) or 'ipv4'
            rich = shlex.quote(f'rule family="{family}" destination address="{ip}" reject')
            commands.append(f'firewall-cmd --zone={q_zone} --add-rich-rule={rich} 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone={q_zone} --add-rich-rule={rich} 2>/dev/null || true')

        return self.execute_batch(commands)

    def unblock_application(self, app_name: str, pids: list[int] = None, remote_ips: list[str] = None, local_ports: list[int] = None) -> tuple[bool, str]:
        """Restore network access for a previously blocked application."""
        zone = self.get_default_zone()
        commands = []
        app_clean = app_name.lower().strip()
        defn = _match_app_definition(app_name)

        services_to_restore = list(defn.get('services', [])) if defn else []
        ports_to_unblock = list(defn.get('ports', [])) if defn else []
        flatpak_ids = list(defn.get('flatpak_ids', [])) if defn else []

        installed_flatpaks = get_installed_flatpaks()
        if app_clean in installed_flatpaks:
            fid = installed_flatpaks[app_clean]
            if fid not in flatpak_ids:
                flatpak_ids.append(fid)

        for fid in flatpak_ids:
            try:
                subprocess.run(['flatpak', 'override', '--user', '--share=network', fid], capture_output=True, timeout=2.0)
                subprocess.run(['flatpak', 'override', '--user', '--reset', fid], capture_output=True, timeout=2.0)
            except Exception:
                pass
            q_fid = shlex.quote(fid)
            commands.append(f'flatpak override --system --share=network {q_fid} 2>/dev/null || true')
            commands.append(f'flatpak override --system --reset {q_fid} 2>/dev/null || true')

        all_pids, _ = self._discover_app_processes(app_name, defn, pids)
        commands.extend(self._collect_cgroup_commands(all_pids, block=False))

        valid_zones = set(self.get_zones())
        zones_to_clean = [zone]
        for extra in ('FedoraWorkstation',):
            if extra in valid_zones:
                zones_to_clean.append(extra)
        zones_to_clean = list(dict.fromkeys(zones_to_clean))

        for z in zones_to_clean:
            q_z = shlex.quote(z)
            for svc in services_to_restore:
                q_svc = shlex.quote(svc)
                commands.append(f'firewall-cmd --zone={q_z} --add-service={q_svc} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --add-service={q_svc} 2>/dev/null || true')

            for port, proto in ports_to_unblock:
                rich = shlex.quote(f'rule port port="{port}" protocol="{proto}" reject')
                commands.append(f'firewall-cmd --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')

            for ip in (remote_ips or []):
                family = self._parse_ip_family(ip) or 'ipv4'
                rich = shlex.quote(f'rule family="{family}" destination address="{ip}" reject')
                commands.append(f'firewall-cmd --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')

        for port, proto in ports_to_unblock:
            q_proto = shlex.quote(proto)
            q_port = shlex.quote(str(port))
            commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p {q_proto} --dport {q_port} -j REJECT 2>/dev/null || true')
            commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p {q_proto} --dport {q_port} -j REJECT 2>/dev/null || true')

        for ip in (remote_ips or []):
            family = self._parse_ip_family(ip) or 'ipv4'
            commands.append(f'firewall-cmd --direct --remove-rule {family} filter OUTPUT 0 -d {shlex.quote(ip)} -j REJECT 2>/dev/null || true')

        commands.append('resolvectl flush-caches 2>/dev/null || true')
        commands.append('ip route flush cache 2>/dev/null || true')
        return self.execute_batch(commands)

    def block_service(self, service_name: str, zone: str = None, ports: list = None) -> tuple[bool, str]:
        """Block a network service across firewalld zones and reject its listening ports."""
        target_zone = zone or self.get_default_zone()
        q_z = shlex.quote(target_zone)
        q_svc = shlex.quote(service_name)
        commands = [
            f'firewall-cmd --zone={q_z} --remove-service={q_svc} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_z} --remove-service={q_svc} 2>/dev/null || true',
        ]
        if ports:
            for port, proto in ports:
                q_pp = shlex.quote(f'{port}/{proto}')
                rich = shlex.quote(f'rule port port="{port}" protocol="{proto}" reject')
                commands.append(f'firewall-cmd --zone={q_z} --remove-port={q_pp} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --remove-port={q_pp} 2>/dev/null || true')
                commands.append(f'firewall-cmd --zone={q_z} --add-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --add-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'ss -K sport = :{shlex.quote(str(port))} 2>/dev/null || true')
        return self.execute_batch(commands)

    def unblock_service(self, service_name: str, zone: str = None, ports: list = None) -> tuple[bool, str]:
        """Restore/allow a network service in the firewall zone."""
        target_zone = zone or self.get_default_zone()
        q_z = shlex.quote(target_zone)
        q_svc = shlex.quote(service_name)
        commands = [
            f'firewall-cmd --zone={q_z} --add-service={q_svc} 2>/dev/null || true',
            f'firewall-cmd --permanent --zone={q_z} --add-service={q_svc} 2>/dev/null || true',
        ]
        if ports:
            for port, proto in ports:
                q_pp = shlex.quote(f'{port}/{proto}')
                q_proto = shlex.quote(proto)
                q_port = shlex.quote(str(port))
                rich = shlex.quote(f'rule port port="{port}" protocol="{proto}" reject')
                commands.append(f'firewall-cmd --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --remove-rich-rule={rich} 2>/dev/null || true')
                commands.append(f'firewall-cmd --zone={q_z} --add-port={q_pp} 2>/dev/null || true')
                commands.append(f'firewall-cmd --permanent --zone={q_z} --add-port={q_pp} 2>/dev/null || true')
                commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p {q_proto} --dport {q_port} -j REJECT 2>/dev/null || true')
                commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p {q_proto} --dport {q_port} -j REJECT 2>/dev/null || true')
        commands.append('resolvectl flush-caches 2>/dev/null || true')
        commands.append('ip route flush cache 2>/dev/null || true')
        return self.execute_batch(commands)

    # ── Rate Limiting ───────────────────────────────────────────────

    def add_rate_limit(self, zone: str, service: str, rate: str = '10/m') -> bool:
        """Add rate limiting for a service (e.g., '10/m' = 10 per minute)."""
        rule = f'rule service name="{service}" accept limit value="{rate}"'
        return self.add_rich_rule(zone, rule)

    # ── Port Forwarding ─────────────────────────────────────────────

    def add_forward_port(self, zone: str, port: str, protocol: str,
                         to_port: str, to_addr: str = '') -> bool:
        if not self.is_running():
            return False
        fwd = f'port={port}:proto={protocol}:toport={to_port}'
        if to_addr:
            fwd += f':toaddr={to_addr}'
        q_z = shlex.quote(zone)
        q_fwd = shlex.quote(fwd)
        ok, _ = self.execute_batch([
            f'firewall-cmd --zone={q_z} --add-forward-port={q_fwd}',
            f'firewall-cmd --permanent --zone={q_z} --add-forward-port={q_fwd}',
        ])
        return ok

    # ── Masquerade (NAT) ────────────────────────────────────────────

    def enable_masquerade(self, zone: str) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'add_masquerade', 'zone': zone, 'permanent': True}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', '--add-masquerade'], permanent=True)
        except PermissionError:
            logger.info("Enable masquerade cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to enable masquerade: {e}")
            return False

    def disable_masquerade(self, zone: str) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'remove_masquerade', 'zone': zone, 'permanent': True}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', '--remove-masquerade'], permanent=True, ignore_runtime_err=True)
        except PermissionError:
            logger.info("Disable masquerade cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to disable masquerade: {e}")
            return False

    # ── Panic Mode ──────────────────────────────────────────────────

    def get_panic_mode(self, force_refresh: bool = False) -> bool:
        now = time.time()
        with self._lock:
            if not force_refresh and 'panic_mode' in self._cache and (now - self._cache_time.get('panic_mode', 0)) < 3.0:
                return self._cache['panic_mode']
        if not self.is_running():
            return False
        val = self._dbus.query_panic() if self._dbus else None
        if val is None:
            val = _query_fw('--query-panic')
        with self._lock:
            self._cache['panic_mode'] = val
            self._cache_time['panic_mode'] = now
        return val


    def set_panic_mode(self, enabled: bool) -> bool:
        """Enable/disable panic mode (drops ALL network traffic when True, restores normal traffic when False)."""
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'panic_on' if enabled else 'panic_off'}])
            if ok:
                with self._lock:
                    self._cache['panic_mode'] = enabled
                    self._cache_time['panic_mode'] = time.time()
            return ok
        try:
            flag = '--panic-on' if enabled else '--panic-off'
            if self._use_pkexec:
                _run_pkexec_bash(f'firewall-cmd {flag}')
            else:
                _fw(flag)
            self.invalidate_cache()
            with self._lock:
                self._cache['panic_mode'] = enabled
                self._cache_time['panic_mode'] = time.time()
            return True
        except PermissionError:
            logger.info(f"{'Enable' if enabled else 'Disable'} panic mode cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to {'enable' if enabled else 'disable'} panic mode: {e}")
            return False

    def enable_panic_mode(self) -> bool:
        """Convenience method to enable panic mode (block all traffic)."""
        return self.set_panic_mode(True)

    def disable_panic_mode(self) -> bool:
        """Convenience method to disable panic mode (restore network traffic)."""
        return self.set_panic_mode(False)

    # ── ICMP Blocking ───────────────────────────────────────────────

    def get_icmp_types(self) -> list[str]:
        try:
            return _fw('--get-icmptypes').split()
        except Exception:
            return []

    def add_icmp_block(self, zone: str, icmp_type: str) -> bool:
        if not self.is_running():
            return False
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'add_icmp_block', 'zone': zone, 'icmp_type': icmp_type, 'permanent': True}])
            return ok
        try:
            return self._exec_fw_action([f'--zone={zone}', f'--add-icmp-block={icmp_type}'], permanent=True)
        except PermissionError:
            logger.info("Add ICMP block cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to add ICMP block: {e}")
            return False

    # ── Logging ─────────────────────────────────────────────────────

    def enable_logging(self, zone: str, level: str = 'all') -> bool:
        """Enable logging for denied packets."""
        rule = f'rule log prefix="VitoriusFW_{zone}_DENY " level="warning" limit value="5/m" drop'
        return self.add_rich_rule(zone, rule)

    # ── Reload / Runtime ────────────────────────────────────

    def reload(self) -> bool:
        if not self.is_running():
            return False
        self.invalidate_cache()
        if self._can_use_helper():
            ok, _ = self.execute_structured([{'action': 'reload'}])
            return ok
        try:
            if self._use_pkexec:
                _run_pkexec_bash('firewall-cmd --reload')
            else:
                _fw('--reload')
            return True
        except PermissionError:
            logger.info("Firewall reload cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Failed to reload: {e}")
            return False

    # ── nftables Direct Access ──────────────────────────────────────

    def nft_list_ruleset(self) -> str:
        """Get the full nftables ruleset (read-only, no pkexec prompt)."""
        try:
            return _run(['nft', 'list', 'ruleset']).stdout
        except Exception:
            return ''

    def nft_list_tables(self) -> list[str]:
        try:
            out = _run(['nft', 'list', 'tables']).stdout
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            return []

    # ── Export / Import ─────────────────────────────────────────────

    def export_rules(self, filepath: str) -> bool:
        """Export all zone configurations to a JSON file."""
        try:
            export_data = {
                'version': '3.0',
                'codename': 'GEOS',
                'default_zone': self.get_default_zone(),
                'zones': {}
            }
            for zone in self.get_zones():
                export_data['zones'][zone] = self.get_zone_settings(zone)

            parent_dir = os.path.dirname(os.path.abspath(filepath))
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export rules: {e}")
            return False

    def import_rules(self, filepath: str) -> tuple[bool, str]:
        """Import rules from a JSON file in a single privileged batch. Returns (success, message)."""
        if not self.is_running():
            return False, "firewalld daemon is not running"
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if data.get('version') not in ('1.0', '1.1', '1.11', '1.24', '1.30', '2.0', '3.0'):
                return False, 'Unsupported export version'

            commands = []
            valid_zones = set(self.get_zones())
            default_zone = data.get('default_zone')
            if default_zone and default_zone in valid_zones:
                commands.append(f'firewall-cmd --set-default-zone={shlex.quote(default_zone)}')
            for zone_name, zone_data in data.get('zones', {}).items():
                if zone_name not in valid_zones:
                    continue
                q_z = shlex.quote(zone_name)
                for svc in zone_data.get('services', []):
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-service={shlex.quote(svc)}')
                for port_info in zone_data.get('ports', []):
                    port = port_info['port']
                    proto = port_info.get('protocol', 'tcp')
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-port={shlex.quote(f"{port}/{proto}")}')
                for icmp in zone_data.get('icmp_blocks', []):
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-icmp-block={shlex.quote(icmp)}')
                for fwd in zone_data.get('forward_ports', []):
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-forward-port={shlex.quote(fwd)}')
                if zone_data.get('masquerade'):
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-masquerade')
                for rule in zone_data.get('rich_rules', []):
                    commands.append(f'firewall-cmd --permanent --zone={q_z} --add-rich-rule={shlex.quote(rule)}')

            if commands:
                commands.append('firewall-cmd --reload')
                return self.execute_batch(commands)
            return True, "No rules to import"
        except Exception as e:
            return False, str(e)

    # ── Summary / Statistics ────────────────────────────────────────

    def get_summary(self) -> dict:
        """Get a summary of the current firewall state."""
        now = time.time()
        with self._lock:
            if 'summary' in self._cache and (now - self._cache_time.get('summary', 0)) < 8.0:
                return copy.deepcopy(self._cache['summary'])

        if not self.is_running():
            summary = {
                'running': False,
                'default_zone': 'public',
                'active_zones': [],
                'total_interfaces': 0,
                'total_services': 0,
                'total_ports': 0,
                'total_rich_rules': 0,
                'panic_mode': False,
                'masquerade': False,
                'blocked_ips': 0,
            }
            with self._lock:
                self._cache['summary'] = copy.deepcopy(summary)
                self._cache_time['summary'] = now
            return summary

        default_zone = self.get_default_zone()
        active_zones = self.get_active_zones()
        zone_settings = self.get_zone_settings(default_zone)

        total_rules = len(zone_settings.get('rich_rules', []))
        total_ports = len(zone_settings.get('ports', []))
        total_services = len(zone_settings.get('services', []))

        pattern = re.compile(r'source address="([^"]+)".*(?:reject|drop)')
        blocked_count = sum(1 for r in zone_settings.get('rich_rules', []) if pattern.search(r))

        summary = {
            'running': self.is_running(),
            'default_zone': default_zone,
            'active_zones': list(active_zones.keys()),
            'total_interfaces': sum(
                len(v.get('interfaces', [])) for v in active_zones.values()
            ),
            'total_services': total_services,
            'total_ports': total_ports,
            'total_rich_rules': total_rules,
            'panic_mode': self.get_panic_mode(),
            'masquerade': zone_settings.get('masquerade', False),
            'blocked_ips': blocked_count,
        }
        with self._lock:
            self._cache['summary'] = copy.deepcopy(summary)
            self._cache_time['summary'] = now
        return summary

