"""
Vitorius Firewall - Offline Country Geo-Blocking via firewalld IPSets
Supports system/user `.zone` CIDR files plus curated offline fallback CIDRs.
"""

import ipaddress
import logging
import os
import re
import shlex
from pathlib import Path
from typing import Optional

logger = logging.getLogger('vitorius.geoblock')

# Curated offline baseline CIDRs for high-risk profile defaults when external GeoIP .zone files are absent.
# Users can drop full ipdeny `.zone` files (e.g. cn.zone, ru.zone) into ~/.local/share/v-firewall/geoip/
BASELINE_COUNTRY_CIDRS: dict[str, list[str]] = {
    'CN': ['1.0.1.0/24', '1.0.2.0/23', '1.0.8.0/21', '1.1.0.0/24', '14.0.0.0/16', '27.0.0.0/16'],
    'RU': ['2.60.0.0/14', '5.8.0.0/16', '5.16.0.0/14', '31.13.0.0/16', '37.9.0.0/16', '46.0.0.0/16'],
    'KP': ['175.45.176.0/22'],
    'IR': ['2.144.0.0/14', '5.22.0.0/16', '5.52.0.0/14', '31.2.0.0/16', '37.32.0.0/14'],
    'SY': ['5.0.0.0/17', '31.9.0.0/16', '46.53.0.0/16', '82.137.192.0/18'],
    'CU': ['152.206.0.0/16', '181.225.224.0/19', '190.6.64.0/20', '200.55.128.0/18'],
}

IPSET_PREFIX = 'vfw_geo_'


class GeoBlockManager:
    """Manages firewalld hash:net IPSets and drop rich rules for country-level blocking."""

    def __init__(self, geoip_dir: Optional[Path] = None):
        if geoip_dir:
            self.geoip_dir = Path(geoip_dir)
        else:
            try:
                self.geoip_dir = Path.home() / '.local' / 'share' / 'v-firewall' / 'geoip'
            except OSError:
                self.geoip_dir = Path(__file__).resolve().parent.parent / '.storage' / 'geoip'
        self.geoip_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _valid_cc(code: str) -> Optional[str]:
        cc = str(code).strip().upper()
        return cc if re.fullmatch(r'[A-Z]{2}', cc) else None

    def load_country_cidrs(self, country_code: str) -> list[str]:
        """Load valid IPv4 CIDRs for *country_code* from local GeoIP/zone files or offline baseline."""
        cc = self._valid_cc(country_code)
        if not cc:
            return []

        search_paths = [
            self.geoip_dir / f'{cc.lower()}.zone',
            self.geoip_dir / f'{cc}.zone',
            Path('/usr/share/GeoIP') / f'{cc.lower()}.zone',
            Path('/var/lib/GeoIP') / f'{cc.lower()}.zone',
        ]
        for path in search_paths:
            if path.is_file():
                cidrs = []
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            s = line.strip()
                            if not s or s.startswith('#'):
                                continue
                            try:
                                net = ipaddress.ip_network(s, strict=False)
                                if net.version == 4:
                                    cidrs.append(str(net))
                            except ValueError:
                                continue
                    if cidrs:
                        return cidrs
                except OSError as e:
                    logger.debug(f"Failed reading zone file {path}: {e}")

        return list(BASELINE_COUNTRY_CIDRS.get(cc, []))

    def _write_ipset_file(self, cc: str, cidrs: list[str]) -> Path:
        out_path = self.geoip_dir / f'{IPSET_PREFIX}{cc}.txt'
        out_path.write_text('\n'.join(cidrs) + '\n', encoding='utf-8')
        return out_path

    def build_apply_commands(self, countries: list[str], zone: str) -> list[str]:
        """Generate batched firewall-cmd commands to enforce country GeoIP IPSets."""
        commands = []
        q_zone = shlex.quote(zone)
        for raw_cc in countries:
            cc = self._valid_cc(raw_cc)
            if not cc:
                continue
            cidrs = self.load_country_cidrs(cc)
            if not cidrs:
                continue

            ipset_name = f'{IPSET_PREFIX}{cc}'
            q_ipset = shlex.quote(ipset_name)
            entry_file = self._write_ipset_file(cc, cidrs)
            q_file = shlex.quote(str(entry_file))
            rich = shlex.quote(f'rule family="ipv4" source ipset="{ipset_name}" drop')

            commands.append(f'firewall-cmd --permanent --new-ipset={q_ipset} --type=hash:net 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --ipset={q_ipset} --add-entries-from-file={q_file} 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --zone={q_zone} --add-rich-rule={rich} 2>/dev/null || true')

        return commands

    def build_cleanup_commands(
        self,
        zone: str,
        existing_rich_rules: Optional[list[str]] = None,
        all_zones: Optional[list[str]] = None,
    ) -> list[str]:
        """Generate commands to remove existing vfw_geo_* rich rules and IPSets."""
        commands = []
        target_zones = list(dict.fromkeys([zone] + list(all_zones or [])))
        q_zone = shlex.quote(zone)
        pattern = re.compile(r'ipset="?(vfw_geo_[A-Z]{2})"?')
        ipsets = set()

        for rule in (existing_rich_rules or []):
            m = pattern.search(rule)
            if m:
                ipsets.add(m.group(1))
                commands.append(f'firewall-cmd --permanent --zone={q_zone} --remove-rich-rule={shlex.quote(rule)} 2>/dev/null || true')

        for cc in BASELINE_COUNTRY_CIDRS:
            ipsets.add(f'{IPSET_PREFIX}{cc}')

        for ipset_name in sorted(ipsets):
            rich = shlex.quote(f'rule family="ipv4" source ipset="{ipset_name}" drop')
            for z in target_zones:
                commands.append(f'firewall-cmd --permanent --zone={shlex.quote(z)} --remove-rich-rule={rich} 2>/dev/null || true')
            commands.append(f'firewall-cmd --permanent --delete-ipset={shlex.quote(ipset_name)} 2>/dev/null || true')

        return commands
