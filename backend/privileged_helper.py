#!/usr/bin/env python3
"""
Vitorius Firewall - Strict Allowlisted Privileged Helper
Executes structured JSON firewall operations using argv lists (`shell=False`),
eliminating arbitrary `bash -c` execution when paired with Polkit (`com.v.firewall.policy`).
"""

import ipaddress
import json
import os
import re
import subprocess
import sys

_ZONE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_SVC_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_PORT_RE = re.compile(r'^\d{1,5}(?:-\d{1,5})?$')
_PROTO_SET = {'tcp', 'udp', 'sctp', 'dccp'}
_IPSET_RE = re.compile(r'^vfw_geo_[A-Z]{2}$')


def _validate_ip(val: str) -> str:
    try:
        ipaddress.ip_address(val)
        return val
    except ValueError:
        ipaddress.ip_network(val, strict=False)
        return val


def build_argv_for_op(op: dict) -> list[tuple[list[str], bool]]:
    """Validate a single operation dict and return a list of (argv, best_effort) tuples."""
    action = op.get('action', '')
    cmds: list[tuple[list[str], bool]] = []

    if action == 'start_firewalld':
        cmds.append((['systemctl', 'start', 'firewalld'], True))
    elif action == 'reload':
        cmds.append((['firewall-cmd', '--reload'], False))
    elif action == 'panic_on':
        cmds.append((['firewall-cmd', '--panic-on'], False))
    elif action == 'panic_off':
        cmds.append((['firewall-cmd', '--panic-off'], False))
    elif action == 'set_default_zone':
        zone = op['zone']
        if not _ZONE_RE.fullmatch(zone):
            raise ValueError(f'Invalid zone: {zone}')
        cmds.append((['firewall-cmd', f'--set-default-zone={zone}'], False))
    elif action == 'set_log_denied':
        val = str(op.get('value', 'off'))
        if val not in ('all', 'unicast', 'broadcast', 'multicast', 'off'):
            raise ValueError(f'Invalid log-denied value: {val}')
        cmds.append((['firewall-cmd', f'--set-log-denied={val}'], False))
    elif action in ('add_service', 'remove_service'):
        zone, svc = op['zone'], op['service']
        if not _ZONE_RE.fullmatch(zone) or not _SVC_RE.fullmatch(svc):
            raise ValueError('Invalid zone or service')
        flag = '--add-service' if action == 'add_service' else '--remove-service'
        be = (action == 'remove_service')
        cmds.append((['firewall-cmd', f'--zone={zone}', f'{flag}={svc}'], be))
        if op.get('permanent', True):
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', f'{flag}={svc}'], False))
    elif action in ('add_port', 'remove_port'):
        zone, port, proto = op['zone'], str(op['port']), op.get('protocol', 'tcp')
        if not _ZONE_RE.fullmatch(zone) or not _PORT_RE.fullmatch(port) or proto not in _PROTO_SET:
            raise ValueError('Invalid port specification')
        flag = '--add-port' if action == 'add_port' else '--remove-port'
        be = (action == 'remove_port')
        cmds.append((['firewall-cmd', f'--zone={zone}', f'{flag}={port}/{proto}'], be))
        if op.get('permanent', True):
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', f'{flag}={port}/{proto}'], False))
    elif action in ('add_rich_rule', 'remove_rich_rule'):
        zone, rule = op['zone'], str(op['rule']).strip()
        if not _ZONE_RE.fullmatch(zone) or not rule.startswith('rule ') or '\n' in rule or '\x00' in rule:
            raise ValueError('Invalid rich rule')
        flag = '--add-rich-rule' if action == 'add_rich_rule' else '--remove-rich-rule'
        be = (action == 'remove_rich_rule')
        cmds.append((['firewall-cmd', f'--zone={zone}', f'{flag}={rule}'], be))
        if op.get('permanent', True):
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', f'{flag}={rule}'], False))
    elif action in ('add_masquerade', 'remove_masquerade'):
        zone = op['zone']
        if not _ZONE_RE.fullmatch(zone):
            raise ValueError('Invalid zone')
        flag = '--add-masquerade' if action == 'add_masquerade' else '--remove-masquerade'
        be = (action == 'remove_masquerade')
        cmds.append((['firewall-cmd', f'--zone={zone}', flag], be))
        if op.get('permanent', True):
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', flag], False))
    elif action in ('add_icmp_block', 'remove_icmp_block'):
        zone, icmp = op['zone'], op['icmp_type']
        if not _ZONE_RE.fullmatch(zone) or not _SVC_RE.fullmatch(icmp):
            raise ValueError('Invalid zone or icmp type')
        flag = '--add-icmp-block' if action == 'add_icmp_block' else '--remove-icmp-block'
        be = (action == 'remove_icmp_block')
        cmds.append((['firewall-cmd', f'--zone={zone}', f'{flag}={icmp}'], be))
        if op.get('permanent', True):
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', f'{flag}={icmp}'], False))
    elif action in ('add_icmp_block_inversion', 'remove_icmp_block_inversion'):
        zone = op['zone']
        if not _ZONE_RE.fullmatch(zone):
            raise ValueError('Invalid zone')
        flag = '--add-icmp-block-inversion' if action == 'add_icmp_block_inversion' else '--remove-icmp-block-inversion'
        cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', flag], False))
    elif action in ('block_ip', 'unblock_ip'):
        zone, ip = op['zone'], _validate_ip(str(op['ip']))
        if not _ZONE_RE.fullmatch(zone):
            raise ValueError('Invalid zone')
        ver = ipaddress.ip_network(ip, strict=False).version
        family = 'ipv6' if ver == 6 else 'ipv4'
        rich_flag = '--add-rich-rule' if action == 'block_ip' else '--remove-rich-rule'
        dir_flag = '--add-rule' if action == 'block_ip' else '--remove-rule'
        if action == 'block_ip':
            cmds.append((['ss', '-K', 'dst', ip], True))
        for target in ('source', 'destination'):
            rule = f'rule family="{family}" {target} address="{ip}" reject'
            cmds.append((['firewall-cmd', f'--zone={zone}', f'{rich_flag}={rule}'], True))
            cmds.append((['firewall-cmd', '--permanent', f'--zone={zone}', f'{rich_flag}={rule}'], True))
        cmds.append((['firewall-cmd', '--direct', dir_flag, family, 'filter', 'OUTPUT', '0', '-d', ip, '-j', 'REJECT'], True))
        cmds.append((['firewall-cmd', '--permanent', '--direct', dir_flag, family, 'filter', 'OUTPUT', '0', '-d', ip, '-j', 'REJECT'], True))
        cmds.append((['firewall-cmd', '--direct', dir_flag, family, 'filter', 'INPUT', '0', '-s', ip, '-j', 'REJECT'], True))
        cmds.append((['firewall-cmd', '--permanent', '--direct', dir_flag, family, 'filter', 'INPUT', '0', '-s', ip, '-j', 'REJECT'], True))
    elif action in ('new_ipset', 'delete_ipset', 'ipset_add_file'):
        ipset = op['ipset']
        if not _IPSET_RE.fullmatch(ipset):
            raise ValueError('Invalid ipset name')
        if action == 'new_ipset':
            cmds.append((['firewall-cmd', '--permanent', f'--new-ipset={ipset}', '--type=hash:net'], True))
        elif action == 'delete_ipset':
            cmds.append((['firewall-cmd', '--permanent', f'--delete-ipset={ipset}'], True))
        else:
            fpath = os.path.realpath(str(op['file']))
            if not fpath.endswith('.txt') or not os.path.isfile(fpath):
                raise ValueError('Invalid ipset entry file')
            cmds.append((['firewall-cmd', '--permanent', f'--ipset={ipset}', f'--add-entries-from-file={fpath}'], True))
    else:
        raise ValueError(f'Unsupported action: {action}')

    return cmds


def execute_operations(payload: dict) -> tuple[bool, str]:
    ops = payload.get('operations', [])
    if not isinstance(ops, list):
        return False, 'operations must be a list'

    for op in ops:
        cmds = build_argv_for_op(op)
        op_ignore = bool(op.get('ignore_errors', False))
        for argv, best_effort in cmds:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if res.returncode != 0 and not (best_effort or op_ignore):
                return False, (res.stderr or res.stdout or f'Command failed: {argv[0]}').strip()
    return True, 'OK'


def main() -> int:
    try:
        data = json.load(sys.stdin)
        ok, msg = execute_operations(data)
        print(json.dumps({'ok': ok, 'message': msg}))
        return 0 if ok else 1
    except Exception as e:
        print(json.dumps({'ok': False, 'message': str(e)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
