"""
Vitorius Firewall - Process Lineage Resolver
Reconstructs the full process ancestry tree from procfs, validates against
PID-reuse race conditions, and generates deterministic lineage signatures.
"""

import os
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger('vitorius.lineage.resolver')


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    pgid: int
    name: str
    exe_path: str
    cmdline: list[str]
    uid: int
    starttime: int
    cgroup_path: str = ""

    def to_dict(self) -> dict:
        return {
            'pid': self.pid,
            'ppid': self.ppid,
            'pgid': self.pgid,
            'name': self.name,
            'exe_path': self.exe_path,
            'cmdline': self.cmdline,
            'uid': self.uid,
            'starttime': self.starttime,
            'cgroup_path': self.cgroup_path,
        }


@dataclass
class LineageTree:
    nodes: list[ProcessNode]  # Leaf [0] -> Parent [1] -> ... -> Root [N]
    signature_hash: str
    is_interactive_shell: bool = False
    is_dev_tool: bool = False
    is_browser_child: bool = False
    summary: str = ""

    @property
    def leaf(self) -> ProcessNode:
        return self.nodes[0]

    def to_dict(self) -> dict:
        return {
            'signature_hash': self.signature_hash,
            'summary': self.summary,
            'is_interactive_shell': self.is_interactive_shell,
            'is_dev_tool': self.is_dev_tool,
            'is_browser_child': self.is_browser_child,
            'nodes': [n.to_dict() for n in self.nodes]
        }


class LineageResolver:
    """Traverses procfs to extract authentic parent-child process execution trees."""

    DEV_TOOLS = {'npm', 'node', 'pip', 'python', 'python3', 'cargo', 'rustc', 'gem', 'composer', 'gradle', 'mvn', 'make', 'cmake'}
    BROWSERS = {'firefox', 'chrome', 'google-chrome', 'brave', 'brave-browser', 'chromium', 'opera', 'vivaldi'}
    SHELLS = {'bash', 'zsh', 'sh', 'dash', 'fish', 'tcsh'}
    TERMINAL_EMULATORS = {
        'ptyxis', 'konsole', 'alacritty', 'kitty', 'wezterm-gui', 'foot',
        'tilix', 'xterm', 'kgx', 'terminator', 'urxvt', 'st',
        'gnome-terminal-', 'mate-terminal', 'xfce4-terminal',
    }

    def resolve_tree(self, pid: int) -> Optional[LineageTree]:
        """Reconstruct the complete process tree up to PID 1 (systemd)."""
        nodes: list[ProcessNode] = []
        curr_pid = pid
        visited_pids = set()

        while curr_pid > 0 and curr_pid not in visited_pids:
            visited_pids.add(curr_pid)
            node = self._read_process_node(curr_pid)
            if not node:
                break

            nodes.append(node)

            # If reached PID 1 (systemd/init), stop
            if curr_pid == 1 or node.ppid == 0 or node.ppid == curr_pid:
                break

            # Anti-PID reuse check: Parent must have been started before or at same time as child
            parent_stat = self._read_stat(node.ppid)
            if parent_stat and parent_stat.get('starttime', 0) > node.starttime:
                logger.warning(f"PID Reuse detected: Parent {node.ppid} started after child {curr_pid}. Halting traversal.")
                break

            curr_pid = node.ppid

        if not nodes:
            return None

        # Determine lineage characteristics
        names = [n.name.lower() for n in nodes]
        is_interactive = any(s in names for s in self.SHELLS) and any(
            'terminal' in n or n in self.TERMINAL_EMULATORS for n in names
        )
        is_dev = any(d in names for d in self.DEV_TOOLS)
        is_browser = any(b in names for b in self.BROWSERS)

        summary = " -> ".join(reversed([n.name for n in nodes]))
        sig_hash = self._compute_signature(nodes)

        return LineageTree(
            nodes=nodes,
            signature_hash=sig_hash,
            is_interactive_shell=is_interactive,
            is_dev_tool=is_dev,
            is_browser_child=is_browser,
            summary=summary
        )

    def _read_process_node(self, pid: int) -> Optional[ProcessNode]:
        """Extract process metadata safely from /proc/[pid]."""
        stat_data = self._read_stat(pid)
        if not stat_data:
            return None

        # Executable path
        exe_path = ""
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
        except Exception:
            exe_path = stat_data.get('comm', '')

        # Command line arguments
        cmdline = []
        try:
            with open(f"/proc/{pid}/cmdline", 'rb') as f:
                raw = f.read()
                cmdline = [p.decode('utf-8', errors='ignore') for p in raw.split(b'\x00') if p]
        except Exception:
            cmdline = [stat_data.get('comm', '')]

        # UID
        uid = os.getuid()
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
        except Exception:
            pass

        # Cgroup path
        cg_path = ""
        try:
            with open(f"/proc/{pid}/cgroup", 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3 and parts[2]:
                        cg_path = parts[2]
                        break
        except Exception:
            pass

        return ProcessNode(
            pid=pid,
            ppid=stat_data.get('ppid', 0),
            pgid=stat_data.get('pgrp', pid),
            name=stat_data.get('comm', ''),
            exe_path=exe_path,
            cmdline=cmdline,
            uid=uid,
            starttime=stat_data.get('starttime', 0),
            cgroup_path=cg_path
        )

    def _read_stat(self, pid: int) -> Optional[dict]:
        """Parse /proc/[pid]/stat respecting parentheses around comm."""
        try:
            with open(f"/proc/{pid}/stat", 'r') as f:
                content = f.read()
            # Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt ... starttime
            lparen = content.find('(')
            rparen = content.rfind(')')
            if lparen == -1 or rparen == -1:
                return None

            pid_val = int(content[:lparen].strip())
            comm = content[lparen+1:rparen]
            rest = content[rparen+1:].strip().split()

            return {
                'pid': pid_val,
                'comm': comm,
                'state': rest[0],
                'ppid': int(rest[1]),
                'pgrp': int(rest[2]),
                'starttime': int(rest[19]) if len(rest) > 19 else 0
            }
        except Exception:
            return None

    def _compute_signature(self, nodes: list[ProcessNode]) -> str:
        """Generate deterministic HMAC/SHA256 signature from executable ancestry chain."""
        h = hashlib.sha256()
        for node in reversed(nodes):
            h.update(node.exe_path.encode('utf-8'))
            h.update(str(node.uid).encode('utf-8'))
        return h.hexdigest()
