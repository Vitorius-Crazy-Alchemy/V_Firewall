"""
Vitorius Firewall - Lineage Policy Engine & Anomaly Detector
Evaluates process ancestry trees against trust signatures and flags
supply-chain attacks, browser escapes, and hidden binary execution.
"""

import os
import json
import time
import tempfile
import threading
import logging
from pathlib import Path
from typing import Optional
from backend.lineage.resolver import LineageTree

logger = logging.getLogger('vitorius.lineage.policy')

BASE_STORAGE = Path(__file__).resolve().parent.parent.parent / '.storage'

try:
    CONFIG_DIR = Path.home() / '.config' / 'v-firewall'
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    CONFIG_DIR = BASE_STORAGE / 'config'

TRUST_DB_FILE = CONFIG_DIR / 'lineage_trust.json'


class LineagePolicyEngine:
    """Manages lineage signatures and detects supply-chain and execution anomalies."""

    NETWORK_TOOLS = {'curl', 'wget', 'nc', 'netcat', 'ncat', 'socat', 'python', 'python3', 'ssh', 'bash', 'sh'}
    PACKAGE_MANAGERS = {'npm', 'node', 'pip', 'pip3', 'setup.py', 'cargo', 'gem', 'composer'}
    BROWSERS = {'firefox', 'chrome', 'google-chrome', 'brave', 'brave-browser', 'chromium'}
    SUSPICIOUS_PATHS = {'/tmp', '/var/tmp', '/dev/shm'}

    def __init__(self, trust_file: Optional[Path] = None):
        self._lock = threading.RLock()
        self.trust_file = trust_file or TRUST_DB_FILE
        self.trusted_signatures: dict[str, dict] = {}
        self._load_trust_db()

    def _load_trust_db(self):
        with self._lock:
            if not self.trust_file.exists():
                return
            try:
                with open(self.trust_file, 'r', encoding='utf-8') as f:
                    self.trusted_signatures = json.load(f)
            except Exception as e:
                logger.error(f"Error loading lineage trust database: {e}")

    def _save_trust_db(self):
        with self._lock:
            try:
                self.trust_file.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp_name = tempfile.mkstemp(prefix='.trust_', suffix='.tmp', dir=str(self.trust_file.parent))
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as f:
                        json.dump(self.trusted_signatures, f, indent=2)
                    os.replace(tmp_name, self.trust_file)
                except Exception:
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
            except Exception as e:
                logger.error(f"Error saving lineage trust database: {e}")

    def evaluate_lineage(self, tree: LineageTree, remote_ip: str, remote_port: int) -> tuple[bool, str, str]:
        """
        Evaluates a process execution tree.
        Returns (is_trusted, anomaly_type, description).
        """
        # 1. Check if signature is already whitelisted by operator
        if tree.signature_hash in self.trusted_signatures:
            return True, "TRUSTED", "Lineage cryptographically trusted"

        leaf = tree.leaf
        ancestor_names = [n.name.lower() for n in tree.nodes[1:]]

        # 2. Anomaly Check: Package Manager / Build Script Supply Chain Attack
        # (e.g. npm or pip spawning curl to download payload)
        pm_match = next((pm for pm in ancestor_names if pm in self.PACKAGE_MANAGERS), None)
        if pm_match and leaf.name.lower() in self.NETWORK_TOOLS:
            return False, "DEV_SUPPLY_CHAIN_ANOMALY", f"Package manager '{pm_match}' spawned network utility '{leaf.name}'"

        # 3. Anomaly Check: Browser Escape
        # (e.g. firefox or chrome spawning /bin/sh or curl)
        browser_match = next((b for b in ancestor_names if b in self.BROWSERS), None)
        if browser_match and leaf.name.lower() in (self.NETWORK_TOOLS | {'sh', 'bash'}):
            return False, "BROWSER_ESCAPE_SPAWN", f"Web browser '{browser_match}' spawned shell/network binary '{leaf.name}'"

        # 4. Anomaly Check: Hidden or World-Writable Directory Execution
        if any(leaf.exe_path.startswith(sp) for sp in self.SUSPICIOUS_PATHS) or '/.cache/' in leaf.exe_path:
            return False, "HIDDEN_EXEC_ANOMALY", f"Executable launched from suspicious directory '{leaf.exe_path}'"

        # 5. Anomaly Check: Interactive Terminal Shell
        # Clean interactive shell usage is permitted with lower friction
        if tree.is_interactive_shell:
            return True, "INTERACTIVE_SHELL", "Interactive user terminal shell"

        # 6. Default: Unsanctioned Lineage
        return False, "UNSANCTIONED_LINEAGE", f"Unapproved execution lineage: {tree.summary}"

    def trust_lineage(self, signature_hash: str, summary: str, description: str = ""):
        with self._lock:
            self.trusted_signatures[signature_hash] = {
                'summary': summary,
                'description': description,
                'trusted_at': time.time()
            }
            self._save_trust_db()

    def revoke_lineage(self, signature_hash: str):
        with self._lock:
            if signature_hash in self.trusted_signatures:
                del self.trusted_signatures[signature_hash]
                self._save_trust_db()

    def get_trusted_lineages(self) -> list[dict]:
        with self._lock:
            return [
                {'signature_hash': k, **v}
                for k, v in self.trusted_signatures.items()
            ]
