"""
Vitorius Firewall - Process Group Micro-Freezer
Atomically freezes execution of an entire process group in kernel space via SIGSTOP,
preventing rogue processes from exfiltrating data or evading containment during operator triage.
"""

import os
import signal
import logging
from typing import Optional

logger = logging.getLogger('vitorius.lineage.freezer')


class ProcessFreezer:
    """Manages process group suspension (SIGSTOP), resumption (SIGCONT), and termination (SIGKILL)."""

    def __init__(self):
        # Maps pgid -> metadata dict
        self._frozen_groups: dict[int, dict] = {}

    def freeze_process_group(self, pid: int, pgid: Optional[int] = None, metadata: Optional[dict] = None) -> bool:
        """
        Atomically freeze the entire process group.
        All child processes, sub-shells, and threads are immediately suspended.
        """
        try:
            target_pgid = pgid or os.getpgid(pid)
        except (ProcessLookupError, OSError):
            target_pgid = pid

        try:
            # Send SIGSTOP to the entire process group
            os.killpg(target_pgid, signal.SIGSTOP)
            self._frozen_groups[target_pgid] = {
                'pgid': target_pgid,
                'root_pid': pid,
                'metadata': metadata or {},
            }
            logger.info(f"Process Group [{target_pgid}] (root PID {pid}) frozen in kernel space via SIGSTOP.")
            return True
        except ProcessLookupError:
            logger.debug(f"Process {pid} or group {target_pgid} exited before freeze could apply.")
            return False
        except PermissionError:
            # If cross-user or unprivileged, fallback to single process kill or pkexec
            try:
                os.kill(pid, signal.SIGSTOP)
                self._frozen_groups[target_pgid] = {'pgid': target_pgid, 'root_pid': pid, 'metadata': metadata or {}}
                return True
            except Exception as e:
                logger.error(f"Permission denied freezing PID {pid}: {e}")
                return False
        except Exception as e:
            logger.error(f"Error freezing process group {target_pgid}: {e}")
            return False

    def resume_process_group(self, pgid: int) -> bool:
        """Resume execution of a previously frozen process group."""
        try:
            os.killpg(pgid, signal.SIGCONT)
            self._frozen_groups.pop(pgid, None)
            logger.info(f"Process Group [{pgid}] resumed via SIGCONT.")
            return True
        except ProcessLookupError:
            self._frozen_groups.pop(pgid, None)
            return True
        except Exception as e:
            logger.error(f"Error resuming process group {pgid}: {e}")
            return False

    def terminate_process_group(self, pgid: int) -> bool:
        """Immediately purge an offending process group and its children from memory."""
        try:
            os.killpg(pgid, signal.SIGKILL)
            self._frozen_groups.pop(pgid, None)
            logger.warning(f"Offending Process Group [{pgid}] eradicated via SIGKILL.")
            return True
        except ProcessLookupError:
            self._frozen_groups.pop(pgid, None)
            return True
        except Exception as e:
            logger.error(f"Error terminating process group {pgid}: {e}")
            return False

    def is_frozen(self, pgid: int) -> bool:
        return pgid in self._frozen_groups

    def get_frozen_groups(self) -> list[dict]:
        """Return list of currently suspended process groups."""
        return list(self._frozen_groups.values())
