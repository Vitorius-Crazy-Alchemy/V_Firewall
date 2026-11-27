"""
Vitorius Firewall - Decoys Package
"""

from backend.honeypot.decoys.base import BaseDecoy
from backend.honeypot.decoys.ssh import SshDecoy
from backend.honeypot.decoys.http import HttpDecoy
from backend.honeypot.decoys.smb import SmbDecoy
from backend.honeypot.decoys.telnet import TelnetDecoy
from backend.honeypot.decoys.database import MySqlDecoy, RedisDecoy
from backend.honeypot.decoys.tarpit import TarpitDecoy

__all__ = [
    'BaseDecoy',
    'SshDecoy',
    'HttpDecoy',
    'SmbDecoy',
    'TelnetDecoy',
    'MySqlDecoy',
    'RedisDecoy',
    'TarpitDecoy',
]
