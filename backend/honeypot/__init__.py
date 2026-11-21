"""
Vitorius Firewall - Honeypot & Deception Subsystem
"""

from backend.honeypot.engine import DeceptionEngine
from backend.honeypot.honeyfiles import HoneyFileManager
from backend.honeypot.telemetry import HoneypotTelemetry
from backend.honeypot.quarantine import QuarantineEngine
from backend.honeypot.arbiter import HoneypotArbiter
from backend.honeypot.deflator import ScannerDeflator
from backend.honeypot.morph import OSMorpher
from backend.honeypot.liquid import LiquidProtocolDecoy

__all__ = [
    'DeceptionEngine',
    'HoneyFileManager',
    'HoneypotTelemetry',
    'QuarantineEngine',
    'HoneypotArbiter',
    'ScannerDeflator',
    'OSMorpher',
    'LiquidProtocolDecoy',
]
