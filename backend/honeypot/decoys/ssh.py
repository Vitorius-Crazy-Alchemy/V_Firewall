"""
Vitorius Firewall - Synthetic OpenSSH Decoy
Emulates OpenSSH RFC 4253 protocol exchange, banner negotiation,
and client credential capture without executing a local shell.
"""

import asyncio
import struct
import logging
from backend.honeypot.decoys.base import BaseDecoy

logger = logging.getLogger('vitorius.honeypot.ssh')

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Fedora-2024\r\n"


class SshDecoy(BaseDecoy):
    """Synthetic SSH decoy protocol handler."""

    def __init__(self, quarantine_engine, internal_port: int = 12022, external_port: int = 22):
        super().__init__(
            name='SSH',
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            timeout_sec=15.0
        )

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        # 1. Send OpenSSH Server Banner
        writer.write(SSH_BANNER)
        await writer.drain()

        # 2. Read Client SSH Banner (up to 255 bytes terminated by newline)
        client_banner_line = await reader.readline()
        if not client_banner_line:
            return

        client_banner = client_banner_line.decode('utf-8', errors='ignore').strip()

        # Record probe telemetry
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='SSH',
            event_type='port_probe',
            details=f"Connected with client banner: '{client_banner}'",
            payload={'client_banner': client_banner}
        )

        # 3. Read up to 4KB of subsequent key exchange or credential packets
        try:
            data = await reader.read(4096)
            if data:
                # Check for plaintext probes or embedded credentials
                raw_text = ''.join(chr(b) for b in data if 32 <= b <= 126)
                if len(raw_text) > 3:
                    self.quarantine.record_interaction(
                        ip=client_ip,
                        source_port=client_port,
                        target_port=self.external_port,
                        decoy_name='SSH',
                        event_type='credential_attempt',
                        details=f"SSH payload extracted: '{raw_text[:64]}'",
                        payload={'credentials': {'service': 'ssh', 'raw_payload': raw_text[:128]}}
                    )
        except Exception:
            pass
