"""
Vitorius Firewall - Sticky TCP Tarpit Decoy
Throttles automated network reconnaissance scans by holding connections open
and trickling bytes at ultra-low throughput to exhaust scanner socket pools.
"""

import asyncio
import logging
from backend.honeypot.decoys.base import BaseDecoy

logger = logging.getLogger('vitorius.honeypot.tarpit')


class TarpitDecoy(BaseDecoy):
    """Sticky TCP Tarpit connection sinkhole."""

    def __init__(self, quarantine_engine, internal_port: int = 12000, external_port: int = 8888):
        super().__init__(
            name='Tarpit',
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            timeout_sec=120.0  # Hold connection open for up to 2 minutes
        )

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='Tarpit',
            event_type='port_probe',
            details="Trapped in sticky TCP Tarpit",
            payload={}
        )

        # Trickle 1 byte every 8 seconds to keep socket in ESTABLISHED state
        try:
            for _ in range(15):
                writer.write(b"\x00")
                await writer.drain()
                await asyncio.sleep(8.0)
        except (ConnectionResetError, BrokenPipeError):
            pass
