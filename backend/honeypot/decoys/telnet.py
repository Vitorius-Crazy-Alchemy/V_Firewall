"""
Vitorius Firewall - Synthetic Telnet Decoy
Emulates an interactive Linux Telnet login session,
harvests attacker credentials, and displays authentic system banners.
"""

import asyncio
import logging
from backend.honeypot.decoys.base import BaseDecoy

logger = logging.getLogger('vitorius.honeypot.telnet')


class TelnetDecoy(BaseDecoy):
    """Synthetic Telnet IoT and terminal decoy."""

    def __init__(self, quarantine_engine, internal_port: int = 12023, external_port: int = 23):
        super().__init__(
            name='Telnet',
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            timeout_sec=20.0
        )

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        # Record initial probe
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='Telnet',
            event_type='port_probe',
            details="Connected to Telnet terminal port",
            payload={}
        )

        # 1. Send Telnet IAC negotiations (WILL ECHO, WILL SGA)
        writer.write(b'\xff\xfb\x01\xff\xfb\x03')
        # 2. Send Fedora login banner
        banner = (
            b"\r\n"
            b"Fedora Linux 41 (Server Edition)\r\n"
            b"Kernel 6.11.4-200.fc41.x86_64 on an x86_64\r\n"
            b"\r\n"
            b"vitorius-node01 login: "
        )
        writer.write(banner)
        await writer.drain()

        # 3. Read username
        user_line = await reader.readline()
        if not user_line:
            return
        username = user_line.decode('utf-8', errors='ignore').strip().replace('\xff', '')

        # 4. Prompt for Password
        writer.write(b"Password: ")
        await writer.drain()

        # 5. Read password
        pass_line = await reader.readline()
        password = pass_line.decode('utf-8', errors='ignore').strip().replace('\xff', '') if pass_line else ""

        # 6. Record harvested credentials
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='Telnet',
            event_type='credential_attempt',
            details=f"Telnet authentication attempt (user: '{username}')",
            payload={'credentials': {'service': 'telnet', 'username': username, 'password': password}}
        )

        # 7. Reject and close
        writer.write(b"\r\nLogin incorrect\r\n\r\n")
        await writer.drain()
