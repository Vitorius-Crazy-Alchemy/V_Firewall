"""
Vitorius Firewall - Liquid Decoy Fabric (Just-in-Time Protocol Synthesizer)
Dynamically synthesizes authentic protocol handshakes (FTP, SMTP, VNC, RDP)
on demand, transforming any unallocated port into an active deception tripwire.
"""

import asyncio
import struct
import logging
from backend.honeypot.decoys.base import BaseDecoy
from backend.honeypot.morph import OSMorpher

logger = logging.getLogger('vitorius.honeypot.liquid')


class LiquidProtocolDecoy(BaseDecoy):
    """Multi-protocol synthesizer supporting FTP, SMTP, VNC, and RDP."""

    def __init__(
        self,
        name: str,
        protocol_type: str,
        internal_port: int,
        external_port: int,
        quarantine_engine,
        morpher: OSMorpher = None
    ):
        super().__init__(
            name=name,
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            timeout_sec=15.0
        )
        self.protocol_type = protocol_type.lower()
        self.morpher = morpher or OSMorpher('polymorphic')

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
            decoy_name=f"Liquid-{self.protocol_type.upper()}",
            event_type='port_probe',
            details=f"Probing {self.protocol_type.upper()} port ({self.external_port})",
            payload={'protocol': self.protocol_type}
        )

        if self.protocol_type == 'ftp':
            await self._handle_ftp(reader, writer, client_ip, client_port)
        elif self.protocol_type == 'smtp':
            await self._handle_smtp(reader, writer, client_ip, client_port)
        elif self.protocol_type == 'vnc':
            await self._handle_vnc(reader, writer, client_ip, client_port)
        elif self.protocol_type == 'rdp':
            await self._handle_rdp(reader, writer, client_ip, client_port)
        else:
            await self._handle_generic(reader, writer, client_ip, client_port)

    async def _handle_ftp(self, reader, writer, client_ip, client_port):
        banner = self.morpher.get_banner('ftp')
        writer.write(f"220 {banner} ready.\r\n".encode('utf-8'))
        await writer.drain()

        username = ""
        for _ in range(4):
            line = await reader.readline()
            if not line:
                break
            cmd = line.decode('utf-8', errors='ignore').strip()
            if cmd.upper().startswith('USER'):
                username = cmd.split(maxsplit=1)[1] if len(cmd.split()) > 1 else ""
                writer.write(b"331 Please specify the password.\r\n")
                await writer.drain()
            elif cmd.upper().startswith('PASS'):
                password = cmd.split(maxsplit=1)[1] if len(cmd.split()) > 1 else ""
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name="Liquid-FTP",
                    event_type='credential_attempt',
                    details=f"FTP login attempt (user: '{username}')",
                    payload={'credentials': {'service': 'ftp', 'username': username, 'password': password}}
                )
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
                break
            elif cmd.upper().startswith('QUIT'):
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"500 Unknown command.\r\n")
                await writer.drain()

    async def _handle_smtp(self, reader, writer, client_ip, client_port):
        banner = self.morpher.get_banner('smtp')
        writer.write(f"220 {banner}\r\n".encode('utf-8'))
        await writer.drain()

        for _ in range(5):
            line = await reader.readline()
            if not line:
                break
            cmd = line.decode('utf-8', errors='ignore').strip()
            if cmd.upper().startswith(('HELO', 'EHLO')):
                domain = cmd.split()[1] if len(cmd.split()) > 1 else "client"
                writer.write(f"250-mail.internal-corp.local Hello {domain}\r\n250-PIPELINING\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n".encode('utf-8'))
                await writer.drain()
            elif cmd.upper().startswith('AUTH'):
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name="Liquid-SMTP",
                    event_type='credential_attempt',
                    details=f"SMTP authentication attempt: {cmd}",
                    payload={'credentials': {'service': 'smtp', 'command': cmd}}
                )
                writer.write(b"535 5.7.8 Authentication credentials invalid\r\n")
                await writer.drain()
                break
            elif cmd.upper().startswith('QUIT'):
                writer.write(b"221 2.0.0 Service closing transmission channel\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 2.1.0 Ok\r\n")
                await writer.drain()

    async def _handle_vnc(self, reader, writer, client_ip, client_port):
        # 1. Send RFB Protocol Version (RFB 003.008)
        writer.write(b"RFB 003.008\n")
        await writer.drain()

        client_ver = await reader.readline()
        if not client_ver:
            return

        # 2. Send Security Types (1 type offered: Type 2 = VNC Authentication)
        writer.write(bytes([1, 2]))
        await writer.drain()

        # Read client selected security type
        sec_choice = await reader.read(1)
        if sec_choice:
            # Send 16-byte random challenge
            challenge = b'\x42' * 16
            writer.write(challenge)
            await writer.drain()

            # Read 16-byte response (encrypted with DES using password)
            response = await reader.read(16)
            if response:
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name="Liquid-VNC",
                    event_type='credential_attempt',
                    details="VNC graphical authentication challenge submitted",
                    payload={'credentials': {'service': 'vnc', 'response_len': len(response)}}
                )
                # Send SecurityResult: 1 = Failed
                writer.write(struct.pack('>I', 1))
                # Send error message
                err_msg = b"Authentication failed - session logged"
                writer.write(struct.pack('>I', len(err_msg)) + err_msg)
                await writer.drain()

    async def _handle_rdp(self, reader, writer, client_ip, client_port):
        # Read TPKT / X.224 Connection Request
        data = await reader.read(1024)
        if data and b'Cookie: mstshash=' in data:
            try:
                cookie_start = data.find(b'Cookie: mstshash=') + 17
                cookie_end = data.find(b'\r\n', cookie_start)
                if cookie_end == -1:
                    cookie_end = len(data)
                username = data[cookie_start:cookie_end].decode('utf-8', errors='ignore').rstrip('\x00')
            except Exception:
                username = "Administrator"

            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name="Liquid-RDP",
                event_type='credential_attempt',
                details=f"RDP connection request (cookie user: '{username}')",
                payload={'credentials': {'service': 'rdp', 'username': username}}
            )

        # Send standard X.224 Connection Confirm packet (11 bytes)
        # TPKT header (0x03, 0x00, 0x00, 0x0b) + X.224 header (0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00)
        x224_confirm = bytes([0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00])
        writer.write(x224_confirm)
        await writer.drain()

    async def _handle_generic(self, reader, writer, client_ip, client_port):
        data = await reader.read(512)
        if data:
            raw_text = ''.join(chr(b) for b in data if 32 <= b <= 126)
            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name=f"Liquid-{self.name}",
                event_type='port_probe',
                details=f"Raw probe on port {self.external_port}: '{raw_text[:40]}'",
                payload={'raw': raw_text[:80]}
            )
