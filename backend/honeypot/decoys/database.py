"""
Vitorius Firewall - Synthetic Database Decoy (MySQL & Redis)
Simulates authentic database protocol handshakes and harvests unauthorized credentials.
"""

import asyncio
import struct
import logging
from backend.honeypot.decoys.base import BaseDecoy

logger = logging.getLogger('vitorius.honeypot.database')


class MySqlDecoy(BaseDecoy):
    """Synthetic MySQL Protocol 10 handshake and auth trap."""

    def __init__(self, quarantine_engine, internal_port: int = 12306, external_port: int = 3306):
        super().__init__(
            name='MySQL',
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
        # Record initial probe
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='MySQL',
            event_type='port_probe',
            details="Connected to MySQL database port",
            payload={}
        )

        # Build MySQL Protocol 10 Initial Handshake Packet
        server_ver = b"8.0.36-commercial\x00"
        thread_id = struct.pack('<I', 42)
        scramble_1 = b"12345678"
        scramble_2 = b"123456789012\x00"
        caps_low = struct.pack('<H', 0xF7FF)
        charset = bytes([33])  # utf8_general_ci
        status = struct.pack('<H', 0x0002)  # SERVER_STATUS_AUTOCOMMIT
        caps_high = struct.pack('<H', 0x81FF)
        auth_len = bytes([21])
        reserved = b'\x00' * 10
        auth_plugin = b"caching_sha2_password\x00"

        body = (
            bytes([10]) + server_ver + thread_id + scramble_1 + bytes([0]) +
            caps_low + charset + status + caps_high + auth_len + reserved +
            scramble_2 + auth_plugin
        )

        pkt_len = len(body)
        header = struct.pack('<I', pkt_len)[:3] + bytes([0])  # length + seq 0
        writer.write(header + body)
        await writer.drain()

        # Read client Handshake Response Packet
        resp_hdr = await reader.read(4)
        if len(resp_hdr) < 4:
            return

        client_pkt = await reader.read(1024)
        if client_pkt and len(client_pkt) > 32:
            # Username starts after client caps (4) + max pkt (4) + charset (1) + reserved (23) = 32
            user_slice = client_pkt[32:]
            null_pos = user_slice.find(b'\x00')
            username = user_slice[:null_pos].decode('utf-8', errors='ignore') if null_pos != -1 else "unknown"

            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name='MySQL',
                event_type='credential_attempt',
                details=f"MySQL authentication attempt (user: '{username}')",
                payload={'credentials': {'service': 'mysql', 'username': username}}
            )

            # Send ER_ACCESS_DENIED_ERROR (1045, 28000)
            err_msg = f"Access denied for user '{username}'@'{client_ip}' (using password: YES)\x00".encode('utf-8')
            err_body = bytes([0xFF]) + struct.pack('<H', 1045) + b"#28000" + err_msg
            err_hdr = struct.pack('<I', len(err_body))[:3] + bytes([2])
            writer.write(err_hdr + err_body)
            await writer.drain()


class RedisDecoy(BaseDecoy):
    """Synthetic Redis RESP protocol decoy."""

    def __init__(self, quarantine_engine, internal_port: int = 12379, external_port: int = 6379):
        super().__init__(
            name='Redis',
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
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='Redis',
            event_type='port_probe',
            details="Connected to Redis caching port",
            payload={}
        )

        # Read line or RESP commands
        for _ in range(5):
            line = await reader.readline()
            if not line:
                break
            cmd_str = line.decode('utf-8', errors='ignore').strip()

            if 'PING' in cmd_str.upper():
                writer.write(b"+PONG\r\n")
                await writer.drain()
            elif 'AUTH' in cmd_str.upper():
                # Extract attempted password
                parts = cmd_str.split()
                pwd = parts[1] if len(parts) > 1 else ""
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name='Redis',
                    event_type='credential_attempt',
                    details=f"Redis AUTH attempt",
                    payload={'credentials': {'service': 'redis', 'password': pwd}}
                )
                writer.write(b"-ERR invalid password\r\n")
                await writer.drain()
            else:
                writer.write(b"-NOAUTH Authentication required.\r\n")
                await writer.drain()
