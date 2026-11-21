"""
Vitorius Firewall - Synthetic SMB / NetBIOS Decoy
Emulates SMB2 Negotiate responses, advertises canary shares,
and logs NTLMSSP authentication probes and machine names.
"""

import asyncio
import struct
import logging
from backend.honeypot.decoys.base import BaseDecoy

logger = logging.getLogger('vitorius.honeypot.smb')


class SmbDecoy(BaseDecoy):
    """Synthetic SMB2 decoy server."""

    def __init__(self, quarantine_engine, honeyfile_manager=None, internal_port: int = 12445, external_port: int = 445):
        super().__init__(
            name='SMB',
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            honeyfile_manager=honeyfile_manager,
            timeout_sec=15.0
        )

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        # Read NetBIOS header (4 bytes)
        netbios_hdr = await reader.read(4)
        if len(netbios_hdr) < 4:
            return

        # Read SMB packet
        packet = await reader.read(1024)
        if not packet:
            return

        is_smb2 = (len(packet) >= 4 and packet[:4] == b'\xfeSMB')
        is_smb1 = (len(packet) >= 4 and packet[:4] == b'\xffSMB')

        protocol_version = "SMB2" if is_smb2 else ("SMB1" if is_smb1 else "RawNetBIOS")

        # Record probe
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='SMB',
            event_type='port_probe',
            details=f"Probing {protocol_version} share service",
            payload={'protocol': protocol_version}
        )

        # If SMB2, construct an authentic SMB2 Negotiate Response
        if is_smb2:
            try:
                # SMB2 Header (64 bytes)
                # Protocol ID: \xfeSMB, StructureSize: 64, CreditCharge: 0, Status: SUCCESS (0)
                # Command: NEGOTIATE (0), Credits: 1, Flags: Response (0x01)
                smb2_hdr = struct.pack(
                    '<4sHHIIHHIQQ16s',
                    b'\xfeSMB', 64, 0, 0, 0, 1, 0x00000001, 0, 0, 0, b'\x00' * 16
                )
                # Negotiate Response Body (65 bytes)
                # StructureSize: 65, SecurityMode: 0x01 (signing enabled), DialectRevision: 0x0210
                # ServerGuid: 16 random bytes
                neg_body = struct.pack(
                    '<HH16sII16sII',
                    65, 0x01, b'\x00' * 16, 0x0210, 0, b'\x12' * 16, 0, 0
                )
                total_len = len(smb2_hdr) + len(neg_body)
                netbios_resp = struct.pack('>I', total_len)

                writer.write(netbios_resp + smb2_hdr + neg_body)
                await writer.drain()

                # Read subsequent Session Setup packet (often contains NTLMSSP)
                subsequent = await reader.read(2048)
                if b'NTLMSSP' in subsequent:
                    # Extract readable ASCII text from NTLMSSP
                    ascii_strings = [
                        subsequent[i:i+32].decode('ascii', errors='ignore')
                        for i in range(len(subsequent) - 32)
                        if subsequent[i:i+4] == b'NTLM'
                    ]
                    self.quarantine.record_interaction(
                        ip=client_ip,
                        source_port=client_port,
                        target_port=self.external_port,
                        decoy_name='SMB',
                        event_type='credential_attempt',
                        details="NTLMSSP Authentication probe on \\\\VITORIUS\\Backups",
                        payload={'credentials': {'service': 'smb', 'ntlm_auth': True}}
                    )
            except Exception as e:
                logger.debug(f"Error in SMB2 handshake response: {e}")
