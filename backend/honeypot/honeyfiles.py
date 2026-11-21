"""
Vitorius Firewall - Honey-File & Canary Vault System
Generates and stages authentic-looking encrypted files (KeePass, OpenPGP, OpenSSL)
to deceive attackers into believing they have compromised a real workstation or server.
"""

import os
import struct
import logging
from pathlib import Path
from typing import AsyncGenerator, Optional
import asyncio

logger = logging.getLogger('vitorius.honeypot.honeyfiles')

BASE_STORAGE = Path(__file__).resolve().parent.parent.parent / '.storage'

try:
    DEFAULT_VAULT_DIR = Path.home() / '.local' / 'share' / 'vitorius-firewall' / 'honeypot' / 'canary_vault'
    DEFAULT_VAULT_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    DEFAULT_VAULT_DIR = BASE_STORAGE / 'honeypot' / 'canary_vault'


def generate_kdbx_file(target_path: Path, size_kb: int = 350) -> bool:
    """Generate a realistic KeePass v4.0 Database (.kdbx) file."""
    try:
        # Magic signatures for KeePass KDBX
        sig1 = struct.pack('<I', 0x9AA2D903)
        sig2 = struct.pack('<I', 0xB54BBF67)
        ver = struct.pack('<I', 0x00040000)  # KDBX 4.0

        # KDBX 4 Header fields:
        # Field 02 (Cipher ID: AES-256 UUID)
        cipher_uuid = bytes.fromhex('31c1f2e6bf714350be5805216afc5aff')
        f_cipher = bytes([0x02]) + struct.pack('<I', len(cipher_uuid)) + cipher_uuid

        # Field 03 (Compression: Gzip)
        f_comp = bytes([0x03]) + struct.pack('<I', 4) + struct.pack('<I', 1)

        # Field 04 (Master Seed: 32 random bytes)
        master_seed = os.urandom(32)
        f_master = bytes([0x04]) + struct.pack('<I', len(master_seed)) + master_seed

        # Field 07 (Encryption IV: 16 random bytes)
        enc_iv = os.urandom(16)
        f_iv = bytes([0x07]) + struct.pack('<I', len(enc_iv)) + enc_iv

        # Field 00 (End of Header marker: 0x0D 0x0A 0x0D 0x0A)
        f_end = bytes([0x00]) + struct.pack('<I', 4) + b'\r\n\r\n'

        header = sig1 + sig2 + ver + f_cipher + f_comp + f_master + f_iv + f_end
        
        # Fill rest with pseudo-random ciphertext payload
        needed_payload = max(1024, (size_kb * 1024) - len(header))
        payload = os.urandom(needed_payload)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'wb') as f:
            f.write(header + payload)
        return True
    except Exception as e:
        logger.error(f"Failed to generate KDBX honey-file {target_path}: {e}")
        return False


def generate_gpg_file(target_path: Path, size_kb: int = 1200) -> bool:
    """Generate a realistic OpenPGP symmetrically encrypted archive (.sql.gpg)."""
    try:
        # Tag 3: Symmetric-Key Encrypted Session Key packet (old packet header 0x8C, length 13)
        # version=4, cipher=9 (AES256), s2k=3 (Iterated & Salted), hash=2 (SHA1), 8-byte salt, count=96
        tag3 = bytes([0x8C, 13, 4, 9, 3, 2]) + os.urandom(8) + bytes([96])

        # Tag 18: Symmetrically Encrypted and Integrity Protected Data Packet (header 0xD2)
        tag18_hdr = bytes([0xD2, 0x40, 1])

        header = tag3 + tag18_hdr
        needed_payload = max(1024, (size_kb * 1024) - len(header))
        payload = os.urandom(needed_payload)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'wb') as f:
            f.write(header + payload)
        return True
    except Exception as e:
        logger.error(f"Failed to generate GPG honey-file {target_path}: {e}")
        return False


def generate_openssl_enc_file(target_path: Path, size_kb: int = 650) -> bool:
    """Generate a realistic OpenSSL AES-256-CBC encrypted archive (.enc)."""
    try:
        # Standard OpenSSL header: 'Salted__' + 8-byte salt + AES ciphertext
        salt = os.urandom(8)
        header = b'Salted__' + salt

        needed_payload = max(1024, (size_kb * 1024) - len(header))
        # Ensure block size is a multiple of 16
        needed_payload = (needed_payload // 16) * 16
        payload = os.urandom(needed_payload)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'wb') as f:
            f.write(header + payload)
        return True
    except Exception as e:
        logger.error(f"Failed to generate OpenSSL honey-file {target_path}: {e}")
        return False


def generate_pkcs8_enc_file(target_path: Path) -> bool:
    """Generate an authentic-looking PKCS#8 encrypted private key PEM file."""
    try:
        import base64
        # Generate 1400 bytes of pseudo DER encrypted private key info
        fake_der = os.urandom(1280)
        b64 = base64.b64encode(fake_der).decode('ascii')
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END ENCRYPTED PRIVATE KEY-----\n"

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as f:
            f.write(pem)
        return True
    except Exception as e:
        logger.error(f"Failed to generate PEM honey-file {target_path}: {e}")
        return False


class HoneyFileManager:
    """Manages the lifecycle of staged encrypted canary files and throttled streaming."""

    DECOY_CATALOG = [
        {
            'filename': 'passwords_corporate.kdbx',
            'type': 'kdbx',
            'size_kb': 380,
            'description': 'Enterprise KeePass 4.0 Password Vault',
            'generator': generate_kdbx_file,
        },
        {
            'filename': 'database_backup_production.sql.gpg',
            'type': 'gpg',
            'size_kb': 1850,
            'description': 'Production PostgreSQL/MySQL GPG Encrypted Dump',
            'generator': generate_gpg_file,
        },
        {
            'filename': 'q3_financials_encrypted.tar.gz.enc',
            'type': 'openssl',
            'size_kb': 720,
            'description': 'Q3 Financial Ledgers & Payroll (AES-256-CBC)',
            'generator': generate_openssl_enc_file,
        },
        {
            'filename': 'corporate_vpn_profiles.ovpn.enc',
            'type': 'openssl',
            'size_kb': 160,
            'description': 'Encrypted OpenVPN Client Configurations',
            'generator': generate_openssl_enc_file,
        },
        {
            'filename': 'id_ed25519_production.key.enc',
            'type': 'pkcs8',
            'size_kb': 2,
            'description': 'Production Infrastructure SSH Private Key (PKCS#8)',
            'generator': generate_pkcs8_enc_file,
        },
        {
            'filename': 'aws_cloud_vault.kdbx',
            'type': 'kdbx',
            'size_kb': 240,
            'description': 'AWS IAM & S3 Access Key Database',
            'generator': generate_kdbx_file,
        },
    ]

    def __init__(self, vault_dir: Optional[Path] = None):
        self.vault_dir = vault_dir or DEFAULT_VAULT_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.ensure_staged_vault()

    def ensure_staged_vault(self):
        """Ensure all staged decoy files exist with realistic attributes."""
        for item in self.DECOY_CATALOG:
            target = self.vault_dir / item['filename']
            if not target.exists() or target.stat().st_size == 0:
                gen_fn = item['generator']
                if item['type'] in ('kdbx', 'gpg', 'openssl'):
                    gen_fn(target, item['size_kb'])
                else:
                    gen_fn(target)
                logger.info(f"Staged encrypted canary file created: {target.name}")

    def list_files(self) -> list[dict]:
        """Return list of staged canary files with sizes and metadata."""
        results = []
        for item in self.DECOY_CATALOG:
            path = self.vault_dir / item['filename']
            size = path.stat().st_size if path.exists() else (item['size_kb'] * 1024)
            results.append({
                'filename': item['filename'],
                'type': item['type'],
                'size_bytes': size,
                'size_formatted': f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.2f} MB",
                'description': item['description'],
                'path': str(path),
                'exists': path.exists()
            })
        return results

    def get_file_path(self, filename: str) -> Optional[Path]:
        """Safely lookup path for a staged canary file, preventing traversal."""
        clean_name = os.path.basename(filename)
        candidate = self.vault_dir / clean_name
        if candidate.exists() and candidate.is_file():
            return candidate
        return None

    async def stream_file_throttled(
        self,
        filename: str,
        chunk_size: int = 4096,
        delay_sec: float = 0.1
    ) -> AsyncGenerator[bytes, None]:
        """
        Stream a canary file with artificial delay to throttle attacker exfiltration.
        At chunk_size=4096 and delay_sec=0.1, the transfer rate is ~40 KB/s.
        """
        path = self.get_file_path(filename)
        if not path:
            return

        with open(path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
                await asyncio.sleep(delay_sec)
