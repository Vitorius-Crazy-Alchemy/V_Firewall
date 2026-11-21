"""
Vitorius Firewall - Active Scanner Deflator (Memory Tarpit)
Generates real-time recursive chunked Gzip streams against automated vulnerability fuzzers
and directory brute-forcers, exhausting client-side parser memory without using host resources.
"""

import zlib
import asyncio
import logging
from typing import AsyncGenerator

logger = logging.getLogger('vitorius.honeypot.deflator')


class ScannerDeflator:
    """
    Active defense against automated vulnerability scanners (Nikto, DirBuster, Sqlmap, Fuzzers).
    Streams highly compressed null bytes encoded with Content-Encoding: gzip.
    Over the wire: ~100 KB.
    In the attacker scanner's memory: Expands to > 100 MB, freezing or crashing their crawler.
    """

    @staticmethod
    def is_scanner_fuzzer(headers: dict, path: str, hit_count_in_window: int = 0) -> bool:
        """Detect automated scanners and aggressive fuzzer bots."""
        ua = headers.get('user-agent', '').lower()
        scanner_signatures = [
            'sqlmap', 'nikto', 'dirbuster', 'gobuster', 'fuzz', 'wfuzz',
            'nuclei', 'nmap', 'masscan', 'acunetix', 'nessus', 'zgrab',
            'burp', 'zap', 'hydra', 'python-requests', 'aiohttp', 'curl'
        ]
        if any(sig in ua for sig in scanner_signatures):
            return True

        # Check for rapid directory fuzzing (e.g. > 4 requests in 2 seconds)
        if hit_count_in_window >= 4:
            return True

        # Check for deep traversal or exploit fuzzer patterns
        fuzz_markers = ['..%2f', '..\\', '<script', 'union+select', 'select+1', 'etc/passwd', 'win.ini']
        if any(marker in path.lower() for marker in fuzz_markers):
            return True

        return False

    @staticmethod
    async def stream_deflator_bomb(
        chunk_count: int = 150,
        chunk_uncompressed_bytes: int = 65536,
        delay_sec: float = 0.05
    ) -> AsyncGenerator[bytes, None]:
        """
        Streams a valid Gzip HTTP chunked payload where each chunk expands 1000x in client RAM.
        Total uncompressed expansion: ~10 MB - 100 MB in client RAM.
        Total transmitted bandwidth: Less than 50 KB.
        """
        # wbits=31 instructs zlib to generate standard Gzip headers and trailer
        compressor = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=31)
        zeros_block = b'\x00' * chunk_uncompressed_bytes

        # First chunk contains gzip header + initial compressed zeros
        initial_compressed = compressor.compress(zeros_block)
        if initial_compressed:
            yield initial_compressed
            await asyncio.sleep(delay_sec)

        for _ in range(chunk_count):
            compressed_chunk = compressor.compress(zeros_block)
            if compressed_chunk:
                yield compressed_chunk
                await asyncio.sleep(delay_sec)

        # Flush final gzip trailer
        final_bytes = compressor.flush()
        if final_bytes:
            yield final_bytes
