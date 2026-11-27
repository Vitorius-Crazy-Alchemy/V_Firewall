"""
Vitorius Firewall - Decoy Base Class
Provides asynchronous lifecycle management, concurrency capping,
and automated connection wrapping for honeypot protocol emulators.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger('vitorius.honeypot.decoy')


class BaseDecoy(ABC):
    """Abstract base class for all synthetic honeypot services."""

    def __init__(
        self,
        name: str,
        internal_port: int,
        external_port: int,
        quarantine_engine,
        honeyfile_manager=None,
        max_connections: int = 64,
        timeout_sec: float = 15.0
    ):
        self.name = name
        self.internal_port = internal_port
        self.external_port = external_port
        self.quarantine = quarantine_engine
        self.honeyfiles = honeyfile_manager
        self.max_connections = max_connections
        self.timeout_sec = timeout_sec

        self.server: Optional[asyncio.Server] = None
        self.active_conns = 0
        self.is_running = False

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        """Protocol-specific emulation logic to be implemented by subclasses."""
        pass

    async def start(self):
        """Start unprivileged async TCP listener."""
        try:
            self.server = await asyncio.start_server(
                self._conn_wrapper, '0.0.0.0', self.internal_port
            )
            self.is_running = True
            logger.info(f"Decoy [{self.name}] listening on port {self.internal_port} (for ext {self.external_port})")
        except Exception as e:
            logger.error(f"Failed to bind decoy [{self.name}] on port {self.internal_port}: {e}")
            self.is_running = False

    async def stop(self):
        """Stop listener and close active sockets."""
        self.is_running = False
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
            self.server = None
        logger.info(f"Decoy [{self.name}] stopped.")

    async def _conn_wrapper(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Enforces concurrency limits, socket timeouts, and exception containment."""
        peer = writer.get_extra_info('peername')
        if not peer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        client_ip, client_port = peer[0], peer[1]

        # Prevent resource exhaustion DoS
        if self.active_conns >= self.max_connections:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        self.active_conns += 1
        try:
            # Wrap client connection with timeout
            await asyncio.wait_for(
                self.handle_connection(reader, writer, client_ip, client_port),
                timeout=self.timeout_sec
            )
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Error handling connection in {self.name}: {e}")
        finally:
            self.active_conns -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
