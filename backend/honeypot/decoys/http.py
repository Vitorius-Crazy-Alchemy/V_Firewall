"""
Vitorius Firewall - Synthetic Web (HTTP) Decoy & Throttled Canary Vault Server
Emulates a Fedora web management interface, directory listings for staged canary files,
and serves honey-files with fixed-delay download throttling.
"""

import asyncio
import html as html_lib
import os
import time
import urllib.parse
from collections import defaultdict
from pathlib import Path
from backend.honeypot.decoys.base import BaseDecoy
from backend.honeypot.deflator import ScannerDeflator


class HttpDecoy(BaseDecoy):
    """Synthetic HTTP decoy web server with active fuzzer deflator defense."""

    def __init__(self, quarantine_engine, honeyfile_manager, internal_port: int = 12080, external_port: int = 80):
        super().__init__(
            name='HTTP',
            internal_port=internal_port,
            external_port=external_port,
            quarantine_engine=quarantine_engine,
            honeyfile_manager=honeyfile_manager,
            timeout_sec=30.0  # Allow longer timeout for throttled downloads
        )
        self._ip_hit_timestamps = defaultdict(list)
        self.deflator_enabled = True

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_ip: str,
        client_port: int
    ):
        # Read HTTP request line and headers
        request_line = await reader.readline()
        if not request_line:
            return

        req_str = request_line.decode('utf-8', errors='ignore').strip()
        parts = req_str.split()
        if len(parts) < 2:
            return

        method = parts[0].upper()
        path = parts[1]

        # Read headers
        headers = {}
        content_length = 0
        while True:
            line = await reader.readline()
            if not line or line in (b'\r\n', b'\n'):
                break
            h_str = line.decode('utf-8', errors='ignore').strip()
            if ':' in h_str:
                k, v = h_str.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        try:
            content_length = max(0, int(headers.get('content-length', 0)))
        except (ValueError, TypeError):
            content_length = 0
        body = b''
        if 0 < content_length < 65536:
            try:
                body = await reader.readexactly(content_length)
            except Exception:
                pass

        ua = headers.get('user-agent', 'Unknown')
        norm_path = urllib.parse.unquote(path).split('?')[0]

        # Track velocity for automated crawler / fuzzer detection (and prune stale IPs)
        now = time.time()
        if len(self._ip_hit_timestamps) > 1024:
            for ip_k in list(self._ip_hit_timestamps.keys()):
                recent = [t for t in self._ip_hit_timestamps[ip_k] if now - t < 3.0]
                if recent:
                    self._ip_hit_timestamps[ip_k] = recent
                else:
                    del self._ip_hit_timestamps[ip_k]
        self._ip_hit_timestamps[client_ip] = [t for t in self._ip_hit_timestamps[client_ip] if now - t < 3.0]
        self._ip_hit_timestamps[client_ip].append(now)
        recent_hits = len(self._ip_hit_timestamps[client_ip])

        # ── Route 0: Active Scanner Memory Tarpit (Deflator Bomb) ──
        if self.deflator_enabled and ScannerDeflator.is_scanner_fuzzer(headers, norm_path, recent_hits):
            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name='HTTP',
                event_type='exploit_url_probe',
                details=f"Fuzzer bot detected (UA: '{ua[:32]}', Hits: {recent_hits}). Dispatched recursive memory deflator bomb.",
                payload={'user_agent': ua, 'path': norm_path, 'deflator': True}
            )
            # Send chunked gzip deflator stream
            header_bytes = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.58 (Fedora Linux) OpenSSL/3.2.0\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Content-Encoding: gzip\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode('utf-8')
            writer.write(header_bytes)
            await writer.drain()

            async for chunk in ScannerDeflator.stream_deflator_bomb(chunk_count=50, delay_sec=0.04):
                try:
                    chunk_hdr = f"{len(chunk):X}\r\n".encode('ascii')
                    writer.write(chunk_hdr + chunk + b"\r\n")
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError):
                    break
            try:
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            return

        # ── Route 1: Canary File Download (Throttled Tarpit Transfer) ──
        if norm_path.startswith('/backups/') and len(norm_path) > 9:
            filename = os.path.basename(norm_path)
            file_path = self.honeyfiles.get_file_path(filename) if self.honeyfiles else None

            if file_path and file_path.exists():
                file_size = file_path.stat().st_size
                # Record high-severity exfiltration attempt
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name='HTTP',
                    event_type='canary_download',
                    details=f"Exfiltrating staged canary file '{filename}'",
                    payload={'filename': filename, 'size': file_size, 'user_agent': ua}
                )

                # Send HTTP headers for binary download
                resp_headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.58 (Fedora Linux) OpenSSL/3.2.0\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    f'Content-Disposition: attachment; filename="{filename}"\r\n'
                    f"Content-Length: {file_size}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                )
                writer.write(resp_headers.encode('utf-8'))
                await writer.drain()

                # Stream file with artificial delay (~40 KB/s)
                async for chunk in self.honeyfiles.stream_file_throttled(filename, chunk_size=4096, delay_sec=0.1):
                    try:
                        writer.write(chunk)
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break
                return

        # ── Route 2: Directory Listing for Canary Backups ──
        if norm_path in ('/backups', '/backups/'):
            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name='HTTP',
                event_type='port_probe',
                details="Browsing /backups directory index",
                payload={'path': norm_path, 'user_agent': ua}
            )

            files_html = ""
            if self.honeyfiles:
                for f in self.honeyfiles.list_files():
                    safe_name = html_lib.escape(f["filename"])
                    safe_size = html_lib.escape(f["size_formatted"])
                    safe_desc = html_lib.escape(f["description"])
                    files_html += (
                        f'<tr><td><a href="/backups/{safe_name}">{safe_name}</a></td>'
                        f'<td align="right">{safe_size}</td>'
                        f'<td>{safe_desc}</td></tr>\n'
                    )

            html = f"""<!DOCTYPE HTML>
<html>
<head><title>Index of /backups</title></head>
<body>
<h1>Index of /backups</h1>
<hr>
<table width="100%">
<tr><th align="left">Name</th><th align="right">Size</th><th align="left">Description</th></tr>
<tr><td colspan="3"><hr></td></tr>
{files_html}
<tr><td colspan="3"><hr></td></tr>
</table>
<address>Apache/2.4.58 (Fedora Linux) Server at {client_ip} Port {self.external_port}</address>
</body></html>"""
            resp = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.58 (Fedora Linux) OpenSSL/3.2.0\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n"
                f"Content-Length: {len(html.encode('utf-8'))}\r\n"
                "Connection: close\r\n\r\n" + html
            )
            writer.write(resp.encode('utf-8'))
            await writer.drain()
            return

        # ── Route 3: Exploit Probe Paths (.env, .git, wp-login, etc.) ──
        exploit_traps = {
            '/.env': "DB_CONNECTION=pgsql\nDB_HOST=127.0.0.1\nDB_PORT=5432\nDB_DATABASE=prod_finance\nDB_USERNAME=postgres\nDB_PASSWORD=VitoriusFw_Canary_Token_x9a8b\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n",
            '/.git/config': "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:internal-corp/secure-vault.git\n",
            '/wp-login.php': "<html><head><title>WordPress &rsaquo; Log In</title></head><body><h1>Administrative Login</h1></body></html>",
            '/phpmyadmin': "<html><head><title>phpMyAdmin</title></head><body><h1>Access Denied</h1></body></html>",
            '/actuator/health': '{"status":"UP","components":{"db":{"status":"UP"}}}',
        }

        for trap_path, trap_content in exploit_traps.items():
            if norm_path.startswith(trap_path):
                self.quarantine.record_interaction(
                    ip=client_ip,
                    source_port=client_port,
                    target_port=self.external_port,
                    decoy_name='HTTP',
                    event_type='exploit_url_probe',
                    details=f"Probing vulnerability path: {norm_path}",
                    payload={'path': norm_path, 'user_agent': ua}
                )
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.58 (Fedora Linux)\r\n"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    f"Content-Length: {len(trap_content.encode('utf-8'))}\r\n"
                    "Connection: close\r\n\r\n" + trap_content
                )
                writer.write(resp.encode('utf-8'))
                await writer.drain()
                return

        # ── Route 4: POST /login (Credential Harvesting) ──
        if method == 'POST' and '/login' in norm_path:
            body_str = body.decode('utf-8', errors='ignore')
            parsed = urllib.parse.parse_qs(body_str)
            username = parsed.get('username', parsed.get('user', ['']))[0]
            password = parsed.get('password', parsed.get('pass', ['']))[0]

            self.quarantine.record_interaction(
                ip=client_ip,
                source_port=client_port,
                target_port=self.external_port,
                decoy_name='HTTP',
                event_type='credential_attempt',
                details=f"Web login attempt (user: '{username}')",
                payload={'credentials': {'service': 'http', 'username': username, 'password': password}, 'user_agent': ua}
            )

            html = "<html><body><h3>401 Unauthorized: Invalid operator credentials</h3></body></html>"
            resp = (
                "HTTP/1.1 401 Unauthorized\r\n"
                "Server: Apache/2.4.58 (Fedora Linux)\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(html.encode('utf-8'))}\r\n"
                "Connection: close\r\n\r\n" + html
            )
            writer.write(resp.encode('utf-8'))
            await writer.drain()
            return

        # ── Route 5: Root Dashboard / Admin Landing Page ──
        self.quarantine.record_interaction(
            ip=client_ip,
            source_port=client_port,
            target_port=self.external_port,
            decoy_name='HTTP',
            event_type='port_probe',
            details=f"GET {norm_path}",
            payload={'path': norm_path, 'user_agent': ua}
        )

        landing_html = """<!DOCTYPE html>
<html>
<head><title>Fedora Linux Administration Portal</title></head>
<body style="font-family: sans-serif; background: #0c1017; color: #e6edf3; padding: 40px; text-align: center;">
  <h2>Fedora Management Gateway</h2>
  <p style="color: #8b949e;">Internal Infrastructure Node #41 &bull; Linux 6.11.4-200.fc41</p>
  <div style="max-width: 380px; margin: 40px auto; padding: 24px; background: #161b22; border: 1px solid #30363d; border-radius: 8px;">
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Operator Username" style="width: 90%; padding: 8px; margin-bottom: 12px; border-radius: 4px; border: 1px solid #30363d; background: #0d1117; color: #fff;"><br>
      <input type="password" name="password" placeholder="Passphrase" style="width: 90%; padding: 8px; margin-bottom: 16px; border-radius: 4px; border: 1px solid #30363d; background: #0d1117; color: #fff;"><br>
      <button type="submit" style="width: 95%; padding: 8px; background: #238636; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">Sign In to Cockpit</button>
    </form>
  </div>
  <p style="font-size: 12px; color: #484f58;">Authorized Administrative Personnel Only. Audit logging is active.</p>
</body>
</html>"""
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.58 (Fedora Linux) OpenSSL/3.2.0\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(landing_html.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n" + landing_html
        )
        writer.write(resp.encode('utf-8'))
        await writer.drain()
