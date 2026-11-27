# V Firewall (v3.0 — Codename: GEOS)

**V Firewall** is a Linux desktop security management suite built with **Python 3**, **GTK 4**, and **Libadwaita**. Rather than replacing Linux packet filtering, it acts as a desktop control plane around **`firewalld`** (`firewall-cmd` and read-only D-Bus), **`nftables`**, **`systemd`/cgroups**, **`iproute2` (`ss`/`ip`)**, **`flatpak`**, and **Polkit (`pkexec`)**, combined with real-time socket monitoring, process ancestry auditing (**LineageGuard**), offline IPSet geo-blocking, kernel log IDS monitoring, and an unprivileged async **Deception & Honeypot** engine.

> **Version:** `3.0` (`GEOS`) • **Package Version:** `3.0.0` • **Author:** Vitorius • **License:** [MIT](LICENSE)

---

## What's New in v3.0 (GEOS)

- **LineageGuard Live Enforcement (`LineageEnforcer`)**: Connects `NetworkMonitor` snapshots to `/proc/[pid]` process-tree analysis (`LineageResolver`) and policy rules (`LineagePolicyEngine`). When an unsanctioned current-user process tree initiates external network traffic, its process group can be micro-frozen via `SIGSTOP` (`ProcessFreezer`) and triaged interactively (`Grant Lease`, `Trust Lineage`, or `Terminate & Block`).
- **Country Geo-Blocking (`GeoBlockManager`)**: Builds `firewalld` `hash:net` IPSets (`vfw_geo_<CC>`) and zone drop rich rules from local IPv4 `.zone` files (`~/.local/share/v-firewall/geoip/`, `/usr/share/GeoIP/`, `/var/lib/GeoIP/`) with built-in offline fallback CIDRs (`CN`, `RU`, `KP`, `IR`, `SY`, `CU`), automatically cleaned up across zones when switching profiles.
- **IDS Kernel Log Monitor (`IdsLogMonitor`)**: Streams `journalctl -k -f -n 0 -o cat` when an IDS-enabled profile (`Corporate`, `Maximum Security`) is active, detecting port-scan and denied-packet bursts and logging/alerting with per-IP cooldowns.
- **Native `firewalld` D-Bus Read Path (`FirewallDbusClient`)**: Queries zones, active zones, default zone, panic state, and `getZoneSettings2` over `org.fedoraproject.FirewallD1` via `Gio.DBusProxy`, automatically falling back to `firewall-cmd` if D-Bus is unavailable.
- **Allowlisted Privileged Helper & Polkit Policy**: Adds `backend/privileged_helper.py` and `policy/com.v.firewall.policy` (`com.v.firewall.pkexec.helper`) so structured JSON rule operations run via `argv` lists (`shell=False`) instead of raw shell snippets when installed via `install.sh --install-policy`.

---

## What This App Actually Does

### 1. Core Firewall Orchestration (`backend/core.py`)
- **Zones, Services, Ports & Rich Rules**: Reads and modifies `firewalld` runtime and `--permanent` rules, NAT masquerading, ICMP block rules/inversion, port forwarding, and rate limits.
- **Transactional Write Batching**: Groups multi-step configuration changes into a single `pkexec` prompt (`execute_batch` / `execute_structured`) with per-instance response caching and cache invalidation.
- **IP & CIDR Blocking**: Validates IPv4/IPv6 addresses and CIDRs via Python `ipaddress`, rejects traffic in both zone rich rules (`source`/`destination`) and `--direct` `INPUT`/`OUTPUT` chains, and terminates active sockets via `ss -K`.
- **Multi-Layer Application Blocking (`block_application` / `block_app`)**: Blocking a service or desktop application does not rely on a single mechanism:
  - Kills active application sockets with `ss -K`.
  - Applies Flatpak network restrictions (`flatpak override --unshare=network` and `flatpak kill`) for discovered Flatpak apps.
  - Injects `iptables` cgroup path (`-m cgroup --path ...`) and `systemctl [--user] set-property --runtime ... IPAddressDeny=any` constraints while skipping protected system units (`init.scope`, `systemd-`, `dbus`, `NetworkManager`, `polkit`, `firewalld`, session scopes).
  - Applies UID owner blocks only for non-interactive dedicated service UIDs (`uid != os.getuid()`).
- **Panic Lockdown Mode**: Runs `firewall-cmd --panic-on` / `--panic-off` to cut or restore all host network traffic immediately from the GUI header, system tray menu, or CLI (`--unpanic`).
- **Rule Snapshots**: Exports all zone configurations to versioned JSON (`version: "3.0"`, `codename: "GEOS"`) and imports backups compatible with versions `1.0` through `3.0`.

### 2. Security Profiles & Geo/IDS Automation (`backend/profiles.py`, `data/default_config.json`)
- **Clean Fresh Install**: Starts with **no active profile** (`active_profile: ""`) so existing system firewall rules are never overwritten until you explicitly activate a tier. Switching profiles backs up current rules automatically before applying a clean slate for that profile's target zone:

| Profile | Target Zone | Tier | Included Rules & Security Controls |
| :--- | :--- | :--- | :--- |
| **Home** | `home` | Standard | Allows `dhcpv6-client`, `mdns`, `samba-client`, `ssh`; minimal logging |
| **Public** | `public` | Standard | Allows `dhcpv6-client`; `log-denied=all` |
| **Corporate** | `work` | Premium | Compliance `SOC2`; allows `dhcpv6-client`, `dns`, `https` + TCP `443`, `8443`; `log-denied=all`, ICMP block inversion, `10/m` rate limiting, Geo-Block (`CN`, `RU`, `KP`, `IR`), IDS kernel monitor |
| **Gaming** | `home` | Standard | Allows `dhcpv6-client`, `mdns` + Steam/STUN/VOIP ports (`27015-27030/tcp+udp`, `3478-3480/udp`, `27000-27100/udp`, `4380/udp`) |
| **Maximum Security** | `drop` | Premium | Compliance `HIPAA`; zero services allowed; outbound/explicit ports `443/tcp`, `53/udp`; `log-denied=all`, ICMP block inversion, `10/m` rate limiting, Geo-Block (`CN`, `RU`, `KP`, `IR`, `SY`, `CU`), IDS kernel monitor |

- `ProfileManager` also supports programmatic creation, duplication, update, and deletion of custom profiles in `config.json`.

### 3. Live Network Monitor & Bandwidth Tracker (`backend/monitor.py`)
- Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6` (plus `psutil` fallback) in a background polling loop to build cached `ConnectionInfo` snapshots (protocol, local/remote endpoints, port service label, socket state, PID, and process name) while skipping unspecified wildcard sockets.
- Computes per-interface RX/TX throughput and byte totals directly from `/proc/net/dev` (`BandwidthTracker`, excluding `lo`).

### 4. Service & Application Discovery (`backend/scanner.py`)
- Inventories running system daemons, `firewalld` XML service definitions (`/usr/lib/firewalld/services`, `/etc/firewalld/services`), `systemd` units, listening sockets, Flatpak applications (with sandbox override inspection), and desktop `.desktop` entries so users can toggle access without writing manual `firewall-cmd` commands.

### 5. LineageGuard (`backend/lineage/`)
- **Ancestry Reconstruction (`resolver.py`)**: Walks parent PIDs from `/proc/[pid]` up to PID `1`, checking `starttime` to stop on PID-reuse races, and builds a SHA-256 chain hash from executable paths and UIDs. Recognizes terminal emulators (such as `ptyxis`, `konsole`, `alacritty`, `kitty`, `wezterm-gui`, `foot`, `tilix`, `xterm`, `kgx`, `gnome-terminal-`, etc.), shells, dev tools, and browsers.
- **Anomaly Detection (`policy.py` & `enforcer.py`)**: Evaluates non-loopback `ESTABLISHED` / `SYN_SENT` / `ACTIVE` sockets for the current user UID and flags:
  - `DEV_SUPPLY_CHAIN_ANOMALY` (e.g., `npm`, `node`, `pip`, `cargo`, `gem`, `composer` spawning `curl`, `wget`, `nc`, `python`, `ssh`, `bash`, etc.)
  - `BROWSER_ESCAPE_SPAWN` (browsers spawning shells or network tools)
  - `HIDDEN_EXEC_ANOMALY` (binaries running from `/tmp`, `/var/tmp`, `/dev/shm`, or `/.cache/`)
  - `UNSANCTIONED_LINEAGE`
- **Micro-Freezing & Ephemeral Leases (`freezer.py`, `leases.py`)**: Suspends or terminates offending process groups (`SIGSTOP` / `SIGCONT` / `SIGKILL`), stores approved lineage hashes in `lineage_trust.json`, and manages temporary non-permanent `firewalld` runtime rich rules across 4 presets (`5m`, `15m` default, `1h`, or `Process Lifetime`), automatically reaping rules and killing sockets (`ss -K`) on expiration or PID exit.

### 6. Deception Engine & Honeypot (`backend/honeypot/`)
- **Unprivileged Async Listeners (`engine.py`)**: Runs `asyncio` TCP decoys bound to high unprivileged ports (`12000`–`12590`), optionally paired with `firewalld` port redirection via `HoneypotArbiter`:
  - **Static Decoys**: `SSH` (`22` → `12022`), `HTTP` (`80` → `12080`), `SMB` (`445` → `12445`), `Telnet` (`23` → `12023`), `MySQL` (`3306` → `12306`), `Redis` (`6379` → `12379`), and `Sticky TCP Tarpit` (`8888` → `12000`, trickling 1 byte every 8s).
  - **Liquid Protocol Fabric (`liquid.py`)**: Synthesizes handshakes and harvests credential probes on `FTP` (`21` → `12021`), `SMTP` (`25` → `12025`), `VNC` (`5900` → `12590`), and `RDP` (`3389` → `12389`).
- **Collision Arbitration (`arbiter.py`)**: Verifies target external ports against `ServiceAppScanner`, `NetworkMonitor`, and `ss -Htlun` before configuring `firewalld` port forwards so real local daemons are never overridden.
- **Anti-Reconnaissance (`morph.py`, `deflator.py`, `honeyfiles.py`)**:
  - `OSMorpher`: Returns intentionally contradictory banners across services in `polymorphic` mode, or emulates `fedora`, `windows_server`, `freebsd`, or `cisco`.
  - `ScannerDeflator`: Flags automated web fuzzers (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, `nmap`, rapid request bursts, traversal/SQLi/XSS paths) and streams chunked `Content-Encoding: gzip` null-byte payloads.
  - `HoneyFileManager`: Stages realistic dummy encrypted files (`.kdbx`, `.sql.gpg`, `.enc`, PKCS#8 PEM) on disk and streams `/backups/<file>` downloads throttled to ~40 KB/s (`4096` bytes every `0.1s`).
- **Score-Based Auto-Quarantine (`quarantine.py`, `telemetry.py`)**: Normalizes IPv4-mapped IPv6 addresses, whitelists `127.0.0.1`, `::1`, default gateway, and `/etc/resolv.conf` nameservers, logs JSONL incidents, accumulates threat scores (`port_probe: +15`, `credential_attempt: +25`, `port_scan_multiple: +30`, `exploit_url_probe: +40`, `canary_download: +50`), and calls `FirewallCore.block_ip()` when `honeypot_ban_threshold` (default `75`) is reached.

---

## User Interface & Desktop Integration

The main window (`ui/app.py`, `ui/pages.py`) uses an adaptive `Adw.NavigationSplitView` with **9 sections**, plus global header controls (**Panic**, **Reload**, **Settings**, **About**):

1. **Dashboard** — Firewall status summary cards, quick IP block, auto-scanned services/apps summary, honeypot shortcut, live interface RX/TX rates, and recent audit events.
2. **Firewall Rules** — Per-zone editor for allowed services, allowed ports, explicitly blocked IPs/subnets, and custom rich rules.
3. **Network Monitor** — Real-time searchable socket table with TCP/UDP and state filters (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`) and quick actions.
4. **Services & Applications** — Rescan, filter by category/status, add custom rules, and toggle network permissions for system services, daemons, Flatpaks, and desktop apps.
5. **LineageGuard** — Toggle live enforcement and `SIGSTOP` micro-freezing, choose lease duration presets, inspect current shell ancestry, triage frozen process groups, revoke/manage active leases, and manage approved SHA-256 lineage signatures.
6. **Honeypot & Decoys** — Master deception toggle, 24h metrics, Scanner Deflator toggle, OS Morphing mode selector, individual switches for all 11 decoys, staged canary vault listing, live incident feed, and quarantined IP release controls.
7. **Security Profiles** — Activate `Home`, `Public`, `Corporate`, `Gaming`, or `Maximum Security`, view tier capabilities, and create/restore JSON rule backups.
8. **Event Log** — Searchable firewall/IDS/honeypot audit trail with severity filters (`info`, `warning`, `alert`, `critical`), JSON/CSV/TXT export, and log clear.
9. **Settings** — Start minimized, panic confirmation toggle, XDG login autostart, minimize-to-tray on close, monitor refresh interval (`1s`, `2s`, `4s`), startup auto-scan toggle, `firewalld`/`nftables`/platform diagnostics, About/License dialogs, and reset to defaults.

Desktop integration (`main.py`, `ui/tray.py`) also includes:
- **System Tray Indicator**: Native `org.kde.StatusNotifierItem` + `com.canonical.dbusmenu` implementation showing active status (`• v3.0 GEOS`), desktop notifications, quick profile/status actions, and Panic toggle.
- **Single-Instance IPC**: UNIX domain socket server (`$XDG_RUNTIME_DIR/vitorius-firewall.sock` or `/tmp/vitorius-firewall-$UID.sock`) that brings the existing window to focus on repeat launches.

---

## Requirements & Installation

### System & Python Dependencies
- **OS**: Linux with `firewalld` and kernel `nftables` (built and tested primarily for Fedora Linux / RHEL / CentOS Stream / Bazzite).
- **Runtime**: Python `>= 3.10`, GTK 4, Libadwaita `>= 1.0`, `PyGObject >= 3.44`, `psutil >= 5.9`.
- **System Tools**: `firewalld` (`firewall-cmd`), `nftables` (`nft`), `iproute` (`ss`, `ip`), `polkit` (`pkexec`), `systemd` (`systemctl`, `journalctl`), `flatpak` (optional, for Flatpak sandbox overrides).

### Install & Launch
```bash
cd /home/Vitorius/Desktop/V_Firewall_3_0

# Install application menu entry, desktop shortcut, and hicolor icons
bash install.sh

# Optional: also install the allowlisted Polkit helper (/usr/libexec/v-firewall-helper
# and /usr/share/polkit-1/actions/com.v.firewall.policy)
bash install.sh --install-policy

# Launch the GUI (writes launcher diagnostics to /tmp/v-firewall.log)
./run.sh
```

### CLI Options
```bash
python3 main.py --minimized    # Also accepts -m, --tray, --start-minimized
python3 main.py --unpanic      # Also accepts --disable-panic (restores network traffic)
```

### Uninstall
```bash
bash uninstall.sh
```

---

## Runtime Data Locations & Project Layout

### User Data & Config Paths
- Config & lineage trust DB: `~/.config/v-firewall/config.json`, `~/.config/v-firewall/lineage_trust.json`
- Audit logs, rule backups & GeoIP `.zone` files: `~/.local/share/v-firewall/logs/`, `~/.local/share/v-firewall/backups/rules/`, `~/.local/share/v-firewall/geoip/`
- Honeypot telemetry & canary vault: `~/.local/share/vitorius-firewall/honeypot/honeypot_events.jsonl`, `~/.local/share/vitorius-firewall/honeypot/canary_vault/`
- Autostart entry (when enabled): `~/.config/autostart/v-firewall.desktop`
- Launcher log: `/tmp/v-firewall.log`

### Repository Structure
```text
V_Firewall_3_0/
├── main.py                     # CLI entry point, single-instance wakeup, desktop sync, Adw init
├── pyproject.toml              # Package metadata (v-firewall 3.0.0) and Python dependencies
├── install.sh / run.sh / uninstall.sh
├── policy/
│   └── com.v.firewall.policy   # Polkit action definition for /usr/libexec/v-firewall-helper
├── data/
│   ├── default_config.json     # Built-in security profiles & default settings (3.0 GEOS)
│   └── icons/ & *.svg          # Normal and panic-mode SVG/PNG application icons
├── backend/
│   ├── core.py                 # FirewallCore, nft/firewall-cmd/ss/cgroup/Flatpak orchestration
│   ├── dbus_client.py          # FirewallDbusClient (Gio.DBusProxy read path)
│   ├── privileged_helper.py    # Allowlisted argv-based Polkit helper
│   ├── geoblock.py             # GeoBlockManager (country IPSets & .zone loader)
│   ├── ids.py                  # IdsLogMonitor (journalctl -k port-scan burst detection)
│   ├── monitor.py              # NetworkMonitor (/proc/net + psutil) & BandwidthTracker
│   ├── profiles.py             # ProfileManager, FirewallLogger & backup/restore
│   ├── scanner.py              # ServiceAppScanner (services, sockets, Flatpaks, .desktop apps)
│   ├── lineage/                # Resolver, PolicyEngine, Enforcer, ProcessFreezer, EphemeralLeases
│   └── honeypot/               # DeceptionEngine, Arbiter, Morph, Deflator, HoneyFiles, Quarantine, Decoys
└── ui/
    ├── app.py                  # VitoriusFirewallApp, MainWindow, SingleInstanceServer, Lineage triage
    ├── pages.py                # 9 Libadwaita pages
    └── tray.py                 # StatusNotifierItem & dbusmenu system tray indicator
```
