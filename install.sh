#!/usr/bin/env bash
# Installation script for V Firewall on Fedora Linux
# Version: 2.0
# License: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"

echo "=== Installing V Firewall v2.0 ==="

# Terminate any running instances and clear stale sockets before upgrade
pkill -f "main.py" 2>/dev/null || true
rm -f "$XDG_RUNTIME_DIR/v-firewall.sock" /tmp/v-firewall-*.sock "$XDG_RUNTIME_DIR/vitorius-firewall.sock" /tmp/vitorius-firewall-*.sock 2>/dev/null || true

mkdir -p "$APPS_DIR"
mkdir -p "$ICONS_BASE/scalable/apps"

# 1. Install scalable SVG icons
for icon in v-firewall.svg com.v.firewall.svg v-firewall-panic.svg com.v.firewall-panic.svg; do
    if [ -f "$SCRIPT_DIR/data/$icon" ]; then
        cp "$SCRIPT_DIR/data/$icon" "$ICONS_BASE/scalable/apps/$icon" 2>/dev/null || true
    fi
done

# 2. Install PNG icons across all resolutions
for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$ICONS_BASE/${size}x${size}/apps"
    for png in v-firewall.png com.v.firewall.png v-firewall-panic.png com.v.firewall-panic.png; do
        if [ -f "$SCRIPT_DIR/data/icons/${size}x${size}/$png" ]; then
            cp "$SCRIPT_DIR/data/icons/${size}x${size}/$png" "$ICONS_BASE/${size}x${size}/apps/$png" 2>/dev/null || true
        fi
    done
done

# Prepare desktop entry
DESKTOP_FILE_CONTENT="[Desktop Entry]
Version=1.5
Name=V Firewall
GenericName=Next-Gen Linux Firewall
Comment=Next-generation Linux firewall with Process Lineage Provenance, Micro-Freezing & Deception Honeypot
Exec=\"$SCRIPT_DIR/run.sh\"
Path=$SCRIPT_DIR
Icon=v-firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.v.firewall
Keywords=firewall;security;network;fedora;rules;ports;monitor;honeypot;lineage;v-firewall;
X-KDE-SubstituteUID=false
"

# 3. Install to Application Menu
echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/v-firewall.desktop"
echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/com.v.firewall.desktop"
chmod +x "${APPS_DIR}/v-firewall.desktop" "${APPS_DIR}/com.v.firewall.desktop"

# 4. Install to Desktop folder
if [ -d "$DESKTOP_DIR" ]; then
    echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_DIR/v-firewall.desktop"
    chmod +x "$DESKTOP_DIR/v-firewall.desktop"
    if command -v gio >/dev/null 2>&1; then
        gio set "$DESKTOP_DIR/v-firewall.desktop" metadata::trusted true 2>/dev/null || true
    fi
fi

# 5. Refresh system caches
echo "Updating desktop and icon caches..."
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null || true
fi

echo "✓ V Firewall v2.0 installed successfully!"
