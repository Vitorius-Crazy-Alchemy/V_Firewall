#!/usr/bin/env bash
# Uninstallation script for V Firewall on Fedora Linux
# Version: 2.0
# License: MIT

set -e

APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"
AUTOSTART_DIR="$HOME/.config/autostart"

echo "=== Uninstalling V Firewall ==="

# 1. Kill running instances
pkill -f "main.py" 2>/dev/null || true
rm -f "$XDG_RUNTIME_DIR/v-firewall.sock" /tmp/v-firewall-*.sock "$XDG_RUNTIME_DIR/vitorius-firewall.sock" /tmp/vitorius-firewall-*.sock 2>/dev/null || true

# 2. Remove desktop entries
rm -f "$APPS_DIR/v-firewall.desktop" "$APPS_DIR/com.v.firewall.desktop"
rm -f "$APPS_DIR/vitorius-firewall.desktop" "$APPS_DIR/com.vitorius.firewall.desktop"
rm -f "$DESKTOP_DIR/v-firewall.desktop" "$DESKTOP_DIR/com.v.firewall.desktop"
rm -f "$DESKTOP_DIR/vitorius-firewall.desktop" "$DESKTOP_DIR/com.vitorius.firewall.desktop"
rm -f "$AUTOSTART_DIR/v-firewall.desktop" "$AUTOSTART_DIR/com.v.firewall.desktop"

# 3. Remove icons
for icon in v-firewall.svg com.v.firewall.svg v-firewall-panic.svg com.v.firewall-panic.svg; do
    rm -f "$ICONS_BASE/scalable/apps/$icon"
done
for size in 16 24 32 48 64 128 256 512; do
    for png in v-firewall.png com.v.firewall.png v-firewall-panic.png com.v.firewall-panic.png; do
        rm -f "$ICONS_BASE/${size}x${size}/apps/$png"
    done
done

# 4. Refresh caches
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null || true
fi

echo "=== V Firewall has been uninstalled successfully ==="
