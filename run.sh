#!/usr/bin/env bash
# V Firewall - Robust GUI Launcher
# Version: 3.0 (GEOS)
# License: MIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"

# Ensure desktop entry & icons exist so taskbar ALWAYS displays the icon when clicked directly
mkdir -p "$APPS_DIR" "$ICONS_BASE/scalable/apps"

# Copy SVGs
for icon in v-firewall.svg com.v.firewall.svg v-firewall-panic.svg com.v.firewall-panic.svg; do
    if [ -f "$SCRIPT_DIR/data/$icon" ]; then
        cp "$SCRIPT_DIR/data/$icon" "$ICONS_BASE/scalable/apps/$icon" 2>/dev/null || true
    fi
done

# Copy PNGs
for size in 16 24 32 48 64 128 256 512; do
    if [ -d "$SCRIPT_DIR/data/icons/${size}x${size}" ]; then
        mkdir -p "$ICONS_BASE/${size}x${size}/apps"
        for png in v-firewall.png com.v.firewall.png v-firewall-panic.png com.v.firewall-panic.png; do
            if [ -f "$SCRIPT_DIR/data/icons/${size}x${size}/$png" ]; then
                cp "$SCRIPT_DIR/data/icons/${size}x${size}/$png" "$ICONS_BASE/${size}x${size}/apps/$png" 2>/dev/null || true
            fi
        done
    fi
done

# Write desktop entry
cat <<EOF > "$APPS_DIR/v-firewall.desktop"
[Desktop Entry]
Version=1.5
Name=V Firewall
GenericName=Next-Gen Linux Firewall
Comment=Next-generation Linux firewall with Process Lineage Provenance, Micro-Freezing & Deception Honeypot
Exec="$SCRIPT_DIR/run.sh"
Path=$SCRIPT_DIR
Icon=v-firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.v.firewall
Keywords=firewall;security;network;fedora;rules;ports;monitor;honeypot;lineage;v-firewall;
X-KDE-SubstituteUID=false
EOF

cp "$APPS_DIR/v-firewall.desktop" "$APPS_DIR/com.v.firewall.desktop" 2>/dev/null || true
cp "$APPS_DIR/v-firewall.desktop" "$DESKTOP_DIR/v-firewall.desktop" 2>/dev/null || true
chmod +x "$APPS_DIR/v-firewall.desktop" "$APPS_DIR/com.v.firewall.desktop" "$DESKTOP_DIR/v-firewall.desktop" 2>/dev/null || true

# Mark trusted on GNOME Desktop if gio is present
if command -v gio >/dev/null 2>&1; then
    gio set "$DESKTOP_DIR/v-firewall.desktop" metadata::trusted true 2>/dev/null || true
fi

(
    command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" 2>/dev/null
    command -v kbuildsycoca6 >/dev/null 2>&1 && kbuildsycoca6 2>/dev/null
    command -v kbuildsycoca5 >/dev/null 2>&1 && kbuildsycoca5 2>/dev/null
) &

# Export FreeDesktop and Wayland desktop integration variables
export GIO_LAUNCHED_DESKTOP_FILE="$APPS_DIR/v-firewall.desktop"
export GIO_LAUNCHED_DESKTOP_FILE_PID=$$
export XDG_DATA_DIRS="$SCRIPT_DIR/share:$HOME/.local/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

LOG_FILE="/tmp/v-firewall.log"
echo "=== Starting V Firewall at $(date) ===" > "$LOG_FILE"
echo "Current directory: $SCRIPT_DIR" >> "$LOG_FILE"
echo "DISPLAY: $DISPLAY" >> "$LOG_FILE"
echo "WAYLAND_DISPLAY: $WAYLAND_DISPLAY" >> "$LOG_FILE"

# Launch application and redirect stderr/stdout to log file
exec python3 "$SCRIPT_DIR/main.py" "$@" >> "$LOG_FILE" 2>&1
