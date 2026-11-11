#!/usr/bin/env bash
# vpn-panel backup — original work, written from scratch.
#
# Backs up the panel database (the source of truth) plus both rendered
# core configs into one tar.gz. Restoring the database and re-rendering
# the configs is enough to rebuild the panel; the tarball just keeps a
# copy of the rendered configs alongside it for convenience.
#
# Usage:
#   sudo scripts/backup.sh [DESTINATION]
#   sudo vpn-panel backup [DESTINATION]
# Default destination: /root/vpn-panel-backup-<date>.tar.gz

set -euo pipefail

DEST="${1:-/root/vpn-panel-backup-$(date +%F).tar.gz}"

[ "$(id -u)" -eq 0 ] || { echo "backup.sh must run as root (use sudo)." >&2; exit 1; }

paths=()
[ -d /opt/vpn-panel/data ] && paths+=("/opt/vpn-panel/data")
[ -f /usr/local/etc/xray/config.json ] && paths+=("/usr/local/etc/xray/config.json")
[ -f /etc/sing-box/config.json ] && paths+=("/etc/sing-box/config.json")
[ -f /opt/vpn-panel/versions.env ] && paths+=("/opt/vpn-panel/versions.env")

if [ "${#paths[@]}" -eq 0 ]; then
    echo "Nothing to back up: no panel data or configs found." >&2
    exit 1
fi

mkdir -p "$(dirname "$DEST")"
tar -czf "$DEST" "${paths[@]}"
chmod 0600 "$DEST"
echo "Backup written to: $DEST ($(du -h "$DEST" | cut -f1))"
