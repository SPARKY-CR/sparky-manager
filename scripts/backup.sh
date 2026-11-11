#!/usr/bin/env bash
# sparky-manager backup — original work, written from scratch.
#
# Backs up the panel database (the source of truth) plus both rendered
# core configs into one tar.gz. Restoring the database and re-rendering
# the configs is enough to rebuild the panel; the tarball just keeps a
# copy of the rendered configs alongside it for convenience.
#
# Usage:
#   sudo scripts/backup.sh [DESTINATION]
#   sudo sparky-manager backup [DESTINATION]
# Default destination: /root/sparky-manager-backup-<date>.tar.gz

set -euo pipefail

DEST="${1:-/root/sparky-manager-backup-$(date +%F).tar.gz}"

[ "$(id -u)" -eq 0 ] || { echo "backup.sh must run as root (use sudo)." >&2; exit 1; }

paths=()
[ -d /opt/sparky-manager/data ] && paths+=("/opt/sparky-manager/data")
[ -f /usr/local/etc/xray/config.json ] && paths+=("/usr/local/etc/xray/config.json")
[ -f /etc/sing-box/config.json ] && paths+=("/etc/sing-box/config.json")
[ -f /opt/sparky-manager/versions.env ] && paths+=("/opt/sparky-manager/versions.env")

if [ "${#paths[@]}" -eq 0 ]; then
    echo "Nothing to back up: no panel data or configs found." >&2
    exit 1
fi

mkdir -p "$(dirname "$DEST")"
tar -czf "$DEST" "${paths[@]}"
chmod 0600 "$DEST"
echo "Backup written to: $DEST ($(du -h "$DEST" | cut -f1))"
