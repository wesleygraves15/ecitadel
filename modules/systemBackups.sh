#!/bin/bash
# ==============================================================================
# Script Name: systemBackups.sh
# Description: Fast, non-destructive backup of the things you need to RESTORE after
#              tampering: /etc, account/auth files, cron, firewall rules, package
#              and service inventories. Stored under /root and locked to root.
#              Service DATA (databases, web content) is handled by the box masters,
#              not here — this is the configuration safety net.
# Date: 2025-2026
# Version: 1.0
#
# Usage:  ./systemBackups.sh [target_dir]   (default: /root/ecitadel_backups/<ts>)
# ==============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

[[ $EUID -ne 0 ]] && { err "Run as root"; exit 3; }

TS="$(date +%Y%m%d_%H%M%S)"
DEST="${1:-/root/ecitadel_backups/$TS}"
mkdir -p "$DEST"

log "Backing up configuration and state to $DEST"

# /etc — the bulk of restorable config
tar -czf "$DEST/etc.tar.gz" -C / etc 2>/dev/null \
    && log "  /etc -> etc.tar.gz" || warn "  /etc backup had errors"

# Account / auth files (copied individually so they are easy to diff/restore)
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    [[ -f "$f" ]] && cp -a "$f" "$DEST/" 2>/dev/null || true
done
[[ -d /etc/sudoers.d ]] && cp -a /etc/sudoers.d "$DEST/" 2>/dev/null || true

# SSH host + authorized keys
mkdir -p "$DEST/ssh"
cp -a /etc/ssh "$DEST/ssh/etc_ssh" 2>/dev/null || true
while IFS= read -r ak; do
    [[ -f "$ak" ]] || continue
    dst="$DEST/ssh/authorized_keys_$(echo "$ak" | tr '/' '_')"
    cp -a "$ak" "$dst" 2>/dev/null || true
done < <(find /root /home -maxdepth 3 -name authorized_keys 2>/dev/null)

# Cron
mkdir -p "$DEST/cron"
for c in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -e "$c" ]] && cp -a "$c" "$DEST/cron/" 2>/dev/null || true
done
for sp in /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$sp" ]] && cp -a "$sp" "$DEST/cron/" 2>/dev/null || true
done

# Firewall rules (both families, whichever exists)
{ iptables-save 2>/dev/null; } > "$DEST/iptables.rules" || true
{ command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null; } > "$DEST/nftables.rules" || true

# Inventories: packages and enabled services
if command -v dpkg >/dev/null 2>&1; then
    dpkg --get-selections > "$DEST/packages.dpkg.txt" 2>/dev/null || true
elif command -v rpm >/dev/null 2>&1; then
    rpm -qa | sort > "$DEST/packages.rpm.txt" 2>/dev/null || true
fi
systemctl list-unit-files --state=enabled > "$DEST/services.enabled.txt" 2>/dev/null || true
systemctl list-units --type=service --state=running > "$DEST/services.running.txt" 2>/dev/null || true

# Lock it down
chmod -R go-rwx "$DEST" 2>/dev/null || true
find "$DEST" -type d -exec chmod 700 {} + 2>/dev/null || true
find "$DEST" -type f -exec chmod 600 {} + 2>/dev/null || true

SIZE="$(du -sh "$DEST" 2>/dev/null | cut -f1)"
log "Backup complete: $DEST ($SIZE)"
