#!/bin/bash
# ==============================================================================
# Script Name: systemBaseline.sh
# Description: Captures a point-in-time baseline of system state (users, listening
#              ports, running processes, SUID/SGID inventory with hashes, cron,
#              services, loaded modules, network config). On subsequent runs it
#              diffs the new snapshot against the previous one and reports drift —
#              new listeners, new SUID binaries, new users/services, etc.
# Date: 2025-2026
# Version: 1.0
#
# Usage:  ./systemBaseline.sh        (capture + diff vs previous)
# ==============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

[[ $EUID -ne 0 ]] && { err "Run as root"; exit 3; }

BASE_ROOT="/root/ecitadel_baseline"
TS="$(date +%Y%m%d_%H%M%S)"
SNAP="$BASE_ROOT/$TS"
LAST_LINK="$BASE_ROOT/last"
mkdir -p "$SNAP"
PREV=""
[[ -L "$LAST_LINK" && -d "$LAST_LINK" ]] && PREV="$(readlink -f "$LAST_LINK")"

log "Capturing baseline -> $SNAP"

getent passwd                       > "$SNAP/users.txt"        2>/dev/null || true
awk -F: '($3>=1000)||($3==0){print $1":"$3}' /etc/passwd | sort > "$SNAP/login_users.txt" 2>/dev/null || true
{ command -v ss >/dev/null && ss -tulpn || netstat -tulpn; } 2>/dev/null \
    | sort > "$SNAP/listening.txt" || true
ps -eo user,pid,ppid,comm,args --sort=pid > "$SNAP/processes.txt" 2>/dev/null || true
systemctl list-unit-files --state=enabled 2>/dev/null | sort > "$SNAP/services_enabled.txt" || true
systemctl list-units --type=service --state=running 2>/dev/null | awk '{print $1}' | sort > "$SNAP/services_running.txt" || true
lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort > "$SNAP/modules.txt" || true
{ ip -o addr 2>/dev/null; echo "---routes---"; ip route 2>/dev/null; } > "$SNAP/network.txt" || true
{ crontab -l 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do echo "## $u"; crontab -l -u "$u" 2>/dev/null; done; } > "$SNAP/cron.txt" 2>/dev/null || true

# SUID/SGID inventory with hashes (the high-value integrity anchor)
: > "$SNAP/suid_sgid.txt"
while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    h="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    printf '%s  %s\n' "$h" "$f" >> "$SNAP/suid_sgid.txt"
done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)

chmod -R go-rwx "$SNAP" 2>/dev/null || true
ln -sfn "$SNAP" "$LAST_LINK"

# --- Drift report -------------------------------------------------------------
if [[ -n "$PREV" && "$PREV" != "$SNAP" && -d "$PREV" ]]; then
    echo ""
    echo -e "${CYAN}===== DRIFT since $(basename "$PREV") =====${NC}"
    drift=0
    report() {  # $1 label, $2 file
        local label="$1" file="$2"
        [[ -f "$PREV/$file" && -f "$SNAP/$file" ]] || return 0
        local added removed
        added="$(comm -13 <(sort "$PREV/$file") <(sort "$SNAP/$file"))"
        removed="$(comm -23 <(sort "$PREV/$file") <(sort "$SNAP/$file"))"
        if [[ -n "$added" || -n "$removed" ]]; then
            drift=1
            echo -e "${YELLOW}[$label]${NC}"
            [[ -n "$added" ]]   && echo "$added"   | sed 's/^/  + /'
            [[ -n "$removed" ]] && echo "$removed" | sed 's/^/  - /'
        fi
    }
    report "login users"     login_users.txt
    report "listening ports" listening.txt
    report "enabled services" services_enabled.txt
    report "running services" services_running.txt
    report "kernel modules"  modules.txt
    report "SUID/SGID (hash or path changed)" suid_sgid.txt
    [[ $drift -eq 0 ]] && log "No drift detected in tracked categories." \
                       || warn "Drift detected (see + added / - removed above)."
else
    log "First baseline captured (no previous snapshot to compare)."
fi
log "Baseline stored at $SNAP (latest: $LAST_LINK)"
