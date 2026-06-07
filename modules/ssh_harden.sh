#!/bin/bash
# ==============================================================================
# Script Name: ssh_harden.sh
# Description: Hardens OpenSSH safely on Debian and Fedora/RHEL. Writes settings
#              to a drop-in, validates with `sshd -t` BEFORE reloading, and rolls
#              back automatically if the new config is invalid. Will NOT lock you
#              out: PasswordAuthentication is left as-is, and root login is only
#              fully disabled when another sudo-capable account exists.
# Date: 2025-2026
# Version: 1.1
#
# Usage:  ./ssh_harden.sh [-n|--dry-run]
#
# Exit Codes: 0 ok / 1 error / 3 not root
# ==============================================================================
set -uo pipefail

DRY_RUN=false
[[ "${1:-}" =~ ^(-n|--dry-run)$ ]] && DRY_RUN=true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; }

[[ $EUID -ne 0 ]] && { err "Run as root"; exit 3; }

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN="$DROPIN_DIR/00-ecitadel-hardening.conf"
TS="$(date +%Y%m%d_%H%M%S)"

[[ -f "$SSHD_CONFIG" ]] || { err "$SSHD_CONFIG not found - is OpenSSH installed?"; exit 1; }

# --- Decide whether it is safe to fully disable root login ---------------------
# Safe only if at least one non-root account has a real shell AND sudo/wheel rights.
PERMIT_ROOT="no"
has_other_admin=false
while IFS=: read -r user _ uid _ _ _ shell; do
    [[ "$uid" -ge 1000 && "$uid" -ne 65534 ]] || continue
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    if id -nG "$user" 2>/dev/null | grep -qwE 'sudo|wheel'; then
        has_other_admin=true; break
    fi
done < /etc/passwd
if [[ "$has_other_admin" == false ]]; then
    PERMIT_ROOT="prohibit-password"
    warn "No non-root sudo account found; setting PermitRootLogin=prohibit-password (not 'no') to avoid lockout."
else
    log "Non-root sudo account present; PermitRootLogin will be set to 'no'."
fi

# --- Build the drop-in (PasswordAuthentication intentionally left untouched) ----
read -r -d '' DESIRED <<EOF || true
# eCitadel SSH hardening — generated ${TS}
PermitRootLogin ${PERMIT_ROOT}
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
StrictModes yes
LogLevel VERBOSE
Banner none
EOF

if [[ "$DRY_RUN" == true ]]; then
    log "[DRY-RUN] Would write $DROPIN with:"
    echo "$DESIRED" | sed 's/^/    /'
    log "[DRY-RUN] Would validate with 'sshd -t' and reload sshd."
    exit 0
fi

# --- Apply via drop-in if the main config Includes it; else append to main ------
mkdir -p "$DROPIN_DIR"
backup_main="${SSHD_CONFIG}.bak.${TS}"
cp -a "$SSHD_CONFIG" "$backup_main"

use_dropin=true
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    # No Include directive — fall back to appending a marked block to the main file.
    use_dropin=false
fi

if [[ "$use_dropin" == true ]]; then
    [[ -f "$DROPIN" ]] && cp -a "$DROPIN" "${DROPIN}.bak.${TS}"
    printf '%s\n' "$DESIRED" > "$DROPIN"
    chmod 600 "$DROPIN"
    target="$DROPIN"
else
    warn "sshd_config has no drop-in Include; appending hardening block to main config."
    # Remove any prior eCitadel block, then append a fresh one.
    sed -i '/# >>> eCitadel SSH hardening >>>/,/# <<< eCitadel SSH hardening <<</d' "$SSHD_CONFIG"
    {
        echo "# >>> eCitadel SSH hardening >>>"
        printf '%s\n' "$DESIRED"
        echo "# <<< eCitadel SSH hardening <<<"
    } >> "$SSHD_CONFIG"
    target="$SSHD_CONFIG"
fi

# --- Validate BEFORE reloading; roll back on failure ---------------------------
if sshd -t 2>/tmp/sshd_test.err; then
    log "sshd config validated OK."
    if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null \
       || service ssh reload 2>/dev/null || service sshd reload 2>/dev/null; then
        log "sshd reloaded. Active hardening applied via: $target"
        log "Backup of original main config: $backup_main"
        warn "Open a NEW SSH session to confirm access before closing this one."
    else
        warn "Config valid but reload command not found; restart sshd manually."
    fi
else
    err "sshd -t REJECTED the new config. Rolling back."
    cat /tmp/sshd_test.err | sed 's/^/    /'
    cp -a "$backup_main" "$SSHD_CONFIG"
    [[ "$use_dropin" == true && -f "$DROPIN" ]] && rm -f "$DROPIN"
    err "Rolled back to original config. No changes are live."
    exit 1
fi
