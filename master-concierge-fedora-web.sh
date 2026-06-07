#!/bin/bash
# ==============================================================================
# master-concierge-fedora-web.sh
# Target: concierge - Fedora 43 - Web (172.21.0.102)
#
# Pipeline: general hardening -> SSH -> Fedora web hardening -> cockpit/firewalld
#           removal -> firewall -> backups -> baseline -> background enum
#
# Tailoring vs the stock masters:
#   - Uses harden_web_fedora.sh, NOT the repo's harden_ecom.sh (that one is
#     Debian/Apache-only: apt, a2enmod, /etc/apache2 - none exist on Fedora).
#   - No hardcoded backup account.
#   - Outbound allowed to the DB box (172.21.0.101) so the web app can query it.
#   - iptables persisted the Fedora way (/etc/sysconfig/iptables + iptables.service).
#   - Default-DROP applied LAST (lockout-safe).
#
# Usage: sudo ./master-concierge-fedora-web.sh
# ==============================================================================
set -uo pipefail

# --- Network policy ---
DB_HOST="172.21.0.101"           # blacklist (database)
DB_PORTS="3306 5432"             # web app -> DB; harmless to allow both outbound
DC_HOST="172.21.0.103"           # cabal (AD domain controller). This box is an AD
                                 # client, so it needs egress to the DC for
                                 # Kerberos/LDAP/etc. Space-separate extra DCs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUXDEV="$SCRIPT_DIR/modules"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-concierge-web_$TIMESTAMP.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()   { echo -e "${GREEN}[INFO]${NC} $1"  | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1"   | tee -a "$LOG_FILE"; }
phase() { echo -e "\n${CYAN}========== $1 ==========${NC}" | tee -a "$LOG_FILE"; }

check_root() { [[ $EUID -ne 0 ]] && { error "Must run as root"; exit 1; }; return 0; }

run_script() {
    local script="$1" name="$2"
    if [[ -f "$script" ]]; then
        log "Running $name..."
        chmod +x "$script" 2>/dev/null || true
        bash "$script" 2>&1 | tee -a "$LOG_FILE"
        log "$name finished (review log for warnings)"
    else
        warn "Script not found: $script"
    fi
}

check_root
mkdir -p "$LOG_DIR"

echo "========================================================"
echo "  CONCIERGE - FEDORA 43 WEB - MASTER HARDENING"
echo "  Time: $(date)"
echo "========================================================"

# ============================================================================
phase "PHASE 1: GENERAL LINUX HARDENING + SSH"
run_script "$LINUXDEV/generalLinuxHarden.sh" "General Linux Hardening"
log "Removing pre-seeded authorized_keys (red-team persistence)..."
find / -name "authorized_keys" -type f -delete 2>/dev/null || true
run_script "$LINUXDEV/ssh_harden.sh" "SSH Hardening"

# ============================================================================
phase "PHASE 2: WEB SERVER HARDENING (Fedora-native)"
run_script "$LINUXDEV/harden_web_fedora.sh" "Fedora Web Hardening"

# ============================================================================
phase "PHASE 2b: REMOVE COCKPIT + FIREWALLD"
systemctl stop cockpit.socket cockpit.service 2>/dev/null || true
systemctl disable cockpit.socket cockpit.service 2>/dev/null || true
dnf remove -y cockpit cockpit-ws cockpit-bridge cockpit-system 2>/dev/null || true
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true
dnf install -y iptables-services 2>/dev/null || true

# ============================================================================
phase "PHASE 3: FIREWALL (iptables)"
# Build with policies ACCEPT (lockout-safe), flip to DROP at the very end.
iptables -F; iptables -X; iptables -Z
iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT

iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT  -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Anti-recon
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip --hashlimit-name syn_scan --hashlimit-htable-expire 30000 -j DROP

# Inbound: SSH + scored web
iptables -A INPUT -p tcp --dport 22  -j ACCEPT
iptables -A INPUT -p tcp --dport 80  -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Outbound: DNS, HTTP/HTTPS, NTP
iptables -A OUTPUT -p udp --dport 53  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
# Outbound: to the database box only
for p in $DB_PORTS; do
    iptables -A OUTPUT -p tcp -d "$DB_HOST" --dport "$p" -j ACCEPT
done
# Outbound: Active Directory client -> Domain Controller(s).
# Kerberos 88, kpasswd 464, LDAP 389 (tcp+udp), LDAPS 636, Global Catalog 3268/3269.
# (DNS 53 and NTP 123 the client also needs for AD are already permitted above.)
for dc in $DC_HOST; do
    for p in 88 464 389; do
        iptables -A OUTPUT -p tcp -d "$dc" --dport "$p" -j ACCEPT
        iptables -A OUTPUT -p udp -d "$dc" --dport "$p" -j ACCEPT
    done
    for p in 636 3268 3269; do
        iptables -A OUTPUT -p tcp -d "$dc" --dport "$p" -j ACCEPT
    done
done
# Outbound: monitoring agents
iptables -A OUTPUT -p tcp --dport 4505 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 4506 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1514 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1515 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# Log + explicit reject
iptables -A INPUT   -j LOG --log-prefix "IPT-INPUT-REJECT: "  --log-level 4
iptables -A OUTPUT  -j LOG --log-prefix "IPT-OUTPUT-REJECT: " --log-level 4
iptables -A INPUT   -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT  -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable

# Flip defaults to DROP last
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP

iptables-save > /etc/sysconfig/iptables
systemctl enable iptables 2>/dev/null || true
systemctl start iptables 2>/dev/null || true
log "Firewall set: in[22,80,443]  out[53,80,443,123, DB:$DB_PORTS to $DB_HOST, AD->$DC_HOST, agents]"

# ============================================================================
phase "PHASE 4: BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"
BACKUP_DIR="/root/web_backup_$TIMESTAMP"; mkdir -p "$BACKUP_DIR"
[[ -d /etc/httpd ]]  && cp -a /etc/httpd  "$BACKUP_DIR/" 2>/dev/null || true
[[ -d /etc/nginx ]]  && cp -a /etc/nginx  "$BACKUP_DIR/" 2>/dev/null || true
[[ -d /var/www ]]    && tar czf "$BACKUP_DIR/var_www.tar.gz" /var/www 2>/dev/null || true
[[ -f /etc/php.ini ]] && cp /etc/php.ini "$BACKUP_DIR/" 2>/dev/null || true
log "Web configs/docroot backed up -> $BACKUP_DIR"

# ============================================================================
phase "PHASE 5: BASELINE"
run_script "$LINUXDEV/systemBaseline.sh" "System Baseline"

# ============================================================================
phase "PHASE 6: POST-HARDENING ENUMERATION (background)"
if [[ -f "$LINUXDEV/masterEnum.sh" ]]; then
    nohup bash "$LINUXDEV/masterEnum.sh" > "$LOG_DIR/enum_post_$TIMESTAMP.log" 2>&1 &
    log "Enumeration running in background (PID $!) -> $LOG_DIR/enum_post_$TIMESTAMP.log"
fi

phase "COMPLETE"
echo "Logs: $LOG_DIR/    Web backup: $BACKUP_DIR"
echo "Verify:  curl -I http://localhost/   &&   curl -Ik https://localhost/"
echo "If the app can't reach the DB and SELinux is enforcing:"
echo "  getsebool httpd_can_network_connect_db   (should be on)"
exit 0
