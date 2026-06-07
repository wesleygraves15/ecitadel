#!/bin/bash
# ==============================================================================
# master-blacklist-debian-db.sh
# Target: blacklist - Debian 13 - Database (172.21.0.101)
#
# Pipeline: general hardening -> SSH -> DB hardening -> firewall -> backups ->
#           baseline -> background enum
#
# Tailoring vs the stock masters:
#   - No hardcoded "sysadmin_backup" account (public-repo credential removed;
#     generalLinuxHarden.sh already provisions emergency admin 'bbob').
#   - DB port opened ONLY to the web box by default (see DB_ALLOWED). If the
#     scoring engine connects to the DB directly, add its source IP there.
#   - Engine auto-detected (MariaDB/MySQL=3306, PostgreSQL=5432; both if unsure).
#   - Default-DROP policy applied LAST, after loopback/established/SSH accepts,
#     so you can't lock yourself out of the SSH session during the build.
#
# Usage: sudo ./master-blacklist-debian-db.sh
# ==============================================================================
set -uo pipefail

# --- Network policy (edit if your topology differs) ---
WEB_HOST="172.21.0.102"          # concierge (web) - the legitimate DB client
# Single allow-list for who may reach the DB over the network. This drives BOTH the
# iptables rule AND (for PostgreSQL) the pg_hba.conf rules in harden_db.sh, so the
# firewall and DB-level gates can't drift. If the DB is a DIRECTLY-SCORED service,
# add the scoring source here - e.g.:
#   DB_CLIENTS="$WEB_HOST 172.21.0.250"      (web box + scoring engine)
#   DB_CLIENTS="172.21.0.0/24"               (entire competition subnet)
DB_CLIENTS="$WEB_HOST"
DB_ALLOWED="$DB_CLIENTS"          # firewall consumes this (iptables -s accepts IPs and CIDRs)
DC_HOST="172.21.0.103"           # cabal (AD domain controller). This box is an AD
                                 # client, so it needs egress to the DC for
                                 # Kerberos/LDAP/etc. Space-separate extra DCs.
export WEB_HOST DB_CLIENTS       # so harden_db.sh inherits the same allow-list

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUXDEV="$SCRIPT_DIR/modules"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/master-blacklist-db_$TIMESTAMP.log"

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
echo "  BLACKLIST - DEBIAN 13 DATABASE - MASTER HARDENING"
echo "  Time: $(date)"
echo "========================================================"

# ============================================================================
phase "PHASE 1: GENERAL LINUX HARDENING + SSH"
run_script "$LINUXDEV/generalLinuxHarden.sh" "General Linux Hardening"
log "Removing pre-seeded authorized_keys (red-team persistence)..."
find / -name "authorized_keys" -type f -delete 2>/dev/null || true
run_script "$LINUXDEV/ssh_harden.sh" "SSH Hardening"

# ============================================================================
phase "PHASE 2: DATABASE HARDENING"
run_script "$LINUXDEV/harden_db.sh" "Database Hardening"

# ============================================================================
phase "PHASE 3: FIREWALL (iptables)"
log "Detecting DB engine for firewall port selection..."
DB_PORTS=""
if command -v mysqld >/dev/null 2>&1 || command -v mariadbd >/dev/null 2>&1 \
   || systemctl list-units 2>/dev/null | grep -qiE 'maria|mysql'; then DB_PORTS="3306"; fi
if command -v psql >/dev/null 2>&1 || systemctl list-units 2>/dev/null | grep -qi postgres; then
    DB_PORTS="${DB_PORTS:+$DB_PORTS }5432"; fi
[[ -z "$DB_PORTS" ]] && { DB_PORTS="3306 5432"; warn "Engine not detected - opening both 3306 and 5432 (still restricted to DB_ALLOWED)."; }
log "DB ports to expose: $DB_PORTS  (clients: $DB_ALLOWED)"

# Persistence package (non-fatal if it prompts/fails)
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>/dev/null || true

# Build with policies still ACCEPT (lockout-safe), flip to DROP at the very end.
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
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 \
    --hashlimit-mode srcip --hashlimit-name syn_scan --hashlimit-htable-expire 30000 -j DROP

# Inbound: SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Inbound: DB port(s), restricted to the allow-list only
for p in $DB_PORTS; do
    for src in $DB_ALLOWED; do
        iptables -A INPUT -p tcp --dport "$p" -s "$src" -j ACCEPT
    done
done

# Outbound: DNS, HTTP/HTTPS (updates), NTP (time sync for Kerberos/logging)
iptables -A OUTPUT -p udp --dport 53  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
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
# Outbound: monitoring agents (Salt, Wazuh, Splunk UF)
iptables -A OUTPUT -p tcp --dport 4505 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 4506 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1514 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 1515 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT

# Log + explicit reject (backstop behind the DROP policy set below)
iptables -A INPUT   -j LOG --log-prefix "IPT-INPUT-REJECT: "  --log-level 4
iptables -A OUTPUT  -j LOG --log-prefix "IPT-OUTPUT-REJECT: " --log-level 4
iptables -A INPUT   -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT  -j REJECT --reject-with icmp-port-unreachable
iptables -A FORWARD -j REJECT --reject-with icmp-port-unreachable

# NOW flip defaults to DROP (top accepts are already in place -> no lockout)
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP

netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables.rules
log "Firewall set: in[22, DB:$DB_PORTS from $DB_ALLOWED]  out[53,80,443,123, AD->$DC_HOST, agents]"

# ============================================================================
phase "PHASE 4: BACKUPS"
run_script "$LINUXDEV/systemBackups.sh" "System Backups"
BACKUP_DIR="/root/db_backup_$TIMESTAMP"; mkdir -p "$BACKUP_DIR"
log "Dumping databases (best-effort, read-only)..."
if mysql -u root -e "SELECT 1" &>/dev/null; then
    mysqldump -u root --all-databases --single-transaction > "$BACKUP_DIR/all_mysql.sql" 2>/dev/null \
        && log "MySQL/MariaDB dump -> $BACKUP_DIR/all_mysql.sql" || warn "mysqldump failed"
elif command -v pg_dumpall >/dev/null 2>&1; then
    # shellcheck disable=SC2024  # redirect runs as root (intended); /root is root-writable
    sudo -u postgres pg_dumpall > "$BACKUP_DIR/all_postgres.sql" 2>/dev/null \
        && log "PostgreSQL dump -> $BACKUP_DIR/all_postgres.sql" || warn "pg_dumpall failed"
fi
[[ -d /etc/mysql ]]      && cp -a /etc/mysql      "$BACKUP_DIR/" 2>/dev/null || true
[[ -d /etc/postgresql ]] && cp -a /etc/postgresql "$BACKUP_DIR/" 2>/dev/null || true

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
echo "Logs: $LOG_DIR/    DB backup: $BACKUP_DIR"
echo "Verify scored DB reachability FROM the web box (172.21.0.102), not from here."
exit 0
