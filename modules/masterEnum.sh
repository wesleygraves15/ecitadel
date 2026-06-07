#!/bin/bash
# ==============================================================================
# Script Name: masterEnum.sh
# Description: Read-only situational-awareness enumeration for blue teams. Prints a
#              report covering host/OS, accounts (UID0/sudo/empty-pw), listening and
#              established sockets with owners, processes, cron, systemd services &
#              timers, SUID/SGID, world-writable files, recent web changes, network,
#              and AD/domain-join status. Makes NO changes to the system.
# Date: 2025-2026
# Version: 1.0
#
# Usage:  ./masterEnum.sh        (writes the report to stdout; redirect to a file)
# ==============================================================================
set -uo pipefail

CYAN='\033[0;36m'; NC='\033[0m'
sec() { echo -e "\n${CYAN}========== $1 ==========${NC}"; }

echo "eCitadel enumeration report"
echo "Generated: $(date)   Host: $(hostname)   User: $(id -un)"

sec "HOST / OS"
{ uname -a; echo; [[ -r /etc/os-release ]] && grep -E '^(PRETTY_NAME|VERSION)=' /etc/os-release; echo; uptime; } 2>/dev/null

sec "ACCOUNTS OF INTEREST"
echo "-- UID 0 accounts --";        awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
echo "-- Login-capable (UID>=1000, real shell) --"
awk -F: '($3>=1000)&&($3!=65534)&&($7!~/(nologin|false)$/){print $1" ("$3") "$7}' /etc/passwd 2>/dev/null
echo "-- sudo / wheel members --"
getent group sudo 2>/dev/null; getent group wheel 2>/dev/null
echo "-- NOPASSWD sudo rules --"
grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/  /' || true
echo "-- Empty-password accounts (shadow) --"
[[ -r /etc/shadow ]] && awk -F: '($2==""){print "  "$1}' /etc/shadow 2>/dev/null || echo "  (cannot read shadow)"

sec "LISTENING SOCKETS"
{ command -v ss >/dev/null && ss -tulpn || netstat -tulpn; } 2>/dev/null

sec "ESTABLISHED CONNECTIONS"
{ command -v ss >/dev/null && ss -tunp state established || netstat -tunp; } 2>/dev/null | head -60

sec "PROCESSES (top by start)"
ps -eo user,pid,ppid,stime,comm,args --sort=pid 2>/dev/null | head -80

sec "CRON"
{ for u in $(cut -d: -f1 /etc/passwd); do c="$(crontab -l -u "$u" 2>/dev/null)"; [[ -n "$c" ]] && { echo "## $u"; echo "$c"; }; done; } 2>/dev/null
for d in /etc/crontab /etc/cron.d; do [[ -e "$d" ]] && { echo "## $d"; cat "$d"/* 2>/dev/null || cat "$d" 2>/dev/null; }; done 2>/dev/null

sec "SYSTEMD SERVICES (enabled) & TIMERS"
systemctl list-unit-files --state=enabled 2>/dev/null | head -60
echo "-- timers --"; systemctl list-timers --all 2>/dev/null | head -30

sec "SUID / SGID BINARIES"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort

sec "WORLD-WRITABLE FILES (sensitive dirs)"
find /etc /usr /bin /sbin /lib /lib64 -xdev -type f -perm -002 2>/dev/null | head -40

sec "RECENTLY MODIFIED IN WEB ROOTS (last 2 days)"
for w in /var/www /var/www/html /usr/share/nginx/html /srv/www /srv/http; do
    [[ -d "$w" ]] && find "$w" -type f -mtime -2 2>/dev/null
done | head -60

sec "NETWORK"
{ ip -o addr 2>/dev/null; echo "-- routes --"; ip route 2>/dev/null; echo "-- neighbors --"; ip neigh 2>/dev/null | head -40; } 2>/dev/null

sec "AD / DOMAIN JOIN STATUS"
if command -v realm >/dev/null 2>&1; then realm list 2>/dev/null || echo "  realm: not joined / no output"; else echo "  realm: not installed"; fi
if command -v sssctl >/dev/null 2>&1; then sssctl domain-list 2>/dev/null || true; fi
systemctl is-active sssd 2>/dev/null | sed 's/^/  sssd active: /' || true

echo -e "\n--- end of report ---"
