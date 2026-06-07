#!/bin/bash
# ==============================================================================
# Script Name: suidCleanup.sh
# Description: Removes SUID/SGID bits from known-dangerous binaries (GTFOBins).
#              These binaries can be abused for privilege escalation if they have
#              SUID/SGID set. Safe to run multiple times.
# Author: Security Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./suidCleanup.sh [options]
#
# Options:
#   -h, --help      Show this help message
#   -n, --dry-run   Show what would be changed without modifying anything
#   -q, --quiet     Minimal output
#   -a, --all       Also scan for ANY SUID/SGID binaries not in the known list
#
# Based on GTFOBins list (~215 binaries known to be abusable with SUID/SGID)
#
# Exit Codes:
#   0 - Success (or dry-run complete)
#   1 - Error
#   3 - Permission denied
# ==============================================================================

set -uo pipefail

# --- Configuration ---
DRY_RUN=false
QUIET=false
SCAN_ALL=false
FIXED=0
SKIPPED=0

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# GTFOBins SUID/SGID abusable binaries
# Source: https://gtfobins.github.io/
GTFOBINS=(
    aa-exec ab agetty alpine ar arj arp as ascii-xfr ash aspell
    atobm awk base32 base64 basenc basez bash bridge busybox
    bzip2 cabal capsh cat chmod chown chroot cmp column comm cp
    cpio cpulimit csh csplit csvtool cupsfilter curl cut dash
    date dd debugfs dialog diff dig distcc dmesg dmsetup docker
    dosbox ed efax elvish emacs env eqn espeak expand expect
    file find fish flock fmt fold gawk gcore gdb genie genisoimage
    gimp git grep gtester gzip hd head hexdump highlight hping3 iconv
    install ionice ip ispell jjs join jq jrunscript julia ksh ksshell
    kubectl ld.so less links logsave look lua make mawk minicom more
    mosquitto msgattrib msgcat msgconv msgfilter msgmerge msguniq
    multitime mv nasm nawk ncftp nft nice nl nm nmap node nohup
    ntpdate od openssl openvpn pandoc paste perf perl pg php
    pidstat pr ptx python readelf realpath recutils restic rev
    rlwrap rsync rtorrent run-parts rview rvim sash scanmem
    sed setarch setfacl setlock shuf slsh socat sort sqlite3
    ss ssh-keygen ssh-keyscan sshpass start-stop-daemon stdbuf
    strace strings sysctl systemctl tac tail taskset tbl tee
    terraform tftp tic time timeout troff ul unexpand uniq
    unshare unsquashfs unzip update-alternatives uudecode
    uuencode vagrant varnishncsa vi view vigr vim vimdiff vipw
    w3m watch wc wget whiptail xargs xdotool xmodmap xmore
    xxd xz yash zsh zsoelim
)

log_info() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_fixed() {
    echo -e "${GREEN}[FIXED]${NC} $1"
}

usage() {
    head -25 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 3
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)   usage ;;
        -n|--dry-run) DRY_RUN=true; shift ;;
        -q|--quiet)  QUIET=true; shift ;;
        -a|--all)    SCAN_ALL=true; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# --- Main ---
check_root

echo "========================================"
echo "SUID/SGID CLEANUP — GTFOBins Scan"
echo "========================================"
[[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}DRY RUN — no changes will be made${NC}"
echo ""

log_info "Scanning for ${#GTFOBINS[@]} known-dangerous binaries with SUID/SGID..."

for bin in "${GTFOBINS[@]}"; do
    # Find all instances of this binary on the system
    while IFS= read -r bin_path; do
        [[ -z "$bin_path" ]] && continue

        # Check if it has SUID or SGID
        # stat -c '%a' returns octal as a string, prefix with 0 for bash octal arithmetic
        perms=$(stat -c '%a' "$bin_path" 2>/dev/null) || continue
        has_suid=false
        has_sgid=false

        if [[ $((0$perms & 04000)) -ne 0 ]]; then
            has_suid=true
        fi
        if [[ $((0$perms & 02000)) -ne 0 ]]; then
            has_sgid=true
        fi

        if [[ "$has_suid" == "true" || "$has_sgid" == "true" ]]; then
            local_desc=""
            [[ "$has_suid" == "true" ]] && local_desc+="SUID "
            [[ "$has_sgid" == "true" ]] && local_desc+="SGID "

            if [[ "$DRY_RUN" == "true" ]]; then
                log_warning "WOULD REMOVE ${local_desc}from: $bin_path (mode: $perms)"
                ((FIXED++)) || true
            else
                chmod u-s,g-s "$bin_path" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    log_fixed "Removed ${local_desc}from: $bin_path"
                    ((FIXED++)) || true
                else
                    log_warning "Failed to fix: $bin_path"
                    ((SKIPPED++)) || true
                fi
            fi
        fi
    done < <( { command -v "$bin" 2>/dev/null; find /usr/bin /usr/sbin /usr/local/bin /bin /sbin -name "$bin" -type f 2>/dev/null; } | sort -u )
done

# --- Optional: Scan for ANY SUID/SGID binaries ---
if [[ "$SCAN_ALL" == "true" ]]; then
    echo ""
    log_info "Scanning for ALL SUID/SGID binaries on the system..."
    echo ""

    # Build a lookup set from GTFOBINS
    declare -A KNOWN_BINS
    for bin in "${GTFOBINS[@]}"; do
        KNOWN_BINS["$bin"]=1
    done

    while IFS= read -r suid_file; do
        [[ -z "$suid_file" ]] && continue
        fname=$(basename "$suid_file")

        # Skip if already in GTFOBins list (handled above)
        [[ -n "${KNOWN_BINS[$fname]:-}" ]] && continue

        perms=$(stat -c '%a' "$suid_file" 2>/dev/null) || continue
        owner=$(stat -c '%U:%G' "$suid_file" 2>/dev/null) || continue
        echo -e "${BLUE}[REVIEW]${NC} $suid_file (mode: $perms, owner: $owner)"
    done < <(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
fi

# --- Summary ---
echo ""
echo "========================================"
echo "SUID/SGID CLEANUP COMPLETE"
echo "========================================"
if [[ "$DRY_RUN" == "true" ]]; then
    echo "Binaries that would be fixed: $FIXED"
else
    echo "Binaries fixed: $FIXED"
    echo "Failures: $SKIPPED"
fi
echo "========================================"

exit 0
