#!/bin/bash
# ==============================================================================
# Script Name: securitySweep.sh
# Description: Detects and neutralizes common persistence mechanisms:
#              - LD_PRELOAD rootkits (env vars, ld.so.preload, profile scripts)
#              - rc.local backdoors
#              - mod_rootme Apache backdoor module
#              Can run once or loop every N minutes to catch re-deployments.
# Author: Security Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./securitySweep.sh [options]
#
# Options:
#   -h, --help         Show this help message
#   -n, --dry-run      Show what would be changed without modifying
#   -l, --loop MIN     Run in loop mode every MIN minutes (default: off)
#   -q, --quiet        Minimal output (useful in loop mode)
#
# What It Checks:
#   1. LD_PRELOAD environment variables in profile scripts
#   2. /etc/ld.so.preload for injected shared libraries
#   3. /etc/rc.local for backdoor commands
#   4. Apache mod_rootme backdoor module
#   5. Suspicious shared libraries in common hijack locations
#
# Exit Codes:
#   0 - Clean (or loop mode)
#   1 - Issues found and fixed
#   3 - Permission denied
# ==============================================================================

set -uo pipefail

# --- Configuration ---
DRY_RUN=false
QUIET=false
LOOP_MINUTES=0
QUARANTINE_LIBS=false   # if true, .so files in temp dirs are moved aside; default = report only
ISSUES_FOUND=0
ISSUES_FIXED=0

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_critical() {
    echo -e "${RED}[CRIT]${NC} $1"
}

log_fixed() {
    echo -e "${GREEN}[FIXED]${NC} $1"
}

usage() {
    head -30 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
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
        -h|--help)    usage ;;
        -n|--dry-run) DRY_RUN=true; shift ;;
        -l|--loop)
            LOOP_MINUTES="${2:-}"
            if ! [[ "$LOOP_MINUTES" =~ ^[0-9]+$ ]]; then
                echo "Error: --loop requires a positive integer (minutes)"; exit 1
            fi
            shift 2 ;;
        -q|--quiet)   QUIET=true; shift ;;
        --quarantine-libs) QUARANTINE_LIBS=true; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

check_root

# ==============================================================================
# CHECK 1: LD_PRELOAD in profile/environment scripts
# ==============================================================================
check_ld_preload() {
    log_info "Checking for LD_PRELOAD persistence..."

    local search_dirs=(
        /etc/profile.d
        /etc/profile
        /etc/environment
        /etc/bash.bashrc
        /etc/bashrc
    )

    # Also check all user profile files
    for home in /home/* /root; do
        [[ -d "$home" ]] || continue
        for f in .bashrc .bash_profile .profile .zshrc; do
            [[ -f "$home/$f" ]] && search_dirs+=("$home/$f")
        done
    done

    for target in "${search_dirs[@]}"; do
        if [[ -d "$target" ]]; then
            # Directory — scan all files in it
            while IFS= read -r file; do
                [[ -z "$file" ]] && continue
                scan_file_for_ld "$file"
            done < <(find "$target" -type f 2>/dev/null)
        elif [[ -f "$target" ]]; then
            scan_file_for_ld "$target"
        fi
    done
}

scan_file_for_ld() {
    local file="$1"
    # High-confidence backdoor: LD_PRELOAD / LD_AUDIT in a profile/env file. Auto-disable.
    if grep -qE '^\s*(export\s+)?LD_(PRELOAD|AUDIT)\s*=' "$file" 2>/dev/null; then
        ((ISSUES_FOUND++)) || true
        log_critical "LD_PRELOAD/LD_AUDIT persistence found in: $file"
        if [[ "$DRY_RUN" == "false" ]]; then
            sed -i 's/^\(\s*\(export\s\+\)\?LD_\(PRELOAD\|AUDIT\)\s*=\)/# DISABLED BY SECURITY SWEEP: \1/' "$file"
            log_fixed "Commented out LD_PRELOAD/LD_AUDIT in: $file"
            ((ISSUES_FIXED++)) || true
        else
            grep -nE '^\s*(export\s+)?LD_(PRELOAD|AUDIT)\s*=' "$file" 2>/dev/null | sed 's/^/    /'
        fi
    fi
    # LD_LIBRARY_PATH is frequently set legitimately (Splunk, Oracle, custom tooling),
    # so flag it for human review instead of auto-editing and risking a broken service.
    if grep -qE '^\s*(export\s+)?LD_LIBRARY_PATH\s*=' "$file" 2>/dev/null; then
        ((ISSUES_FOUND++)) || true
        log_warning "LD_LIBRARY_PATH set in: $file (review — legitimate for some tools, abused by others)"
        grep -nE '^\s*(export\s+)?LD_LIBRARY_PATH\s*=' "$file" 2>/dev/null | sed 's/^/    /'
    fi
}

# ==============================================================================
# CHECK 2: /etc/ld.so.preload
# ==============================================================================
check_ld_so_preload() {
    log_info "Checking /etc/ld.so.preload..."

    if [[ -f /etc/ld.so.preload ]]; then
        # Check if it has any actual content (non-empty, non-comment lines)
        if grep -qE '^\s*/' /etc/ld.so.preload 2>/dev/null; then
            ((ISSUES_FOUND++)) || true
            log_critical "/etc/ld.so.preload contains library injections:"
            grep -E '^\s*/' /etc/ld.so.preload

            if [[ "$DRY_RUN" == "false" ]]; then
                # Preserve for forensics, then neutralize
                cp /etc/ld.so.preload "/etc/ld.so.preload.EVIL_$(date +%s)" 2>/dev/null
                : > /etc/ld.so.preload
                log_fixed "Emptied /etc/ld.so.preload (original saved as .EVIL_*)"
                ((ISSUES_FIXED++)) || true
            fi
        else
            log_info "/etc/ld.so.preload exists but is clean"
        fi
    else
        log_info "/etc/ld.so.preload not present (good)"
    fi
}

# ==============================================================================
# CHECK 3: /etc/rc.local backdoors
# ==============================================================================
check_rc_local() {
    log_info "Checking /etc/rc.local..."

    if [[ -f /etc/rc.local ]]; then
        # Check for suspicious content (not just "exit 0" or comments)
        local suspicious_lines
        suspicious_lines=$(grep -cvE '^\s*(#|exit\s+0\s*$|$)' /etc/rc.local 2>/dev/null || echo "0")
        suspicious_lines=$(echo "$suspicious_lines" | tail -1)

        if [[ "$suspicious_lines" -gt 0 ]]; then
            ((ISSUES_FOUND++)) || true
            log_critical "/etc/rc.local has $suspicious_lines suspicious lines:"
            grep -vE '^\s*(#|exit\s+0\s*$|$)' /etc/rc.local 2>/dev/null | head -20

            if [[ "$DRY_RUN" == "false" ]]; then
                cp /etc/rc.local "/etc/rc.local.EVIL_$(date +%s)" 2>/dev/null
                # Replace with safe version
                cat > /etc/rc.local << 'RCEOF'
#!/bin/bash
# rc.local - cleaned by security sweep
exit 0
RCEOF
                chmod 644 /etc/rc.local
                log_fixed "Neutralized /etc/rc.local (original saved as .EVIL_*)"
                ((ISSUES_FIXED++)) || true
            fi
        else
            log_info "/etc/rc.local is clean"
        fi
    fi
}

# ==============================================================================
# CHECK 4: Apache mod_rootme backdoor
# ==============================================================================
check_mod_rootme() {
    log_info "Checking for Apache mod_rootme backdoor..."

    # Build the real file list by expanding globs (nullglob so non-matches vanish
    # instead of being passed through literally — the original stored glob strings
    # in an array and tested them with [[ -f ]], so conf.d/* was never scanned).
    local apache_configs=()
    local glob
    shopt -s nullglob
    for glob in \
        /etc/httpd/conf/httpd.conf \
        /etc/apache2/apache2.conf \
        /etc/httpd/conf.d/*.conf \
        /etc/apache2/mods-enabled/*.load \
        /etc/apache2/mods-enabled/*.conf \
        /etc/apache2/sites-enabled/*.conf
    do
        apache_configs+=("$glob")
    done
    shopt -u nullglob

    for conf in "${apache_configs[@]}"; do
        [[ -f "$conf" ]] || continue

        if grep -qiE '^\s*(LoadModule|Include).*rootme' "$conf" 2>/dev/null; then
            ((ISSUES_FOUND++)) || true
            log_critical "mod_rootme backdoor found in: $conf"

            if [[ "$DRY_RUN" == "false" ]]; then
                sed -i 's/^\(\s*\(LoadModule\|Include\).*rootme\)/#DISABLED: \1/' "$conf"
                log_fixed "Disabled mod_rootme in: $conf"
                ((ISSUES_FIXED++)) || true
            fi
        fi
    done

    # Try a2dismod if available
    if command -v a2dismod &>/dev/null; then
        if a2query -m rootme &>/dev/null 2>&1; then
            ((ISSUES_FOUND++)) || true
            log_critical "mod_rootme is enabled via a2enmod"

            if [[ "$DRY_RUN" == "false" ]]; then
                a2dismod rootme 2>/dev/null
                log_fixed "Disabled mod_rootme via a2dismod"
                ((ISSUES_FIXED++)) || true
            fi
        fi
    fi

    # Check for the rootme module on disk — match only shared objects, not any
    # file containing "rootme" (the original matched things like rootme.svg icons).
    local rootme_files
    rootme_files=$(find /usr/lib /usr/lib64 /usr/local/lib -type f \
        \( -name "mod_rootme*.so" -o -name "*rootme*.so" \) 2>/dev/null || true)
    if [[ -n "$rootme_files" ]]; then
        while IFS= read -r rf; do
            ((ISSUES_FOUND++)) || true
            log_critical "mod_rootme shared object found: $rf"
            if [[ "$DRY_RUN" == "false" ]]; then
                mv "$rf" "${rf}.DISABLED" 2>/dev/null
                log_fixed "Renamed $rf → ${rf}.DISABLED"
                ((ISSUES_FIXED++)) || true
            fi
        done <<< "$rootme_files"
    fi

    # Restart Apache if we made changes
    if [[ "$ISSUES_FIXED" -gt 0 && "$DRY_RUN" == "false" ]]; then
        if systemctl is-active --quiet httpd 2>/dev/null; then
            systemctl restart httpd 2>/dev/null && log_info "Restarted httpd"
        elif systemctl is-active --quiet apache2 2>/dev/null; then
            systemctl restart apache2 2>/dev/null && log_info "Restarted apache2"
        fi
    fi
}

# ==============================================================================
# CHECK 5: Suspicious shared libraries in common hijack locations
# ==============================================================================
check_suspicious_libs() {
    log_info "Checking for suspicious shared libraries..."

    local suspicious_dirs=(
        /tmp
        /dev/shm
        /var/tmp
        /run/shm
    )

    for dir in "${suspicious_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        # NOTE: group the -name tests with \( \) so the implicit -print applies to
        # BOTH (the original `-name A -o -name B` only printed the B matches).
        while IFS= read -r so_file; do
            [[ -z "$so_file" ]] && continue
            ((ISSUES_FOUND++)) || true
            log_critical "Shared library in temp dir (review): $so_file"
            if [[ "$DRY_RUN" == "false" && "$QUARANTINE_LIBS" == "true" ]]; then
                mv "$so_file" "${so_file}.QUARANTINED" 2>/dev/null \
                    && { log_fixed "Quarantined: $so_file"; ((ISSUES_FIXED++)) || true; }
            else
                # Default: report only. A .so under /tmp or /dev/shm is suspicious but
                # legit software (JVM, cffi, installers) also stages libs there, so do
                # not auto-move unless --quarantine-libs is given.
                log_warning "  not moved (run with --quarantine-libs to quarantine automatically)"
            fi
        done < <(find "$dir" -type f \( -name "*.so" -o -name "*.so.*" \) 2>/dev/null)
    done
}

# ==============================================================================
# CHECK 6: Other persistence (REPORT-ONLY — high value, high false-positive risk
# to auto-remove, so this only flags for the operator to act on)
# ==============================================================================
check_other_persistence() {
    log_info "Checking other persistence vectors (report-only)..."

    # SSH authorized_keys — re-appearing keys are a classic foothold
    while IFS= read -r ak; do
        [[ -z "$ak" ]] && continue
        if [[ -s "$ak" ]]; then
            ((ISSUES_FOUND++)) || true
            log_warning "authorized_keys present: $ak ($(wc -l < "$ak" 2>/dev/null) key line(s))"
        fi
    done < <(find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null)

    # sudoers drop-ins granting NOPASSWD (privilege backdoor)
    if compgen -G "/etc/sudoers.d/*" >/dev/null 2>&1; then
        while IFS= read -r sd; do
            if grep -qE 'NOPASSWD' "$sd" 2>/dev/null; then
                ((ISSUES_FOUND++)) || true
                log_critical "NOPASSWD sudo rule in $sd:"
                grep -nE 'NOPASSWD' "$sd" 2>/dev/null | sed 's/^/    /'
            fi
        done < <(find /etc/sudoers.d -type f 2>/dev/null)
    fi
    if grep -rqE '^\s*[^#].*NOPASSWD' /etc/sudoers 2>/dev/null; then
        ((ISSUES_FOUND++)) || true
        log_warning "NOPASSWD rule in /etc/sudoers (verify it is intended)"
    fi

    # Cron re-seeding (the general hardening nukes cron once; this catches re-adds)
    for cron_loc in /etc/cron.d /var/spool/cron /var/spool/cron/crontabs; do
        [[ -d "$cron_loc" ]] || continue
        while IFS= read -r cf; do
            [[ -s "$cf" ]] || continue
            if grep -qE '(curl|wget|nc|ncat|/dev/tcp|bash -i|python.*socket|base64\s+-d|/tmp/|/dev/shm/)' "$cf" 2>/dev/null; then
                ((ISSUES_FOUND++)) || true
                log_critical "Suspicious cron entry in $cf:"
                grep -nE '(curl|wget|nc|ncat|/dev/tcp|bash -i|python.*socket|base64\s+-d|/tmp/|/dev/shm/)' "$cf" 2>/dev/null | head -5 | sed 's/^/    /'
            fi
        done < <(find "$cron_loc" -type f 2>/dev/null)
    done

    # systemd units/timers with suspicious ExecStart (common modern persistence)
    while IFS= read -r unit; do
        [[ -z "$unit" ]] && continue
        if grep -qE 'ExecStart=.*(curl|wget|nc |ncat|/dev/tcp|bash -i|/tmp/|/dev/shm/|base64)' "$unit" 2>/dev/null; then
            ((ISSUES_FOUND++)) || true
            log_critical "Suspicious systemd unit: $unit"
            grep -nE 'ExecStart=' "$unit" 2>/dev/null | head -3 | sed 's/^/    /'
        fi
    done < <(find /etc/systemd/system /run/systemd/system -maxdepth 2 -name '*.service' -o -name '*.timer' 2>/dev/null)
}

# ==============================================================================
# RUN ALL CHECKS
# ==============================================================================
run_sweep() {
    ISSUES_FOUND=0
    ISSUES_FIXED=0

    if [[ "$QUIET" == "false" ]]; then
        echo "========================================"
        echo "SECURITY SWEEP — $(date)"
        echo "========================================"
        [[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}DRY RUN — no changes will be made${NC}"
        echo ""
    fi

    check_ld_preload
    check_ld_so_preload
    check_rc_local
    check_mod_rootme
    check_suspicious_libs
    check_other_persistence

    echo ""
    if [[ "$ISSUES_FOUND" -eq 0 ]]; then
        log_info "Security sweep complete — system clean"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_warning "Issues found: $ISSUES_FOUND (dry-run, nothing changed)"
        else
            log_warning "Issues found: $ISSUES_FOUND | Fixed: $ISSUES_FIXED"
        fi
    fi
}

# ==============================================================================
# MAIN
# ==============================================================================
if [[ "$LOOP_MINUTES" -gt 0 ]]; then
    echo "========================================"
    echo "SECURITY SWEEP — LOOP MODE"
    echo "Interval: every ${LOOP_MINUTES} minutes"
    echo "========================================"
    echo ""

    while true; do
        run_sweep
        echo ""
        log_info "Next sweep in ${LOOP_MINUTES} minutes..."
        sleep "$((LOOP_MINUTES * 60))"
    done
else
    run_sweep
fi

exit 0
