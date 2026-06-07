#!/bin/bash
# ==============================================================================
# Script Name: packageVerify.sh
# Description: Verifies installed package integrity using rpm -V or dpkg -V.
#              Detects tampered system binaries and offers to reinstall affected
#              packages to restore them to their original state.
# Author: Security Team
# Date: 2025-2026
# Version: 1.0
#
# Usage:
#   ./packageVerify.sh [options]
#
# Options:
#   -h, --help      Show this help message
#   -f, --fix       Automatically reinstall packages with verification failures
#   -n, --dry-run   Show what would be reinstalled without doing it
#   -q, --quiet     Only show failures, not clean packages
#   -c, --critical  Only check critical packages (coreutils, openssh, sudo, etc.)
#
# What It Checks:
#   - rpm -V (RHEL/Fedora/Oracle): Size, Mode, MD5, Device, Links, User, Group, Time, Caps
#   - dpkg -V (Debian/Ubuntu): Checksums of installed files
#
# Understanding rpm -V output:
#   S = Size differs         c = config file
#   M = Mode differs         d = documentation
#   5 = MD5 sum differs      g = ghost file
#   D = Device major/minor   l = license file
#   L = readLink path        r = readme file
#   U = User ownership
#   G = Group ownership
#   T = mTime differs
#   P = caPabilities
#
# Exit Codes:
#   0 - All packages verified OK
#   1 - Verification failures found
#   3 - Permission denied
# ==============================================================================

set -uo pipefail

# --- Configuration ---
FIX_MODE=false
DRY_RUN=false
QUIET=false
CRITICAL_ONLY=false
FAILURES=0
FIXED=0

# Critical packages to check when --critical is used
CRITICAL_PACKAGES_RPM=(
    coreutils bash sudo openssh-server openssh-clients shadow-utils
    util-linux systemd pam cronie glibc findutils grep sed gawk
    procps-ng iproute net-tools curl wget
)
CRITICAL_PACKAGES_DEB=(
    coreutils bash sudo openssh-server openssh-client passwd login
    util-linux systemd libpam-runtime cron libc6 findutils grep sed
    gawk procps iproute2 net-tools curl wget
)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_fixed() { echo -e "${GREEN}[FIXED]${NC} $1"; }

usage() {
    head -40 "$0" | grep -E "^#" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 3
    fi
}

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)     usage ;;
        -f|--fix)      FIX_MODE=true; shift ;;
        -n|--dry-run)  DRY_RUN=true; shift ;;
        -q|--quiet)    QUIET=true; shift ;;
        -c|--critical) CRITICAL_ONLY=true; shift ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

check_root

echo "========================================"
echo "PACKAGE INTEGRITY VERIFICATION"
echo "========================================"
[[ "$DRY_RUN" == "true" ]] && echo -e "${YELLOW}DRY RUN — no packages will be reinstalled${NC}"
echo ""

# Detect package manager
if command -v rpm &>/dev/null && command -v dnf &>/dev/null; then
    PKG_MGR="rpm"
    INSTALL_CMD="dnf"
elif command -v rpm &>/dev/null && command -v yum &>/dev/null; then
    PKG_MGR="rpm"
    INSTALL_CMD="yum"
elif command -v dpkg &>/dev/null && command -v apt-get &>/dev/null; then
    PKG_MGR="dpkg"
    INSTALL_CMD="apt-get"
else
    log_error "No supported package manager found (need rpm+dnf/yum or dpkg+apt-get)"
    exit 1
fi

log_info "Package manager: $PKG_MGR (installer: $INSTALL_CMD)"
echo ""

# Track packages that need reinstall
declare -A FAILED_PACKAGES

if [[ "$PKG_MGR" == "rpm" ]]; then
    if [[ "$CRITICAL_ONLY" == "true" ]]; then
        log_info "Verifying critical packages only..."
        packages_to_check=("${CRITICAL_PACKAGES_RPM[@]}")
    else
        log_info "Verifying all installed packages (this may take a while)..."
        mapfile -t packages_to_check < <(rpm -qa --queryformat '%{NAME}\n' 2>/dev/null | sort -u)
    fi

    for pkg in "${packages_to_check[@]}"; do
        # Check if package is installed
        if ! rpm -q "$pkg" &>/dev/null; then
            continue
        fi

        output=$(rpm -V "$pkg" 2>/dev/null || true)
        if [[ -n "$output" ]]; then
            # Filter out config file changes (expected) unless they include size/md5 changes
            critical_changes=""
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                # Skip config file changes (marked with 'c') — config edits are expected
                if echo "$line" | grep -qE '\s+c\s+/'; then
                    continue
                fi
                # rpm -V status field columns: 1=S(ize) 2=M(ode) 3=5(digest) ...
                # The ORIGINAL regex `^(S|.{4}5)` looked for the digest flag in column 5,
                # so a checksum-only change (the primary trojan signal) slipped through.
                # Parse the status token and flag Size, Mode, digest, or missing files.
                status=$(echo "$line" | awk '{print $1}')
                if [[ "${status:0:1}" == "S" || "${status:1:1}" == "M" || "${status:2:1}" == "5" \
                      || "$status" == "missing" ]]; then
                    critical_changes+="$line"$'\n'
                fi
            done <<< "$output"

            if [[ -n "$critical_changes" ]]; then
                ((FAILURES++)) || true
                FAILED_PACKAGES["$pkg"]=1
                log_warning "VERIFICATION FAILED: $pkg"
                echo "$output" | while IFS= read -r line; do
                    echo "    $line"
                done
            fi
        else
            [[ "$QUIET" == "false" ]] && echo -e "  ${GREEN}[OK]${NC} $pkg"
        fi
    done

elif [[ "$PKG_MGR" == "dpkg" ]]; then
    if [[ "$CRITICAL_ONLY" == "true" ]]; then
        log_info "Verifying critical packages only..."
        for pkg in "${CRITICAL_PACKAGES_DEB[@]}"; do
            if ! dpkg -l "$pkg" &>/dev/null 2>&1; then
                continue
            fi

            output=$(dpkg -V "$pkg" 2>/dev/null || true)
            if [[ -n "$output" ]]; then
                ((FAILURES++)) || true
                FAILED_PACKAGES["$pkg"]=1
                log_warning "VERIFICATION FAILED: $pkg"
                echo "$output" | while IFS= read -r line; do
                    echo "    $line"
                done
            else
                [[ "$QUIET" == "false" ]] && echo -e "  ${GREEN}[OK]${NC} $pkg"
            fi
        done
    else
        log_info "Verifying all installed packages..."
        output=$(dpkg -V 2>/dev/null || true)
        if [[ -n "$output" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                # Extract file path and find owning package
                file_path=$(echo "$line" | awk '{print $NF}')
                pkg=$(dpkg -S "$file_path" 2>/dev/null | head -1 | cut -d: -f1)
                if [[ -n "$pkg" ]]; then
                    ((FAILURES++)) || true
                    FAILED_PACKAGES["$pkg"]=1
                    log_warning "TAMPERED: $file_path (package: $pkg)"
                fi
            done <<< "$output"
        else
            log_info "All packages verified OK"
        fi
    fi
fi

# --- Fix Mode ---
if [[ $FAILURES -gt 0 && ("$FIX_MODE" == "true" || "$DRY_RUN" == "true") ]]; then
    echo ""
    echo "========================================"
    echo "REINSTALLING FAILED PACKAGES"
    echo "========================================"
    echo ""

    for pkg in "${!FAILED_PACKAGES[@]}"; do
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "  WOULD REINSTALL: $pkg"
        else
            log_info "Reinstalling: $pkg"
            if [[ "$INSTALL_CMD" == "dnf" || "$INSTALL_CMD" == "yum" ]]; then
                if $INSTALL_CMD reinstall -y "$pkg" &>/dev/null; then
                    log_fixed "$pkg reinstalled"
                    ((FIXED++)) || true
                else
                    log_error "Failed to reinstall: $pkg"
                fi
            elif [[ "$INSTALL_CMD" == "apt-get" ]]; then
                if apt-get install --reinstall -y "$pkg" &>/dev/null; then
                    log_fixed "$pkg reinstalled"
                    ((FIXED++)) || true
                else
                    log_error "Failed to reinstall: $pkg"
                fi
            fi
        fi
    done
fi

# --- Summary ---
echo ""
echo "========================================"
echo "PACKAGE VERIFICATION COMPLETE"
echo "========================================"
echo "Packages with failures: $FAILURES"
if [[ "$FIX_MODE" == "true" && "$DRY_RUN" == "false" ]]; then
    echo "Packages reinstalled: $FIXED"
fi
echo "========================================"

[[ $FAILURES -gt 0 ]] && exit 1
exit 0
