#!/bin/bash
#
# Universal Linux Hardening Script (RHEL/Ubuntu/Debian) - No Firewall
# Usage: sudo ./generalLinuxHarden.sh
#
# DEBUGGED FOR eCITADEL. Changes vs the original (see REVIEW.md):
#   1. SCRIPT_DIR is now defined at the TOP, before any reference. The original
#      defined it on line 289 but referenced it on line 170, so under `set -u`
#      the script aborted with "SCRIPT_DIR: unbound variable" before sysctl,
#      SUID cleanup, the security sweep, package verify, or enum ever ran.
#   2. Dropped `set -e` (kept -u and pipefail) and added `|| true` to every
#      best-effort op. The original aborted at the first `chmod 000` of an
#      absent binary (e.g. clang) because the failing chmod tripped `set -e`.
#      A hardening script must push through best-effort steps, not die on the
#      first missing optional binary.
#   3. Removed the step-7 enumeration + normalizeTools* calls. Enumeration is run
#      by the box master (PHASE 6, backgrounded) to avoid a double run, and the
#      normalizeTools* helpers are not part of this bundle.
#   4. Removed the hardcoded `svcadmin:Changeme1!` credential. This repo is
#      public; a static password = free red-team access. Now generated random
#      and written root-only to /root/.ecitadel_svcadmin_cred (0600).
#   5. tty-aware password prompts: prompts at a console, random+stored when
#      run non-interactively, so the master flow never hangs on `read`.
#

set -uo pipefail

# --- 0. OS DETECTION & PRE-CHECKS ---
if [ "$(id -u)" != "0" ]; then
   echo "ERROR: Must be run as root."
   exit 1
fi

# Resolve our own directory FIRST so every later reference is safe under set -u.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POSTHARDEN_DIR="$(cd "$SCRIPT_DIR/../../postHardenTools" 2>/dev/null && pwd || echo "$SCRIPT_DIR/../../postHardenTools")"

# Detect OS family for Package Manager & Service names
if [ -f /etc/debian_version ]; then
    OS_FAMILY="debian"
    GROUP_ADMIN="sudo"
    PKG_MGR="apt-get"
    echo "Detected Debian/Ubuntu system."
    export DEBIAN_FRONTEND=noninteractive
elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="rhel"
    GROUP_ADMIN="wheel"
    PKG_MGR="dnf"
    echo "Detected RHEL/Fedora system."
else
    echo "Unsupported OS. Exiting."
    exit 1
fi
echo "OS_FAMILY=$OS_FAMILY  PKG_MGR=$PKG_MGR  ADMIN_GROUP=$GROUP_ADMIN"

# --- CONFIGURATION ---
LOG_DIR="/var/log/syst"
LOG_FILE="$LOG_DIR/harden_$(date +%F).log"
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "==================================================="
echo "      STARTING UNIVERSAL HARDENING (NO FW)"
echo "==================================================="

# --- HELPER FUNCTIONS ---
gen_pass() {
    # 20-char URL-safe random password
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 18 | tr -d '/+=' | cut -c1-20
    else
        tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
    fi
}

prompt_password() {
    local user_label=$1
    local var_name=$2
    # Non-interactive (no controlling tty): generate + record, never block on read.
    if [ ! -t 0 ]; then
        local generated; generated="$(gen_pass)"
        declare -g "$var_name=$generated"
        echo "[non-interactive] Generated password for $user_label -> recorded in /root/.ecitadel_creds"
        umask 077
        echo "$user_label: $generated" >> /root/.ecitadel_creds
        chmod 600 /root/.ecitadel_creds 2>/dev/null || true
        return 0
    fi
    while true; do
        echo -n "Enter new password for $user_label: "
        stty -echo; read -r pass1; stty echo; echo
        echo -n "Confirm new password for $user_label: "
        stty -echo; read -r pass2; stty echo; echo
        if [ "$pass1" == "$pass2" ] && [ -n "$pass1" ]; then
            declare -g "$var_name=$pass1"
            break
        else
            echo "Passwords do not match or are empty. Try again."
        fi
    done
}

# --- 1. CREDENTIAL SETUP ---
echo "[+] Phase 1: User & Password Setup"
prompt_password "ROOT User" ROOT_PASS
prompt_password "Emergency Admin (bbob)" BBOB_PASS

if id "sysadmin" &>/dev/null; then
    prompt_password "SYSADMIN User" SYSADMIN_PASS
else
    SYSADMIN_PASS=""
fi

echo "Updating passwords..."
echo "root:$ROOT_PASS" | chpasswd

if [ -n "$SYSADMIN_PASS" ]; then
    echo "sysadmin:$SYSADMIN_PASS" | chpasswd
    echo "Updated sysadmin password."
fi

# Emergency admin user
if ! id "bbob" &>/dev/null; then
    echo "Creating emergency admin 'bbob'..."
    useradd -m -s /bin/bash bbob
fi
echo "bbob:$BBOB_PASS" | chpasswd
usermod -aG "$GROUP_ADMIN" bbob || true

# --- Service Admin Account (random password, recorded root-only) ---
SVC_PASS="$(gen_pass)"
if ! id "svcadmin" &>/dev/null; then
    echo "Creating service admin account 'svcadmin'..."
    useradd -m -s /bin/bash svcadmin
fi
echo "svcadmin:$SVC_PASS" | chpasswd
usermod -aG "$GROUP_ADMIN" svcadmin || true
umask 077
echo "svcadmin: $SVC_PASS" >> /root/.ecitadel_creds
chmod 600 /root/.ecitadel_creds 2>/dev/null || true
echo "Service account 'svcadmin' ready (password recorded in /root/.ecitadel_creds)."

# Lock standard passwordless accounts (best-effort; may not exist on all distros)
for u in sync games lp; do passwd -l "$u" 2>/dev/null || true; done

# --- 3. SYSTEM HARDENING ---
echo "[+] Phase 3: System Hardening"

echo "Setting Banners..."
echo "UNAUTHORIZED ACCESS PROHIBITED. ALL ACTIVITY IS MONITORED AND RECORDED. VIOLATIONS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW." > /etc/issue
cp /etc/issue /etc/motd
cp /etc/issue /etc/issue.net

echo "Nuking Cron jobs..."
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
rm -rf /var/spool/cron/* 2>/dev/null || true
rm -rf /var/spool/cron/crontabs/* 2>/dev/null || true
if [[ -f /etc/crontab ]]; then
    grep -E '^\s*(#|SHELL=|PATH=|MAILTO=|HOME=|LOGNAME=|$)' /etc/crontab > /tmp/crontab_clean || true
    mv /tmp/crontab_clean /etc/crontab
    chmod 644 /etc/crontab
fi

echo "Restricting Permissions on Critical Compilers (Anti-Compile)..."
# Best-effort: only touch binaries that actually exist (no set -e abort on absent ones).
for c in gcc g++ make cc clang ld as; do
    p="$(command -v "$c" 2>/dev/null || true)"
    if [ -n "$p" ]; then
        chmod 000 "$p" 2>/dev/null && echo "  locked $p" || true
    fi
done

echo "Running comprehensive SUID/SGID cleanup (GTFOBins)..."
if [[ -f "$POSTHARDEN_DIR/suidCleanup.sh" ]]; then
    bash "$POSTHARDEN_DIR/suidCleanup.sh" -q 2>&1 | tee -a "$LOG_FILE" || true
else
    echo "[WARN] suidCleanup.sh not found, falling back to basic SUID removal"
    for bin in find vim nmap less awk sed python python3 perl ruby tar zip netcat nc man; do
        BINARY_PATH="$(command -v "$bin" 2>/dev/null || true)"
        [ -n "$BINARY_PATH" ] && chmod u-s "$BINARY_PATH" 2>/dev/null && echo "Removed SUID from $bin" || true
    done
fi

echo "Setting Kernel parameters (Sysctl)..."
SYSCTL_HARDEN="/etc/sysctl.d/99-security-hardening.conf"
[[ -f "$SYSCTL_HARDEN" ]] && cp "$SYSCTL_HARDEN" "${SYSCTL_HARDEN}.backup" || true

cat > "$SYSCTL_HARDEN" << 'SYSCTL_EOF'
# Kernel Hardening - Sysctl Configuration
# --- NETWORK SECURITY - IPv4 ---
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
# --- IPv6 - DISABLE (competition is IPv4-only) ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
# --- KERNEL SECURITY ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
# --- FILESYSTEM SECURITY ---
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
# --- MEMORY SECURITY ---
vm.mmap_min_addr = 65536
SYSCTL_EOF

# Apply (some keys may be rejected on a given kernel/arch; that is non-fatal).
sysctl -p "$SYSCTL_HARDEN" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true
echo "Kernel hardening applied: $SYSCTL_HARDEN"

# Restrict the service account to nologin and strip admin group membership.
usermod -s /usr/sbin/nologin svcadmin 2>/dev/null || usermod -s /sbin/nologin svcadmin 2>/dev/null || true
gpasswd -d svcadmin sudo  2>/dev/null || true
gpasswd -d svcadmin wheel 2>/dev/null || true

# --- 4. SECURITY SWEEP (LD_PRELOAD, mod_rootme, rc.local, suspicious libs) ---
echo "[+] Phase 4: Security Sweep"
if [[ -f "$POSTHARDEN_DIR/securitySweep.sh" ]]; then
    bash "$POSTHARDEN_DIR/securitySweep.sh" -q 2>&1 | tee -a "$LOG_FILE" || true
else
    echo "[WARN] securitySweep.sh not found - skipping"
fi

# --- 5. PACKAGE INTEGRITY VERIFICATION ---
echo "[+] Phase 5: Package Integrity Verification"
if [[ -f "$POSTHARDEN_DIR/packageVerify.sh" ]]; then
    bash "$POSTHARDEN_DIR/packageVerify.sh" -c -q 2>&1 | tee -a "$LOG_FILE" || true
else
    echo "[WARN] packageVerify.sh not found - skipping"
fi

# --- 6. BACKGROUND SECURITY SWEEP LOOP ---
echo "[+] Phase 6: Starting Background Security Sweep"
if [[ -f "$POSTHARDEN_DIR/securitySweep.sh" ]]; then
    nohup bash "$POSTHARDEN_DIR/securitySweep.sh" -l 3 -q >> "$LOG_DIR/security_sweep.log" 2>&1 &
    echo "Security sweep loop started (PID: $!) - logs at $LOG_DIR/security_sweep.log"
else
    echo "[WARN] securitySweep.sh not found - background loop not started"
fi

# --- 7. (enumeration is run by the box master in its PHASE 6, backgrounded, so it
#         is intentionally NOT invoked here to avoid running the big enum twice.
#         The normalizeTools* helpers are not part of this bundle and were removed.)
echo "Baseline hardening steps complete."

echo "==================================================="
echo "        SYSTEM HARDENING COMPLETE"
echo "Enumeration report: $LOG_DIR/"
echo "Generated creds (if any): /root/.ecitadel_creds"
echo "Good luck!"
echo "==================================================="
