#!/bin/bash
# ==============================================================================
# harden_db.sh - Non-interactive database hardening for the eCitadel DB box
# Target: blacklist (Debian 13, 172.21.0.101) - Database role
#
# Detects MariaDB/MySQL or PostgreSQL and applies competition-safe hardening:
#   - Removes anonymous users and the 'test' database
#   - Removes ALL remote root logins (keeps localhost root)
#   - Binds the engine to listen for the web box (firewall does the restriction)
#   - Enables logging
#
# IT DELIBERATELY DOES NOT ROTATE ANY PASSWORDS. The web app (concierge) holds
# the DB credential in its config; silently rotating root or the app user mid
# competition desyncs that and tanks the scored service. Rotate manually, in
# lockstep with the app config, if you must.
#
# Usage: sudo ./harden_db.sh
# ==============================================================================
set -uo pipefail

# --- Who is allowed to reach the DB over the network (the web box) ---
WEB_HOST="${WEB_HOST:-172.21.0.102}"

log()  { echo "[DB][INFO] $*"; }
warn() { echo "[DB][WARN] $*" >&2; }

[[ $EUID -ne 0 ]] && { echo "[DB][ERROR] must run as root"; exit 1; }

# ------------------------------------------------------------------------------
# ENGINE DETECTION
# ------------------------------------------------------------------------------
ENGINE="none"
if systemctl list-units --type=service 2>/dev/null | grep -qiE 'mariadb|mysql' \
   || command -v mysqld >/dev/null 2>&1 || command -v mariadbd >/dev/null 2>&1 \
   || command -v mysql >/dev/null 2>&1; then
    ENGINE="mysql"
elif systemctl list-units --type=service 2>/dev/null | grep -qi 'postgres' \
   || command -v psql >/dev/null 2>&1; then
    ENGINE="postgres"
fi
log "Detected engine: $ENGINE"

# ==============================================================================
# MARIADB / MYSQL
# ==============================================================================
harden_mysql() {
    # Find a working admin connection without assuming a password.
    local MYSQL_CMD=""
    if mysql -u root -e "SELECT 1" &>/dev/null; then
        MYSQL_CMD="mysql -u root"                      # unix_socket auth (MariaDB/Debian default)
    elif [[ -f /root/.my.cnf ]] && mysql --defaults-extra-file=/root/.my.cnf -e "SELECT 1" &>/dev/null; then
        MYSQL_CMD="mysql --defaults-extra-file=/root/.my.cnf"
    else
        warn "Could not authenticate to MySQL/MariaDB (no socket auth, no /root/.my.cnf)."
        warn "Skipping SQL-level hardening; will still bind + log. Create /root/.my.cnf and re-run for full SQL hardening."
    fi

    if [[ -n "$MYSQL_CMD" ]]; then
        log "Removing anonymous users..."
        $MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null \
            || $MYSQL_CMD -e "DROP USER IF EXISTS ''@'localhost', ''@'$(hostname)';" 2>/dev/null || true

        log "Dropping 'test' database if present..."
        $MYSQL_CMD -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
        $MYSQL_CMD -e "DELETE FROM mysql.db WHERE Db LIKE 'test%';" 2>/dev/null || true

        log "Removing remote root logins (keeping localhost)..."
        local remote_roots
        remote_roots="$($MYSQL_CMD -N -e \
            "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null || true)"
        if [[ -n "$remote_roots" ]]; then
            while IFS= read -r ur; do
                [[ -z "$ur" ]] && continue
                local u="${ur%@*}" h="${ur#*@}"
                $MYSQL_CMD -e "DROP USER IF EXISTS '$u'@'$h';" 2>/dev/null \
                    && log "  dropped $ur" || warn "  could not drop $ur"
            done <<< "$remote_roots"
        fi

        $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null || true
        log "SQL hardening done (no passwords changed)."
    fi

    # --- Config: bind so the web box can connect; firewall restricts to WEB_HOST ---
    local cnf=""
    for c in /etc/mysql/mariadb.conf.d/50-server.cnf \
             /etc/mysql/mysql.conf.d/mysqld.cnf \
             /etc/my.cnf.d/mariadb-server.cnf \
             /etc/my.cnf; do
        [[ -f "$c" ]] && { cnf="$c"; break; }
    done

    if [[ -n "$cnf" ]]; then
        cp -a "$cnf" "${cnf}.bak.$(date +%s)" 2>/dev/null || true
        log "Editing $cnf"
        # bind-address: must NOT be 127.0.0.1 since the app is remote. Restriction is enforced by iptables.
        if grep -qE '^\s*bind-address' "$cnf"; then
            sed -i 's/^\s*bind-address.*/bind-address = 0.0.0.0/' "$cnf"
        else
            sed -i '/^\[mysqld\]/a bind-address = 0.0.0.0' "$cnf"
        fi
        # Disable LOAD DATA LOCAL INFILE (common exfil/abuse vector)
        grep -qE '^\s*local-infile' "$cnf" || sed -i '/^\[mysqld\]/a local-infile = 0' "$cnf"
        # Don't follow symlinks
        grep -qE '^\s*symbolic-links' "$cnf" || sed -i '/^\[mysqld\]/a symbolic-links = 0' "$cnf"
        # Error + general logging
        grep -qE '^\s*log_error' "$cnf" || sed -i '/^\[mysqld\]/a log_error = /var/log/mysql/error.log' "$cnf"
        mkdir -p /var/log/mysql 2>/dev/null || true
        chown mysql:mysql /var/log/mysql 2>/dev/null || true
    else
        warn "No MySQL/MariaDB server config found to edit."
    fi

    log "Restarting database service..."
    systemctl restart mariadb 2>/dev/null || systemctl restart mysqld 2>/dev/null \
        || systemctl restart mysql 2>/dev/null || warn "Could not restart DB service automatically."
}

# ==============================================================================
# POSTGRESQL
# ==============================================================================
harden_postgres() {
    # Locate active config + hba (works for Debian's versioned layout and generic).
    local conf hba
    conf="$(sudo -u postgres psql -tAc 'SHOW config_file;' 2>/dev/null || true)"
    hba="$(sudo -u postgres psql -tAc 'SHOW hba_file;' 2>/dev/null || true)"
    if [[ -z "$conf" ]]; then
        conf="$(find /etc/postgresql -name postgresql.conf 2>/dev/null | head -1)"
        hba="$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)"
    fi
    [[ -z "$conf" ]] && { warn "postgresql.conf not found; skipping."; return; }

    log "postgresql.conf: $conf"
    log "pg_hba.conf:     $hba"
    cp -a "$conf" "${conf}.bak.$(date +%s)" 2>/dev/null || true
    [[ -n "$hba" ]] && cp -a "$hba" "${hba}.bak.$(date +%s)" 2>/dev/null || true

    # Listen for remote web box; firewall restricts to WEB_HOST.
    if grep -qE "^\s*#?\s*listen_addresses" "$conf"; then
        sed -i "s/^\s*#\?\s*listen_addresses.*/listen_addresses = '*'/" "$conf"
    else
        echo "listen_addresses = '*'" >> "$conf"
    fi
    # Log connections/disconnections for detection
    sed -i "s/^\s*#\?\s*log_connections.*/log_connections = on/"        "$conf" 2>/dev/null || echo "log_connections = on"    >> "$conf"
    sed -i "s/^\s*#\?\s*log_disconnections.*/log_disconnections = on/"  "$conf" 2>/dev/null || echo "log_disconnections = on" >> "$conf"

    if [[ -n "$hba" ]]; then
        # Force strong auth and scope the web host. Append an explicit allow + a catch-all reject.
        if ! grep -qE "host\s+all\s+all\s+${WEB_HOST}/32\s+scram-sha-256" "$hba"; then
            log "Adding scram-sha-256 host rule for web box ${WEB_HOST}"
            echo "host    all             all             ${WEB_HOST}/32          scram-sha-256" >> "$hba"
        fi
        # Reject everything else over TCP (local peer/ident lines above still apply)
        grep -qE "^\s*host\s+all\s+all\s+0\.0\.0\.0/0\s+reject" "$hba" \
            || echo "host    all             all             0.0.0.0/0               reject" >> "$hba"
    fi

    log "Reloading PostgreSQL..."
    systemctl reload postgresql 2>/dev/null || systemctl restart postgresql 2>/dev/null \
        || warn "Could not reload PostgreSQL automatically."
}

case "$ENGINE" in
    mysql)    harden_mysql ;;
    postgres) harden_postgres ;;
    *)        warn "No database engine detected. Nothing to harden." ;;
esac

log "Database hardening complete. Verify the scored connection from the web box:"
log "  MySQL/MariaDB:  mysql -h 172.21.0.101 -u <appuser> -p"
log "  PostgreSQL:     psql -h 172.21.0.101 -U <appuser> -d <appdb>"
