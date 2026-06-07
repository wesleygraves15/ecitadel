#!/bin/bash
# ==============================================================================
# harden_web_fedora.sh - Fedora-native web hardening for the eCitadel web box
# Target: concierge (Fedora 43, 172.21.0.102) - Web role
#
# The repo's harden_ecom.sh is Debian/Apache-only (apt, a2enmod, /etc/apache2).
# None of that exists on Fedora. This module is the Fedora equivalent: httpd or
# nginx, dnf, SELinux booleans, config validation with automatic rollback so a
# bad directive can never take down the scored site.
#
# Usage: sudo ./harden_web_fedora.sh
# ==============================================================================
set -uo pipefail

log()  { echo "[WEB][INFO] $*"; }
warn() { echo "[WEB][WARN] $*" >&2; }

[[ $EUID -ne 0 ]] && { echo "[WEB][ERROR] must run as root"; exit 1; }

# ------------------------------------------------------------------------------
# DETECT WEB SERVER
# ------------------------------------------------------------------------------
WEB="none"
if systemctl is-active --quiet httpd 2>/dev/null || command -v httpd >/dev/null 2>&1; then
    WEB="httpd"
elif systemctl is-active --quiet nginx 2>/dev/null || command -v nginx >/dev/null 2>&1; then
    WEB="nginx"
fi
log "Detected web server: $WEB"

# ------------------------------------------------------------------------------
# APACHE (httpd) HARDENING
# ------------------------------------------------------------------------------
harden_httpd() {
    local DROPIN="/etc/httpd/conf.d/zz-ecitadel-hardening.conf"
    log "Writing hardening drop-in: $DROPIN"
    cat > "$DROPIN" << 'EOF'
# eCitadel Apache hardening (drop-in; loaded after main config)
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None

# Security response headers (mod_headers)
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>

# No directory listings under the docroot; deny dotfiles
<Directory "/var/www">
    Options -Indexes -Includes -ExecCGI FollowSymLinks
    AllowOverride None
</Directory>

<FilesMatch "^\.(ht|git|svn|env)">
    Require all denied
</FilesMatch>
EOF

    # Validate before committing. Roll back the drop-in if config is broken.
    local cfgtest="httpd -t"; command -v apachectl >/dev/null 2>&1 && cfgtest="apachectl configtest"
    if $cfgtest 2>/tmp/httpd_test; then
        log "httpd config valid; reloading."
        systemctl reload httpd 2>/dev/null || systemctl restart httpd 2>/dev/null || warn "Could not reload httpd."
    else
        warn "httpd config INVALID after drop-in - removing it to protect the scored site:"
        cat /tmp/httpd_test >&2
        rm -f "$DROPIN"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# NGINX HARDENING
# ------------------------------------------------------------------------------
harden_nginx() {
    local DROPIN="/etc/nginx/conf.d/zz-ecitadel-hardening.conf"
    log "Writing hardening drop-in: $DROPIN (http context)"
    cat > "$DROPIN" << 'EOF'
# eCitadel nginx hardening (included in http context on Fedora)
server_tokens off;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
EOF

    if nginx -t 2>/tmp/nginx_test; then
        log "nginx config valid; reloading."
        systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || warn "Could not reload nginx."
    else
        warn "nginx config INVALID after drop-in - removing it to protect the scored site:"
        cat /tmp/nginx_test >&2
        rm -f "$DROPIN"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# PHP HARDENING (only the no-break-the-app settings)
# ------------------------------------------------------------------------------
harden_php() {
    local ini="/etc/php.ini"
    [[ -f "$ini" ]] || { log "No /etc/php.ini; skipping PHP."; return; }
    log "Hardening $ini (expose_php, error display, cookie flags)"
    cp -a "$ini" "${ini}.bak.$(date +%s)" 2>/dev/null || true
    sed -i 's/^\s*expose_php\s*=.*/expose_php = Off/'                     "$ini" 2>/dev/null || true
    sed -i 's/^\s*display_errors\s*=.*/display_errors = Off/'             "$ini" 2>/dev/null || true
    sed -i 's/^\s*log_errors\s*=.*/log_errors = On/'                      "$ini" 2>/dev/null || true
    grep -qiE '^\s*session.cookie_httponly' "$ini" \
        && sed -i 's/^\s*session.cookie_httponly\s*=.*/session.cookie_httponly = 1/' "$ini" \
        || echo 'session.cookie_httponly = 1' >> "$ini"
    # NOTE: not touching disable_functions / allow_url_fopen here - those can break a
    #       scored app. Add them by hand once you know the app tolerates it.
    systemctl restart php-fpm 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# SELINUX (Fedora-specific): let the web app reach the remote database
# ------------------------------------------------------------------------------
harden_selinux() {
    command -v getenforce >/dev/null 2>&1 || { log "SELinux tools absent; skipping."; return; }
    log "SELinux mode: $(getenforce 2>/dev/null)"
    # If enforcing, the PHP app cannot open a remote DB socket unless this is on.
    setsebool -P httpd_can_network_connect_db on 2>/dev/null && log "set httpd_can_network_connect_db=on" || true
    # NOTE: deliberately NOT flipping permissive->enforcing here. Forcing enforcing
    #       mid-competition can break an app with mislabeled files. If you want
    #       enforcing, do it explicitly and watch the audit log:
    #         setenforce 1 && ausearch -m avc -ts recent
}

case "$WEB" in
    httpd) harden_httpd || warn "Apache hardening backed out." ;;
    nginx) harden_nginx || warn "nginx hardening backed out." ;;
    *)     warn "No web server detected." ;;
esac
harden_php
harden_selinux

log "Web hardening complete. Verify the scored service still answers:"
log "  curl -I http://localhost/"
log "  curl -Ik https://localhost/"
