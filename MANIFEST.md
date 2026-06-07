# eCitadel CCDC-SOC — script bundle (self-contained)

Reviewed, debugged, and tailored defensive scripts for the eCitadel network:
- blacklist  172.21.0.101  Debian 13  Database
- concierge  172.21.0.102  Fedora 43  Web
- cabal      172.21.0.103  Windows AD Domain Controller (the Linux boxes are AD clients)
- thebox     pfSense edge (FreeBSD — see the checklist, not a script)

This bundle is SELF-CONTAINED: every script the masters call is included. Keep the
directory layout intact — `linux/initialHarden/modules/` and `linux/postHardenTools/`
must stay as siblings, because `generalLinuxHarden.sh` reaches the post-harden tools
via `../../postHardenTools`. All shell scripts are `bash -n` clean and `shellcheck`
zero-warning. Run masters from the console (not the SSH session you depend on) the
first time. Read the two REVIEW files first.

## linux/initialHarden/  — first-touch hardening (run the master once)
- master-blacklist-debian-db.sh   : Orchestrates the Debian DB box. Firewall now allows AD-client egress to the DC.
- master-concierge-fedora-web.sh  : Orchestrates the Fedora web box. Firewall now allows AD-client egress to the DC.
- modules/generalLinuxHarden.sh   : Debugged baseline hardener (sysctl, accounts, banners, kernel knobs).
- modules/harden_db.sh            : Non-interactive MariaDB/MySQL/PostgreSQL hardening (no password changes).
- modules/harden_web_fedora.sh    : Fedora httpd/nginx hardening with SELinux booleans + auto-rollback.
- modules/ssh_harden.sh           : SSH hardening via drop-in; `sshd -t` validate + auto-rollback; lockout-safe root handling.
- modules/systemBackups.sh        : Backs up /etc, auth files, cron, firewall rules, package/service inventory to /root.
- modules/systemBaseline.sh       : Snapshots system state and reports drift (new listeners/SUID/users/services) on re-run.
- modules/masterEnum.sh           : Read-only situational-awareness report (accounts, sockets, cron, SUID, AD join status).

## linux/postHardenTools/  — detection & scan layer (run repeatedly during play)
- firewallGenerator.sh   : Granular per-host iptables tool; strict egress via `--out-established-only` / `--strict-egress`.
- securitySweep.sh       : Detects/neutralizes persistence (LD_PRELOAD, ld.so.preload, rc.local, mod_rootme, keys/sudoers/cron/systemd).
- packageVerify.sh       : Flags trojanized binaries via rpm -V / dpkg -V; can reinstall to restore.
- suidCleanup.sh         : Strips SUID/SGID from known privesc binaries (GTFOBins).
- pamManager.sh          : Audits PAM for auth backdoors; emergency package-based restore.
- webshellScan.sh        : Scans web roots for PHP webshells; one-shot, --watch, or --quarantine.

## AD / Active Directory note
Both masters define `DC_HOST="172.21.0.103"` and open outbound to the DC for
Kerberos 88, kpasswd 464, LDAP 389 (tcp+udp), LDAPS 636, and Global Catalog
3268/3269. DNS 53 and NTP 123 (also needed for AD/Kerberos) are already permitted.
If you have more than one DC, space-separate them in `DC_HOST`.

## Database access (works for MariaDB/MySQL OR PostgreSQL - auto-detected)
The blacklist master has ONE allow-list, `DB_CLIENTS` (default: the web box), that
drives both gates so they can't drift:
  - the iptables rule that exposes the DB port, and
  - (PostgreSQL only) the pg_hba.conf host rules in harden_db.sh.
If the DB is DIRECTLY SCORED, add the scoring source to `DB_CLIENTS`, e.g.
`DB_CLIENTS="$WEB_HOST 172.21.0.250"` or `DB_CLIENTS="172.21.0.0/24"`, and both the
firewall and pg_hba update together. MariaDB/MySQL is not host-locked by the
script (the firewall is the gate) - just ensure the scoring DB user's grant allows
its host (`user@'%'` or `@'<ip>'`). harden_db.sh changes NO passwords.

## top level
- REVIEW.md                         : Findings + fixes for the initialHarden layer.
- linux/postHardenTools/REVIEW-postHardenTools.md : Findings + fixes for the detection layer + strict-egress.
- thebox-pfsense-hardening.md       : pfSense is FreeBSD — a console/WebGUI hardening checklist.

## Validation
bash -n clean + shellcheck zero-warning on all 15 scripts. Live-exercised where
possible (enum, baseline, backups, firewall egress modes, sweeps). The `rpm -V`
path (packageVerify) and ssh_harden's reload need a real Fedora/Debian host with
OpenSSH to exercise end-to-end.
