# eCitadel - Review of `linux/initialHarden` + tailored box scripts

Reviewed the master scripts and modules under `linux/initialHarden/` plus the
`postHardenTools` they call. Everything parses (`bash -n` clean across all 13
files); the problems are runtime/logic, not syntax. Findings below are ordered
by how badly they bite you in a live round.

---

## 1. CRITICAL - `modules/generalLinuxHarden.sh` aborts mid-hardening (silently)

This module is run first by every master, and as written it does **not finish**.
Two independent abort points, both under `set -euo pipefail`:

- **`set -e` + `chmod` on an absent compiler (line 167).**
  `chmod 000 /usr/bin/clang 2>/dev/null` has no `|| true`. `clang` is usually not
  installed, so `chmod` returns non-zero, and `set -e` kills the script right
  there. The redirect hides the message but not the exit.

- **`set -u` + `SCRIPT_DIR` used before it's defined (line 170).**
  `SCRIPT_DIR` is referenced at line 170 (`[[ -f "$SCRIPT_DIR/../../postHardenTools/suidCleanup.sh" ]]`)
  but only assigned at **line 289**. Under `set -u` that's an immediate
  "unbound variable" abort.

Net effect: the script sets banners and wipes cron, then dies **before** sysctl
hardening, SUID/SGID cleanup, the security sweep, package verification, and
enumeration. And because the masters call it as `bash "$script" 2>&1 | tee ...`
with no exit-code check, the master prints **"General Linux Hardening completed"**
regardless. You think the box is hardened; most of the hardening never ran.

A third, smaller one: line 292 calls `bash .../normalizeToolsSecurity.sh` with no
existence guard, and that file **is not in the repo** -> exit 127 (also masked).

I reproduced all three failure modes in isolation:

```
TEST 1  set -u, SCRIPT_DIR before def   -> "SCRIPT_DIR: unbound variable", exit 1
TEST 2  set -e, chmod absent clang       -> dies at chmod,                 exit 1
TEST 3  set -e, bash missing script      -> exit 127
```

**Fixed** in the replacement `modules/generalLinuxHarden.sh`:
- `SCRIPT_DIR` (and a derived `POSTHARDEN_DIR`) defined at the top, before any use.
- Dropped `set -e` (kept `-u` + `pipefail`, matching the masters) and added
  `|| true` on every best-effort op; compiler-lock now loops over binaries that
  actually exist.
- Guarded the `normalizeToolsSecurity.sh` call (and the other helper calls).
- Smoke-tested end-to-end with all helpers stubbed: it now reaches
  "SYSTEM HARDENING COMPLETE" and degrades to `[WARN]` instead of aborting.

---

## 2. HIGH - Hardcoded credentials in a public repo

- `generalLinuxHarden.sh`: `svcadmin:Changeme1!`
- `master-fedora-webmail.sh` / `master-ubuntu-ecom.sh`: `sysadmin_backup:Backup@dmin2024!`

This repo is public. A static admin password in it is free red-team access on
every box you deploy to. In the rewrite, `svcadmin` gets a **random** password
recorded root-only to `/root/.ecitadel_creds` (0600), and the tailored masters
**drop the `sysadmin_backup` account entirely** (the general module already
provisions emergency admin `bbob`). Rotate/replace these regardless.

---

## 3. HIGH - `modules/harden_ecom.sh` is Debian/Apache-only; won't run on Fedora

22 references to `apt`/`a2enmod`/`/etc/apache2`/`ufw`; zero to `dnf`/`httpd`/
`firewall-cmd`/SELinux. Your web box (concierge) is **Fedora 43**, where Apache
is `httpd`, modules and paths differ, the firewall is firewalld, and SELinux is
enforcing. This module is a no-op-to-broken there. Replaced with a Fedora-native
`harden_web_fedora.sh` (below).

---

## 4. MEDIUM - `mysqlharden.sh` is interactive and offers to rotate the DB root password

Fine as an interactive tool, dangerous in an automated round: a prompt stalls the
pipeline, and rotating the DB password mid-game desyncs the web app's stored
credential and tanks the scored service. The new `harden_db.sh` is
non-interactive and **never changes passwords**.

---

## 5. MEDIUM - Firewall issues in the stock masters

- **Default `DROP` policy is set first** (e.g. ecom lines 179-181), *then* the
  loopback/established/SSH rules are added. There's a window where your own SSH
  session can be cut. The tailored masters build the ruleset with policies on
  `ACCEPT`, add loopback/established/SSH/services, and flip to `DROP` **last**.
- **ecom opens 3306 to `127.0.0.1` only** (line 225). That rule is also dead -
  loopback is already accepted on `lo`. For a *dedicated* DB box that serves a
  *remote* web box, the DB port must be reachable from concierge (172.21.0.102),
  not localhost. Handled in `master-blacklist-debian-db.sh`.
- No outbound NTP (123). Time drift breaks Kerberos against the DC and muddies
  log correlation. Added to both tailored masters.

---

## Per-file verdict

| File | Verdict |
|---|---|
| `modules/generalLinuxHarden.sh` | **Broken** (aborts mid-run). Replaced. |
| `modules/ssh_harden.sh` | Solid. Validates config, rolls back on failure. Reused as-is. |
| `modules/harden_ecom.sh` | Debian/Apache-only. Replaced for Fedora. |
| `modules/mail_hardener.sh` | Mail box only - not in your topology. Skip. |
| `modules/systemBackups.sh`, `systemBaseline.sh`, `masterEnum.sh` | No `set -e`; reusable as-is. |
| `postHardenTools/misc/MySQL/mysqlharden.sh` | Interactive + rotates pw. Avoid mid-round; use `harden_db.sh`. |
| `postHardenTools/normalizeToolsSecurity.sh` | **Missing from repo** (called unguarded). Guarded in rewrite. |
| stock masters | Hardcoded creds + DROP-first firewall + localhost-only DB rule. Tailored versions provided. |

---

## What I built for your three Linux-relevant boxes

Drop these into the repo so the relative paths to `modules/` and
`../../postHardenTools/` keep resolving:

```
linux/initialHarden/master-blacklist-debian-db.sh      <- blacklist (Debian 13, DB)
linux/initialHarden/master-concierge-fedora-web.sh     <- concierge (Fedora 43, Web)
linux/initialHarden/modules/generalLinuxHarden.sh      <- DEBUGGED drop-in replacement
linux/initialHarden/modules/harden_db.sh               <- new, non-interactive DB hardener
linux/initialHarden/modules/harden_web_fedora.sh       <- new, Fedora web hardener
thebox-pfsense-hardening.md                            <- pfSense is FreeBSD: checklist, not a script
```

**blacklist (172.21.0.101):** general + SSH + DB hardening (auto-detects
MariaDB/MySQL vs PostgreSQL; removes anonymous users, drops `test`, removes remote
root, binds for the network, enables logging, **no password changes**) + firewall
that exposes the DB port **only to 172.21.0.102** (edit `DB_ALLOWED` if the DB is
scored directly) + DB dump/backups.

**concierge (172.21.0.102):** general + SSH + Fedora web hardening (httpd/nginx
aware, security headers, no-listing, conservative PHP, `httpd_can_network_connect_db`
SELinux boolean, config validated with auto-rollback) + cockpit/firewalld removal +
firewall in[22,80,443] / out to DB box + agents + web config/docroot backup.

**thebox (pfSense):** see the markdown checklist.

### Before you run them
1. Read each master top-to-bottom - confirm the agent ports (Salt/Wazuh/Splunk)
   match your SOC and that `WEB_HOST`/`DB_HOST`/`DB_ALLOWED` match the scoreboard.
2. Run at the **console**, not over the SSH session you care about, the first time.
3. The general module prompts for root/bbob/sysadmin passwords at a TTY; run
   non-interactively and it generates randoms into `/root/.ecitadel_creds`.

### Validation done here
`bash -n` clean and `shellcheck -S warning` **zero warnings** on all five scripts;
fixed general module smoke-tested to completion with helpers stubbed. Not executed
against live Debian/Fedora targets - do a dry run on a snapshot if you can.
