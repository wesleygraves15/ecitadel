# eCitadel - Review of `linux/postHardenTools` (detection & scan layer)

Reviewed the `postHardenTools` scripts, ignoring Firejail / Suricata / Kubernetes
as requested. Picked the core set that covers the main persistence + integrity +
auth + web attack surface, debugged and refined them, and added the strict-egress
option to the firewall generator. All six below are `bash -n` clean and
`shellcheck -S warning` zero-warning; the ones that can run on a non-target host
were exercised live.

## Core set (and why)

| Picked | Covers |
|---|---|
| `securitySweep.sh` | LD_PRELOAD / ld.so.preload / rc.local / mod_rootme persistence (+ new: keys/sudoers/cron/systemd) |
| `packageVerify.sh` | Trojanized system binaries via `rpm -V` / `dpkg -V` |
| `suidCleanup.sh` | SUID/SGID privilege-escalation surface (GTFOBins) |
| `pamManager.sh` | PAM auth backdoors (pam_permit, unknown/world-writable modules, empty passwords) |
| `webshellScan.sh` | PHP webshells on the web box (concierge) |
| `firewallGenerator.sh` | Your granular per-host firewall tool (egress feature added) |

**Not picked:** `binaryVerify.sh` overlaps `packageVerify.sh` (same package-checksum
mechanism); `postscreenConfig.sh` is Postfix-only and you have no mail box;
`setDnsResolver.sh`, `ttyDestroyer.sh`, `linpeasDeploy.sh`, `securityScannerSetup.sh`,
`normalizeToolsGeneral.sh` are situational utilities, not core scans. They're fine
to keep around, just not part of the core detection loop.

---

## firewallGenerator.sh — egress feature + 4 bug fixes

### NEW: strict egress (your request)
Added an option to allow **only ESTABLISHED/RELATED outbound** — the box can answer
connections made to it, but cannot initiate any new outbound connection.

- CLI: `--out-established-only` (alias `--strict-egress`)
- Menu: prompt **#10** ("STRICT EGRESS")

When on, it skips every outbound NEW rule (even if you selected Splunk-fwd /
Salt-minion / DNS / updates), drops the blanket outbound ICMP accept, and forces
`OUTPUT` policy `DROP` (even on a K8s node). Verified by dry-run:

```
normal  (--ssh --dns-resolver --splunk-fwd):
   OUTPUT: established/related + ICMP + NEW 53,8089,9997   policy DROP
strict  (... --out-established-only):
   OUTPUT: established/related ONLY                        policy DROP
```

Trade-off to be aware of: strict egress blocks DNS, package updates, agent
check-ins (Splunk/Wazuh/Salt), and DB egress, because those are all *new* outbound
connections. Use it on hosts that should never originate traffic. Replies to
inbound (including ping replies) still work via the ESTABLISHED,RELATED rule.

### Bugs fixed
1. **SYN rate-limit defeated the allow-list.** The original did
   `--syn -m limit --limit 25/sec -j ACCEPT` then `--syn -j DROP`. The blanket
   under-rate ACCEPT accepted new SYNs to **any** port before the per-port rules
   ran, so any listening service was reachable regardless of what you opened.
   Replaced with a per-source `hashlimit --hashlimit-above 25/sec ... -j DROP`
   that only drops the over-rate SYNs and lets legitimate SYNs fall through to the
   explicit per-port rules (custom-chain fallback if `xt_hashlimit` is absent).
2. **Failsafe confirmation was inverted.** Answering "yes" killed the timer but
   never persisted and never printed success; answering "no"/timeout still killed
   the timer and **saved** the locked-down rules — the opposite of a failsafe.
   Rewrote it: yes -> save + confirm; no/timeout -> revert to open immediately.
3. **`--help` had side effects.** `prepare_os` (masks firewalld, installs
   iptables packages) ran before help was handled. Help is now processed first.
4. **rsyslog filter missed `FW-FRAG`.** Broadened the match from `FW-DROP` to
   `FW-` so fragment/synflood drops are logged too.

---

## securitySweep.sh — 2 bugs, 1 FP, 1 softening, 1 new check

1. **Apache config globs never expanded.** The config list stored glob strings
   (`/etc/httpd/conf.d/*.conf`) in an array and tested them with `[[ -f ]]`, which
   doesn't expand globs — so drop-in configs (where a real `mod_rootme` Include
   usually hides) were never scanned. Rewrote with `nullglob` to build a real file
   list (added `sites-enabled/*.conf`).
2. **`.so` find precedence bug.** `find -name "*.so" -o -name "*.so.*"` only
   printed the `*.so.*` matches (the implicit `-print` bound to the last term),
   missing plain `*.so`. Grouped the predicates with `\( \)`.
3. **False-positive auto-rename.** The on-disk `mod_rootme` search used
   `-name "*rootme*"`, which matched unrelated files (it flagged a MkDocs
   `rootme.svg` here and, in non-dry-run, would have renamed it). Tightened to
   shared objects only. Also made temp-dir `.so` handling **report-only by
   default** (legit software stages libs in `/tmp`, `/dev/shm`); pass
   `--quarantine-libs` to actually move them.
4. **LD_LIBRARY_PATH softened.** The original auto-commented any `LD_*` export,
   including `LD_LIBRARY_PATH`, which legitimate tooling (Splunk, Oracle) sets and
   would break. Now `LD_PRELOAD`/`LD_AUDIT` are auto-disabled (high-confidence
   backdoors) while `LD_LIBRARY_PATH` is flagged for review only.
5. **NEW report-only CHECK 6** to cover persistence the original missed:
   reappearing SSH `authorized_keys`, `NOPASSWD` sudoers drop-ins, suspicious cron
   (`/etc/cron.d`, user crontabs) and systemd units/timers with beacon-like
   `ExecStart`. Detection only — these are too easy to break by auto-removing.
   Also validated the `--loop` argument is numeric.

---

## packageVerify.sh — rpm verify detection bug

`rpm -V` status columns are `1=S(ize) 2=M(ode) 3=5(digest)`. The filter
`^(S|.{4}5)` looked for the digest flag in **column 5**, so a checksum-only change
(the primary trojanized-binary signal) slipped through. Replaced with an explicit
parse of the status token that flags Size, Mode, digest, or `missing` on
non-config files.

---

## suidCleanup.sh — minor

Path discovery unioned `which` + `find` but only `sort -u`'d the `find` half, so a
binary found by both was processed (and counted) twice. Unified both into one
`sort -u`; switched `which` to `command -v`. Otherwise the script was sound — the
GTFOBins list deliberately excludes the binaries that are legitimately SUID
(`su`, `sudo`, `passwd`, `mount`, `ping`).

---

## webshellScan.sh — dispatch bug + default-root

- **`--watch` watched a directory named `--watch`.** `SCAN_DIR="${1:-/var/www}"`
  ran before argument parsing, so the flag itself became the scan target. Moved
  directory resolution into each dispatch branch.
- Added `resolve_default_root()` so the default picks the first existing of
  `/var/www`, `/var/www/html`, `/usr/share/nginx/html`, `/srv/www`, `/srv/http` —
  nginx's docroot on Fedora is no longer missed.
- Verified it flags a planted `eval($_POST[...])` shell as CRITICAL.

Otherwise this one was already well written (proper `set -e` guarding, sensible
critical-vs-suspicious pattern split).

---

## pamManager.sh — solid; one cleanup

Thorough and correct: detects `pam_permit` as sufficient/required auth, unknown
modules, world-writable / recently-modified modules, empty-password and MD5-hashed
accounts, and has a package-based emergency restore behind a typed confirmation.
Only change: the unknown-module membership test used a quoted regex on the
right-hand side of `=~` (matches literally, not as a regex — SC2076); switched to
the standard glob-membership form. Left the rest as-is.

---

## Validation summary
`bash -n` clean and `shellcheck -S warning` zero-warning on all six. Live-exercised
on a non-target host: firewall egress modes (shimmed iptables), securitySweep full
dry-run through all six checks, webshell scan against a planted shell, suidCleanup
dry-run, pamManager audit. The `rpm -V` path in packageVerify needs a real RHEL/
Fedora host to exercise end-to-end. Run `securitySweep.sh -n` and
`firewallGenerator.sh` from the console (not the SSH session you depend on) the
first time.
