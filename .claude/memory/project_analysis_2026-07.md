---
name: Deep-analysis pass & remediation backlog (2026-07)
description: Root cause of slow lookups, the #187-#248 issue backlog it produced, and what's fixed vs pending.
metadata:
  type: project
---

On 2026-07-10 a deep-analysis pass ran **4 sequential Fable 5 agents** (perf,
code-quality, security, feature ideation) over `web/public_html_beta/`. See
[[workflow-process-standing-tasks]] for why sequential (owner rule) and
[[domaincheckr-mwwhois-project-overview]] for the architecture.

**Root cause of the ~60s lookups:** `lookup.php` runs ~40 external enrichment
checks strictly **serially** in one blocking request. Aggravators: unbounded
`whois` shell_exec; no `session_write_close()` (session lock serializes
concurrent requests); only WHOIS text cached (cache hits still re-run ~35
checks); 187-resolver `dig` fork-storm with a partial-results bug; dead DNSBL
zones; available domains pay full price.

**Backlog created:** GitHub issues **#187–#248**.
- Perf #187–#196 (epic #196 = re-arch into fast CORE + progressive modules).
- Security #197–#204 — **#197 = Critical SSRF (no private-range block on
  outbound fetchers); needs an owner egress-policy decision before fixing.**
- Bugs #205–#218 (#218 = cleanup batch + module-split map for the 2810-line
  functions.php / 2441-line index.php).
- `for consideration` features #219–#247 (#247 = the recommended-against list).
- #248 = Privacy/Terms rewrite.

**Fixed this session (15 local commits on `beta`, `a285837`..`1d7d696`,
PENDING PUSH):** #187,#188,#190,#191 (perf Phase-1) · #199,#200,#201 (safe
security) · #205,#206,#207,#208,#209,#210 (bugs) · #248 (Privacy/Terms + delete
stale pre-header.php). All Sonnet-implemented, `php -l` clean, prod untouched.

**Key pending:** push+verify the 15 commits; decide SSRF egress policy (#197)
then CSRF/CORS (#198); remaining safe perf issues #189/#192/#193/#194/#195;
the docs sweep. Full detail in `.claude/HANDOFF.md`.

**Positive controls confirmed (don't regress):** no SQL (no DB); command
injection properly defended (escapeshellarg + isValidDomain blocklist); IP
rate-limit uses REMOTE_ADDR (not spoofable); session hardening solid; WHOIS raw
blob is server-escaped; API keys stored as SHA-256 hashes.
