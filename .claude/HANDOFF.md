# Handoff — mwWhoIs / DomainCheckr

> Resume point. Keep current: update as tasks start/finish so any session can
> pick up without re-reading the brief, the whole codebase, or prior chat.
> Last updated: **2026-07-10** (deep-analysis + remediation session).

## ⚠️ Immediate state (2026-07-11) — #196 in progress; 2 unpushed commits

The pre-PR batch below (39 commits) **was PUSHED** to `origin/beta`; CI's version-bump +
changelog ran green on the new single-source structure (now v1.50.1, `a6e6532`) — validating
the workflow restructure end-to-end. `origin/main` untouched. **No PR open yet.**

**#196 (progressive-loading re-arch) — ✅ CODE-COMPLETE (all 7 steps).** Plan + per-step
status/commits: `.claude/plans/196-progressive-loading.md`. Step 1 (`aed2e12`) is pushed +
CI-green; **8 more commits (Steps 3–7 + 2) are local on `beta`, unpushed, clean fast-forward.**
- Backend fully verified: **149 PHPUnit tests / 629 assertions green**, live `php -S` smoke
  (modules=core returns the completed core payload + clean JSON, back-compat 51 keys).
- The module API: `POST /lookup?modules=core|dns|web|email|reputation|subdomains|score`,
  rate-exempt HMAC `lookup_token`, per-module caches; progressive core-first frontend;
  reputation+subdomains parallelised (curl_multi/dig, SSRF-safe); OpenAPI documented.
- Found+fixed along the way: PHP 8.4 `session.sid_length` deprecation that was corrupting
  ALL JSON API responses (`a51766a`); a bracketed-IPv6 SSRF bypass in the batch helper.

**⬜ REMAINING for #196:** (1) push the 8 commits; (2) **browser/visual verification of the
progressive UX** — no browser in the build sandbox, so Steps 5–6 (frontend) are verified by
construction + syntax + trace, NOT a rendered check. Load the app and confirm: core paints
fast, tabs fill progressively with skeletons, DNT hides reputation, available/IP trim, no
stale bleed on re-search.

**Local `beta` is 19 commits ahead of `origin/beta`, unpushed, clean fast-forward.**
(8 = #196; then #212, #213, #218-safe cleanup, PHP-8.4 fix, CI intl; then promoted features
#246 SSL cert depth [chain trust/hostname/key-alg, closed] + #225 EPP status explainers [open,
browser-verify]; then #218 deferred appLog wiring + grade-threshold unify. 171 tests green.)
`php -l` clean; 149 tests green; tree clean. Sandbox caveat: DNS hangs on CAA/TLSA → the
web-module live domain path can't be exercised here (environmental, not a code bug).

### (historical) pre-PR batch — 39 commits, since pushed

**Four tranches sit in these 39 commits:** (A) deep-analysis remediation (15 commits);
(B) single-source deploy **restructure** (8 commits incl. the config auto-merge);
(C) **pre-PR batch** — remaining perf + security + safe fixes + OpenAPI (16 commits).

### Pre-PR batch done (2026-07-10 pt4) — owner selected all four batches
- **Perf Phase-1 finish:** #189 full-response cache · #192 hard curl timeouts + crt.sh/redirect caps · #193 TLD refresh off request path · #194 propagation completion fix + `dns_propagation_max=25` · #195 SMTP egress skip.
- **Security:** #197 **SSRF egress gate** (`resolveAndVetHost`, blocks private/reserved, IP-pinning, re-vets redirect hops — agent self-caught 2 bypasses) · #198 CSRF/API-key required on JSON + `?suggest=1`, wildcard CORS removed.
- **Safe fixes/hardening:** #202 admin key via header + Referrer-Policy · #203 HSTS + host allow-list + appLog newline · #214 SW cache bound · #215 RDAP-404 confirm · #216 availability-unknown · #217 IP display · #218 firstARecord/guards/cache-backend.
- **Docs/infra:** #245 OpenAPI refresh (51-prop schema, X-API-Key auth, Retry-After now sent on 429). #204 CLOSED (`.auth` + auto-merge). Created 5 **Milestones**, the **DomainCheckr Development** project (#14), assigned all 64 issues.

### Backlog cleared this session (2026-07-11) — all closed, on `beta` unpushed
- **#196** progressive-loading re-arch — CODE-COMPLETE (7 steps, 149→155 tests). Open, awaiting push + browser verify.
- **#212** IDN/punycode support (`dfe86b2` + CI `b8a9f36`) — closed.
- **#213** bulk 429 graceful pause/resume (`dd34a1e`) — closed.
- **#218** cleanup batch safe subset (`f04a21a`, `29682a4`) — done; strict_types/module-split/appLog/grade-thresholds deferred (issue left open to track).
- PHP 8.4 `session.sid_length` deprecation — FIXED (`a51766a`; it was corrupting JSON responses).
- All of #187–#210, #214–#217 verified + **closed**.

### 🟡 Still needs an OWNER DECISION (autonomous backlog is otherwise exhausted)
- **#211 watch/monitor pipeline** — the missing link is client→server watch registration + the model: **(a)** anonymous/global watch list, **(b)** per-session, or **(c)** requires the account system (#163). monitor.php (#200) + the RSS feed + CDATA are already fixed/hardened; only the registration+model is blocked. **Needs your call before building.**
- **Enable the GitHub Wiki** (Settings → Features → Wikis) + first page → then `scratchpad/wiki-Home.md` can be pushed.
- **`for consideration` features #219–#247** and the older feature backlog **#146–#181** — promote the ones you want built.
- **`stash@{0}`** broken infoAppVer edit (#186) — salvage or `git stash drop`.
- **Stale `origin` URL** (`Salem874/mwWhoIs` → redirects to `MWBMPartners/phpWhoIs`) — `git remote set-url` when ready.

### 🔴 BEFORE PUSHING — owner must set GitHub secrets (Settings → Secrets and variables → Actions)
The deploy pipeline was rewritten. It now needs:
- **`SFTP_DEV_PATH`** = server path to `public_html_dev_alpha` (NEW — for the alpha branch).
- Confirm **`SFTP_BETA_PATH`** → `public_html_dev_beta` and **`SFTP_LIVE_PATH`** → `public_html`.
- **All three SFTP path secrets must have NO trailing slash** (the `.auth` sibling
  deploy derives its path via `dirname`, exactly like iHymns).
Without `SFTP_DEV_PATH`, alpha simply won't deploy (harmless). Push to `beta` deploys
to `public_html_dev_beta` and does NOT touch production.

## Restructure session (2026-07-10 pt3) — single-source deploy (iHymns-style)

The repo now matches iHymns / WebMS-Intra: ONE web-accessible source `web/public_html/`;
branch chooses the SFTP target (`main→public_html`, `beta→public_html_dev_beta`,
`alpha→public_html_dev_alpha`). API keys moved out of `config.php` into a gitignored
`web/.auth/keys.php` (loaded via `dirname(__DIR__,2).'/.auth/'`; deployed above web root,
real `keys.php` never clobbered). The 7 restructure commits:
| SHA | What |
|---|---|
| `4fcab25` | consolidate `public_html_beta` → single `web/public_html/` (beta was newest); drop stale pre-header.php |
| `f89385d` | API keys → gitignored `web/.auth/` (`.htaccess` + `keys.example.php` tracked); `.gitignore` + config.php loader (#204) |
| `4d309e7` | rewrite `deploy.yml`: single source, main/beta/alpha → LIVE/BETA/DEV, `.auth` sibling deploy, removed beta→prod sync job |
| `6c36f0b` | repoint version-bump/changelog/update-dns-resolvers workflows at `web/public_html/` + alpha; fixed hardcoded `push origin beta` (would corrupt beta from alpha) |
| `7bb177e` | fix tests/bootstrap.php path (test suite was broken post-consolidation) |
| `f50b711` | update README/DEV_NOTES/CLAUDE docs to the single-source model |

Also fixed in passing: infoAppVer.php dev-status detection now reads the CI-injected
`.env-channel` (the old `__DIR__` folder check is dead under single-source).

When authorised: `git push origin beta` (clean fast-forward). Monitor deploy + CI.
Do **not** auto-advance `alpha` with these dev commits.

## #197 + #198 — DONE (in the pre-PR batch above). Only #196 remains from that trio.
- **#196 progressive-loading re-architecture** — still deferred; its own focused pass (big; touches lookup.php/index.php/functions.php). This is the last major latency win (Phase 2 parallelise + Phase 3 progressive modules) after the Phase-1 work already landed.

### The 15 deep-analysis commits (oldest→newest)

### The 15 commits (oldest→newest)
| SHA | Issue | What |
|---|---|---|
| `a285837` | #187 | perf: portable timeout on whois/dig subprocesses (kills the 30–130s hang) |
| `a70c23b` | #188 | perf: `session_write_close()` before network work (de-serialize concurrent reqs) |
| `38633e1` | #190 | perf: skip enrichment pipeline for available domains |
| `1261b0f` | #191 | perf: remove dead DNSBLs + duplicate DNS_ANY + double Spamhaus |
| `6a1df22` | #199 | security: escape parsed WHOIS fields (stored XSS) |
| `d025fb0` | #200 | security: monitor.php CLI-only guard + fix undefined `parseWhois()` |
| `1ea10df` | #201 | security: CSV formula-injection neutralisation in exports |
| `4601ec9` | #205 | fix: enforce API-key tier rate limits |
| `1391f6c` | #206 | fix: add missing `domain` key to HTML-format response |
| `6d151de` | #207 | fix: correct HTTP-version detection (1.1 misreported as 2) |
| `f368e31` | #208 | fix: stop infoAppVer.php else nulling the Application ID |
| `d406340` | #210 | fix: footer reads correct watch-list localStorage key |
| `d75fab2` | #209 | fix: delete stale pre-header.php (footer before doctype in terms.php) |
| `3efad4f` | #248 | docs: rewrite Privacy Policy (actual data practices) |
| `1d7d696` | #248 | docs: rewrite Terms of Service |

## Deep-analysis + remediation session (2026-07-10) — what happened

Ran **4 sequential Fable 5 agents** (never parallel, per standing rule) over the
whole beta codebase: (1) performance, (2) code-quality/lint, (3) security, (4)
feature ideation. Root cause of the ~60s lookups: **`lookup.php` runs ~40 external
enrichment checks strictly serially in one blocking request**, with an unbounded
`whois` subprocess, a session-lock that serializes concurrent requests, near-useless
caching (only WHOIS text cached), a 187-resolver `dig` fork-storm with a
partial-results bug, dead DNSBL zones, and available-domains paying full price.

**61 issues filed (#187–#247)** + docs issue **#248**:
- **Perf #187–#196** (10) — Phase-1 quick wins + the re-arch epic #196 (Phase 2 parallelise / Phase 3 progressive modules).
- **Security #197–#204** (8) — **#197 Critical SSRF** (needs owner egress-policy decision), #198 CSRF/CORS, #199 XSS, #200 monitor, #201 CSV, #202 admin-key-in-URL, #203 header hardening, #204 gitignore config.
- **Bugs #205–#218** (14) incl. #218 code-quality cleanup batch + module-split map.
- **For-consideration features #219–#247** (`for consideration` label) + #247 the recommended-against reference list.

### Done this session (the 15 commits above): #187,#188,#190,#191,#199,#200,#201,#205,#206,#207,#208,#209,#210,#248.

## Open items / decisions pending (owner)

- **PUSH the 15 beta commits** (gated). Then verify the latency improvement on the live beta deploy.
- **#197 Critical SSRF** — needs an egress-policy decision (block private ranges vs. allow-list) before implementing the `resolveAndVetHost()` gate. Highest-priority security item.
- **#198 CSRF/CORS on the JSON+suggest API** — changes the public API contract; owner call (ties to #197).
- **#196 perf re-arch (Phase 2/3)** — the big latency win beyond Phase 1; larger, owner-directed.
- **#204 gitignore config.php** — deferred (deploy could delete live config; Low severity). Coordinate with the deploy workflow first.
- **#213 bulk >30 rate-limit**, **#212 IDN support**, **#211 watch/monitor wiring** — design/feature calls.
- **`stash@{0}`** — abandoned broken `infoAppVer.php` bundle-ID edit (see #186). NOTE: the *committed* infoAppVer.php inverted-else bug was fixed separately (#208, `f368e31`); the stash is a different, syntactically-broken edit still pending salvage-or-drop.
- **Stale `origin` URL** → `Salem874/mwWhoIs` (redirects to `MWBMPartners/phpWhoIs`). Fix: `git remote set-url origin https://github.com/MWBMPartners/phpWhoIs.git` (`.git/config` change needs go-ahead).
- **Local `main`** 2 behind `origin/main` (harmless).

## Next steps when resuming

1. Get go-ahead to **push beta**; monitor the beta deploy CI; verify lookup latency.
2. Decide the **SSRF egress policy (#197)** → implement the gate (Sonnet) → then #198.
3. Continue the remaining perf issues (#189 full-response cache, #192 curl timeouts, #193 TLD-refresh off-path, #194 propagation fix, #195 SMTP skip) — all Phase-1, safe, Sonnet-implementable.
4. Then the **standing docs sweep** (Standing Task #6): README/CHANGELOG, GitHub **Wiki / Project / Milestones** (none exist — create), and refresh **OpenAPI** (`assets/api/openapi.yaml`) — incl. the newly-documented behaviours (#245).
5. Work the bug backlog #211–#218 and triage the `for consideration` features #219–#247.

## Prior session (branch cleanup) — 2026-07-10 pt1 (for reference)
Issues **#185** (standing tasks/in-repo Claude docs) and **#186** (branch cleanup)
CLOSED. `alpha` advanced to `beta` (aligned), merged TLD branch deleted, `main`
untouched. Remote branches: `main`, `beta`, `alpha`. (The CI version-bump to
v1.50.0 = `793bb29` sits on top of that work and is now `origin/beta`.)
