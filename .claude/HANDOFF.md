# Handoff — mwWhoIs / DomainCheckr

> Resume point. Keep current: update as tasks start/finish so any session can
> pick up without re-reading the brief, the whole codebase, or prior chat.
> Last updated: **2026-07-10** (deep-analysis + remediation session).

## ⚠️ Immediate state — 15 local commits on `beta`, PENDING PUSH

`local beta` (`1d7d696`) is **15 commits ahead of `origin/beta`** (`793bb29`) — a
clean fast-forward. **Nothing has been pushed** (awaiting explicit owner go-ahead
per git-safety rules). All changes are in `web/public_html_beta/` only;
production `web/public_html/` is untouched. `php -l` clean across all touched files.

When authorised: `git push origin beta`. That will trigger the beta SFTP deploy +
auto version-bump CI. Do **not** auto-advance `alpha` with these dev commits
(alpha realignment was a one-off; alpha becomes base-dev only when the owner switches).

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
