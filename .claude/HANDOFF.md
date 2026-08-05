# Handoff Document — mwWhoIs

> Living document. Update as work progresses so any session can resume instantly.
> Last updated: 2026-08-05 (session: daily-update-tasks-failures — round 2).

---

## ⏱️ ACTIVE SESSION (2026-08-05) — NEW failure: CSV fetch timeout on `alpha`

**This is a DIFFERENT bug from the 2026-08-04 path-mismatch fix (that one is DONE and live on all branches).**

### What happened
Daily "Update DNS Resolvers" run **#134** (run_id 30977141653, 2026-08-05 05:07 UTC): the
**matrix workflow is now working** (both legs run) — `update (beta)` **succeeded** (14s), but
`update (alpha)` **failed** (40s) at the CSV fetch:
```
Fetching https://public-dns.info/nameservers.csv ...     @ 05:07:31.004
Error: failed to fetch CSV from public-dns.info          @ 05:08:01.677   (= 30.7s)
```

### Root cause (CONFIRMED)
`scripts/update-dns-resolvers.php` (~lines 81-88) fetches the CSV with a **single**
`@file_get_contents($csvUrl, false, $ctx)` — `'timeout' => 30`, **no retry, no fallback**,
and `exit(1)` on ANY failure. The 30.7s gap == the 30s stream timeout → the fetch **timed out**
for the alpha runner while the beta runner (seconds apart) got through. A transient upstream
slowness thus turns a **non-critical daily maintenance job red** and emails the owner a false alarm.

### Branch ground truth (re-verified 2026-08-05 — supersedes stale notes further down)
- `public_html_beta/` **exists on ALL of alpha, beta, main** (layouts have re-converged).
- `scripts/update-dns-resolvers.php`, `.github/workflows/update-dns-resolvers.yml`,
  `docs.php` (10745B) and `assets/api/openapi.yaml` (16328B) are **byte-identical across
  alpha/beta/main** and our working HEAD. No divergence — docs/OpenAPI work is now LOW risk
  (beta's feared "v1.50 ~1500-line openapi" is NOT present; current is the 16KB version everywhere).
- Working branch `claude/daily-update-tasks-failures-q0w1xt`: PR #253 already merged into alpha.
  This session **merged `origin/alpha` back in** (non-destructive, no force-push) so the branch is
  a strict superset of alpha → the NEXT PR (to be created later, when owner asks) shows a clean diff.

### Plan for this session (in order)
1. **[phase 1 — PRIMARY]** Harden the CSV fetch: retry + exponential backoff, timeout tuning,
   empty/garbage-body guard, **soft-fail** (`::warning::` + exit 0, keep last-known-good) on total
   fetch failure vs **hard-fail** on malformed CSV / write / syntax errors. Add a dependency-free
   PHPUnit test (fail-then-succeed / all-fail). Deep analysis via **Fable 5** (running now).
2. **[phase 2]** Thorough docs sweep: README.md (PHP version, branch flow, DNS auto-update),
   **SECURITY.md** (replace GitHub stub with a real policy), in-app `docs.php`, `.claude/` memory.
3. **[phase 2]** OpenAPI/Swagger: refresh `assets/api/openapi.yaml` to match current features;
   **vendor Swagger UI locally** (assets/vendor/swagger-ui/) for shared hosting + fix the
   `docs.php:200` broken `SwaggerUIStandalonePreset` reference + CSP self-hosting.
4. Per task: individual commit + push to working branch, update/close the GitHub issue, update
   `.claude/` memory + this handoff. **No PR stacking** — one branch, one later PR to `alpha`.

### Progress (this session)
- [done] Root cause confirmed from run #134 logs (30.7s == stream timeout).
- [done] Branch ground truth re-verified; branch brought up to date with alpha (merge 503e84b).
- [done] Docs surface scoped (README/SECURITY/docs.php/openapi all read).
- [in progress] Fable 5 deep-analysis of the fetch fix (agent running).
- [pending] phases 1 & 2 implementation.

---

## Current working branch

`claude/daily-update-tasks-failures-q0w1xt` (based on `main`, will target **`alpha`** via a single PR created later).

**Branch flow:** `claude/*` → `alpha` → `beta` → `main` (production).

**Rules in force (standing instructions — see `.claude/memory/standing_instructions.md`):**
- Deep analysis & deep planning: **sequential Fable 5 agents** (fall back to Opus if unavailable; retry Fable first each run).
- Implementation: **Sonnet or Haiku** (Opus only if complex). GIRFT — token-efficient, correct first time.
- After each task: commit + push to the working branch, update the relevant GitHub issue(s), update `.claude/` memory/context, update this handoff.
- **No PR stacking** — one branch, one PR later. Do not open multiple PRs.
- Work autonomously; only pause for decisions that genuinely need the user.

## The problem being solved

Daily "Update DNS Resolvers" GitHub Action fails every day ("All jobs have failed").

### Root cause (CONFIRMED via run logs, run_id 30879730451)

Scheduled workflows execute the workflow file from the **default branch (`main`)**, but this
workflow does `checkout ref: beta`. On the **beta** branch, `web/public_html_beta/` does **not
exist** — beta keeps its files in `web/public_html/`.

- The updater step (beta's `scripts/update-dns-resolvers.php`) writes to
  `web/public_html/includes/dns_resolvers.php` and **passes** ("Syntax check passed").
- The next step, *"Check for changes"*, runs
  `git diff --quiet web/public_html_beta/includes/dns_resolvers.php` — a path not in beta's
  working tree → `fatal: ... unknown revision or path not in the working tree` → exit 128.
- Because the step shell is `bash -e`, the job fails. Every day.

### Cross-branch state (ground truth)

| Branch | `web/public_html_beta/` exists? | script writes to | workflow refs |
|--------|-------------------------------|------------------|---------------|
| alpha  | yes                           | public_html_beta | public_html_beta |
| beta   | **no** (only public_html)     | public_html      | public_html_beta |
| main   | yes                           | public_html_beta | public_html_beta |

The workflow **always** checks out `beta`, so it must reference the path that exists on beta
(`public_html`). The safest, drift-proof fix is to make the **script auto-detect** the resolver
file (prefer `public_html_beta`, else `public_html`) and make the **workflow** use a path-glob
(`web/*/includes/dns_resolvers.php`) that matches whichever exists.

### Secondary issue

The script rewrites the "Last updated" timestamp on every run even when no resolvers change,
producing a needless daily commit. Fix: skip writing when resolver data is unchanged.

## Plan (high level)

1. Fix workflow path references + harden (glob-based change detection). [task #1]
2. Harden script path auto-detection + no-op skip. [task #2]
3. Deep analysis (Fable 5) — validate + inventory docs/API/Swagger scope. [task #3]
4. Deep planning (Fable 5). [task #4]
5. Thorough documentation update (all .md + in-app help). [task #5]
6. OpenAPI update + Swagger UI for shared hosting. [task #6]
7. Update .claude memory/context + standing instructions. [task #7]
8. Maintain this handoff. [task #8]
9. Update GitHub issue(s). [task #9]
10. Commit + push each task to working branch. [task #10]

## GitHub issue mapping (repo: mwbmpartners/phpwhois)

- **DNS workflow failure** → **#251** (Bug, OPEN). Fixed on this branch (commit `9dcf967`); issue stays open until fix lands on `main`, then close as completed.
- **OpenAPI update** → relates to #245 (OpenAPI completeness + Retry-After on 429), #160 (OpenAPI validation in CI).
- **Swagger UI (shared hosting)** → relates to #158 (Dark-mode Swagger UI improvements), #148 (API "Try It" docs). Confirms Swagger UI was already intended.
- **Workflow-lint / prevention** → #250 (actionlint workflow-lint CI).
- **Docs** → #248 is privacy/terms-specific; general docs handled in commits.

## Environment notes

- No claude.ai plugins enabled (dev-team-plugins not available in session as of 2026-08-04).
- Model routing: analysis/planning = Fable 5 (sequential); implementation = Sonnet/Haiku (Opus if complex).

## Progress log

- [done] Ground truth gathered; root cause confirmed; task list (#1–#10) created; handoff + standing_instructions.md written.
- [done] Fable 5 deep-analysis complete (see key findings below).
- [done] DNS workflow + script fix implemented, verified locally (php -l, YAML lint, no-op/multi-write unit test, git pathspec glob test), committed & pushed. Tasks #1 & #2 complete.
  - Workflow: matrix `[alpha, beta]`, `ref: ${{ matrix.branch }}`, glob change-detection `web/*/includes/dns_resolvers.php` via `git status --porcelain`, loud-failing retry loop (exits non-zero after 3 tries).
  - Script: layout-invariant file detection (prefer `public_html_beta`, else `public_html`; updates every copy present), skip-write when only the "Last updated" timestamp would change (no more daily no-op commits).
  - REMINDER (analysis finding #1): fix is inert on the daily schedule until it reaches `main` (scheduled workflows run YAML from the default branch). Promotion path claude/* → alpha → beta → main still required; user may wish to expedite.
- [done] Issue **#252** filed (CI hardening: `deploy.yml` deploys even when the sync job fails — confirmed on `main`). Beta-dependent workflow items flagged "verify on beta".
- [done] Remaining analysis findings preserved in `.claude/memory/findings_backlog.md` (security + workflow items to verify on `beta`; docs/OpenAPI/Swagger deferred). MEMORY.md index updated.
- [deferred] Tasks #4 (deep planning), #5 (docs), #6 (OpenAPI/Swagger UI) — per user-declined scope decision, NOT done on this stale-main branch. Do on a fresh `beta`-based branch if pursued.
- [DONE] **Promotion chain complete (2026-08-04, at owner's explicit request).** Fix promoted to production:
  - **#253** `claude/daily-update-tasks-failures-q0w1xt → alpha` — merged (conflict: `.claude/HANDOFF.md`, took ours).
  - **#254** integration branch `claude/promote-dns-to-beta → beta` — merged (conflicts on the 2 DNS files + HANDOFF resolved in favour of the layout-invariant version; beta's hardcoded `public_html` was a strict subset; NO `web/`/`tests/` regressions). No deploy (beta's `deploy.yml` is `paths:web/**`-gated; no web changes).
  - **#255** `beta → main` — merged. **Production release v1.48.0 → v1.50.3** (169 commits/95 files). All CI green (PHP lint, PHPUnit, actionlint, CodeQL). **Production SFTP deploy SUCCEEDED** (run 30914193391).
  - `main` now runs the fixed layout-invariant DNS workflow — daily failure resolved from next 04:00 UTC run.
  - **#251 CLOSED** (fix live on main). **#252 CLOSED** — superseded: beta's rewritten single-source `deploy.yml` (now on main) has one `deploy` job gated only by `if: vars.SFTP_ENABLED=='true'`; the old sync-job + `always()` structure no longer exists.
  - Security + remaining workflow-robustness findings still open in `findings_backlog.md` for a future `beta`-based pass.

## Deep-analysis key findings (Fable 5, 2026-08-04)

1. **CRITICAL — fix is inert until it lands on `main`.** Scheduled workflows run the YAML from the
   DEFAULT branch (main). Our branch targets alpha, and rules forbid direct pushes to main, so the
   daily failure persists until promoted alpha→beta→main. → **User decision flagged** (expedite?).
   The workflow-only fix, once on main, cures BOTH matrix legs even with old scripts on alpha/beta.
2. **CRITICAL — `beta` has already diverged massively.** Beta already: consolidated to single-source
   `web/public_html/` (deleted `public_html_beta` in commit 4fcab25); rewrote the DNS workflow to a
   `matrix: [alpha, beta]`; refreshed `openapi.yaml` to v1.50 (~1500 lines, adds suggest=1,
   dns_propagation_only, Retry-After/429); rewrote README/CLAUDE.md/DEV_NOTES/lookup.php.
   → Doc/OpenAPI/Swagger work on our stale main base **will conflict with / regress beta**.
   → **User decision flagged** (scope of docs work).
3. **Swagger UI already EXISTS** in `docs.php` but loads swagger-ui-dist@5 from **jsdelivr CDN**.
   The real gap = vendor it locally for shared hosting + add a CSP header + fix a live bug
   (`docs.php:200` references never-loaded `SwaggerUIStandalonePreset`).
4. Only ONE scheduled workflow exists (update-dns-resolvers). "Daily tasks (plural)" = one job.
5. Additional latent bugs (all branches): push-retry loops swallow terminal failure; `deploy.yml`
   deploys even if sync job failed; `version-bump.yml` grep-assign under `bash -e` can abort; several
   `bash -e` + git-exit-128 traps. → File as issues (touch beta-rewritten files; don't fix blind).
6. Security findings to FILE (not fix blind — beta rewrote these): `?suggest=1` runs before
   CSRF/rate-limit; `monitor.php` web-reachable with no CLI/auth guard; rate-limit "tier" advertised
   in headers but enforcement hard-caps at 30/min regardless.

## Decisions taken

- DNS fix = adopt beta's matrix design + drift-proof paths (glob `web/*/includes/dns_resolvers.php`,
  `git status --porcelain`, auto-detect resolver file in script, skip write on timestamp-only diff,
  retry-loop fails loudly). Layout-invariant across alpha/beta/main. **DONE** on THIS branch (commit `9dcf967`).
- **[2026-08-04] User declined the two scope questions → proceeding on safe defaults:**
  1. **Promotion:** do NOT open a PR (not requested) and do NOT push to `main` (branch rules). Fix stays
     on the working branch; user promotes manually. Issue #251 stays OPEN until it reaches `main`.
  2. **Scope:** keep THIS branch **DNS-only**. Do NOT run the docs/OpenAPI/Swagger refresh on the stale
     main base (would conflict with / regress beta's v1.50 work). Capture remaining findings as issues.
     → Tasks #4 (deep planning), #5 (docs), #6 (OpenAPI/Swagger) DEFERRED; if pursued later, do them on a
     fresh branch cut from `beta`, not from here.
- SECURITY.md = broken GitHub stub on ALL branches → rewrite (safe, no conflict).
- Docs/OpenAPI/Swagger big refresh = **await user scope decision** (port beta forward vs. minimal).
- Workflow-robustness + security findings = file as GitHub issues (avoid blind edits to beta-diverged files).

## Sequencing / conflict rules for promotion (record for implementer)

- Our branch → alpha merges CLEAN (alpha == main layout).
- alpha→beta WILL conflict on `scripts/update-dns-resolvers.php` + `update-dns-resolvers.yml`:
  resolution rule = **take our (fixed) version of both**.
- Landing workflow-only on main is safe vs other automation (verified in analysis) IF user permits.

## Key files

- `.github/workflows/update-dns-resolvers.yml` — the failing workflow.
- `scripts/update-dns-resolvers.php` — the updater.
- `web/public_html*/includes/dns_resolvers.php` — generated resolver list.
- `web/public_html*/assets/api/openapi.yaml` — API spec.
- `web/public_html*/docs.php` — in-app help/docs.
- `.claude/memory/` — project memory/context.
