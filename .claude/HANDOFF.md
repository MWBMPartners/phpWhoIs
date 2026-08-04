# Handoff Document — mwWhoIs

> Living document. Update as work progresses so any session can resume instantly.
> Last updated: 2026-08-04 (session: daily-update-tasks-failures).

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

- **DNS workflow failure** → NO existing issue; create a new `bug` issue and close it when fixed.
- **OpenAPI update** → relates to #245 (OpenAPI completeness + Retry-After on 429), #160 (OpenAPI validation in CI).
- **Swagger UI (shared hosting)** → relates to #158 (Dark-mode Swagger UI improvements), #148 (API "Try It" docs). Confirms Swagger UI was already intended.
- **Workflow-lint / prevention** → #250 (actionlint workflow-lint CI).
- **Docs** → #248 is privacy/terms-specific; general docs handled in commits.

## Environment notes

- No claude.ai plugins enabled (dev-team-plugins not available in session as of 2026-08-04).
- Model routing: analysis/planning = Fable 5 (sequential); implementation = Sonnet/Haiku (Opus if complex).

## Progress log

- [done] Ground truth gathered; root cause confirmed; task list (#1–#10) created; handoff + standing_instructions.md written.
- [in progress] Fable 5 deep-analysis agent running (validates root cause, inventories docs, API/Swagger gap analysis, checks all workflows).
- [next] Fable 5 deep-planning agent → implementation (Sonnet/Haiku) → commit/push → issue updates.

## Key files

- `.github/workflows/update-dns-resolvers.yml` — the failing workflow.
- `scripts/update-dns-resolvers.php` — the updater.
- `web/public_html*/includes/dns_resolvers.php` — generated resolver list.
- `web/public_html*/assets/api/openapi.yaml` — API spec.
- `web/public_html*/docs.php` — in-app help/docs.
- `.claude/memory/` — project memory/context.
