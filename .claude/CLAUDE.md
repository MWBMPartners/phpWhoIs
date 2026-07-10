# mwWhoIs - Project Instructions

## Memory

All Claude memory, context, and configuration should be stored in this `.claude/` directory within the repo.

## Project Overview

- **Name:** WHOIS Lookup (mwWhoIs)
- **Owner:** MWBM Partners Ltd (t/a MWservices)
- **Type:** PHP web application — domain WHOIS/RDAP lookup tool
- **Branch strategy:** `beta` (active development) → `main` (production)
- **Deployment:** Automated via GitHub Actions (SFTP), triggered on push
- **Versioning:** Semantic versioning, auto-incremented by CI from commit message prefixes

## Directory Structure

```text
web/public_html_beta/          # Beta (active dev)
├── index.php                  # Frontend UI (single-page app)
├── lookup.php                 # Backend API (POST endpoint)
├── admin.php, health.php, docs.php, monitor.php, privacy.php, terms.php
├── manifest.json, sw.js       # PWA support
├── assets/css/, assets/images/, assets/api/  # Static assets
├── includes/                  # PHP libraries (config, functions, session, version)
└── lang/                      # i18n JSON files
web/public_html/               # Production (synced from beta)
tests/                         # PHPUnit tests
.github/workflows/             # CI/CD (deploy, version-bump, changelog, test)
```

## Key Technical Details

- PHP 7.4+ with Bootstrap 5.3 frontend
- RDAP-first lookups with WHOIS fallback
- Dual rate limiting (session + IP-based)
- Caching: Redis → Memcached → file fallback (15min TTL)
- CSRF protection, input sanitisation, shell injection prevention
- DNT (Do Not Track) support — skips third-party calls when enabled
- 4 themes: light, dark, colourblind-safe, auto (system)
- 4 languages: English, Spanish, French, German
- WCAG 2.1 AA compliant, W3C HTML5 validated

## Conventions

- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)
- `feat:` → minor bump, `fix:` → patch bump, `feat!:` → major bump
- All PHP includes use `__DIR__ . DIRECTORY_SEPARATOR . 'path'`
- Frontend JS uses vanilla JS (no frameworks), `esc()` helper for XSS prevention
- GitHub Issues track all features/bugs with sequential numbering

## Standing Tasks & Working Agreement

> Durable process rules for how Claude conducts work on this project. Added
> 2026-07-10 at the owner's request. Apply these on **every** piece of work,
> in addition to the security review and git-safety rules in the user-global
> `~/.claude/CLAUDE.md`. Keep this section current.

### 1. Model selection (cost-efficient, quality-first)

- **Deep planning / architecture:** use **Fable 5** (`claude-fable-5`).
  Run planning agents **sequentially, never in parallel**. If Fable 5 is
  unavailable, fall back to **Opus** — but **re-check Fable 5 availability at
  the start of each subsequent planning round** and switch back when it returns.
- **Implementation:** use the most appropriate of **Sonnet** or **Haiku**
  (Haiku for mechanical/low-reasoning edits; Sonnet for logic-bearing changes).
  Use **Opus for implementation only when absolutely necessary** and say why.
- Goal: efficient use of usage limits / quotas / credits while still getting
  **top-quality output right the first time**.

### 2. Per-work-item discipline (one task = one issue = one commit)

For **each** distinct piece of work:

- **GitHub issue first.** If no issue exists (open *or* closed), create one in
  **high detail** (what · why · approach · acceptance criteria). If one exists,
  **update it thoroughly** before starting. If it's **closed, reopen it**.
- **Commit individually** — one focused commit per task, never batched.
- On completion, **update that issue** (what was done, evidence) and **commit**
  that update path individually.
- Keep the **Handoff doc**, **Claude Memory**, **Claude Context**, and other
  `.claude/` files updated as you go.

### 3. Claude data lives in the repo `.claude/`

Maintain and update **all** Claude memory, context, handoff, and config in this
repo's `.claude/` directory so it is shared across development
environments/users. Do not rely on the machine-global `~/.claude/` for
project state.

### 4. Handoff documents (crash / restart resilience)

Create and continuously maintain `.claude/HANDOFF.md` so the owner can resume
instantly after a crash, Claude Code error, or new session — **without**
re-stating the brief, re-reading the whole codebase, or replaying prior chat
(all of which burn tokens). Record: current focus, what's done, what's pending,
open decisions, and exact next steps.

### 5. Feature ideation loop & dev-team plugin

Feel free to **loop and propose new features**, and to use the
**`dev-team` plugin** skills (orchestrator / iterate / security / review /
featurefind / autopilot) to manage, steer, and guide the above. Un-actioned
suggestions become `for consideration` GitHub issues (per user-global rule).

### 6. Documentation sweep (after the queued tasks are done)

Once the currently queued tasks are complete, update **all** documentation:
`.md` files, **GitHub Issues**, **GitHub Wiki**, **GitHub Project**, and
**GitHub Milestones** — creating any of these that do not yet exist. Because
the app exposes an **API**, keep the **Swagger / OpenAPI** spec
(`assets/api/openapi.yaml`) thoroughly updated to match the current feature set.

### 7. PR policy — no stacking, wait for explicit ask

- **Do not create PRs autonomously.** Wait until the owner **explicitly asks**
  for a PR.
- **Never stack PRs** (avoids merge race conditions). If a pending PR already
  targets the requested branch, **add the items to that PR** instead of opening
  a new one.
- When a PR is created, **autonomously monitor its checks / CI**, and **resolve
  any failures**. Ask the owner only when a resolution needs a decision.

### 8. Git safety (reinforces user-global rules)

Never `git push`, force-push, `reset --hard`, delete remote branches, or modify
`.git/config` without an **explicit** go-ahead. Branch/remote mutations are
presented for confirmation first.
