# Handoff — mwWhoIs / DomainCheckr

> Resume point for the current work. Keep this file current: update it as tasks
> start/finish so any session can pick up without re-reading the brief, the full
> codebase, or prior chat. Last updated: **2026-07-10**.

## Active session focus

1. **Record standing tasks** into `.claude/` — **DONE** (see
   `.claude/CLAUDE.md` → "Standing Tasks & Working Agreement",
   `.claude/memory/feedback_workflow_process.md`).
2. **Branch cleanup & alpha↔beta realignment** — **ANALYSIS DONE, execution
   awaiting owner go-ahead** (remote pushes/deletes are gated).

## Branch state as of 2026-07-10 (analysed against `origin/*`, post-fetch)

| Branch | Tip | Relationship | Verdict |
|---|---|---|---|
| `origin/main` | `43d84f9` | fully contained in beta; 85 behind beta | keep (production) |
| `origin/beta` | `a9b5297` | **most advanced branch**; contains all of main, alpha, TLD | keep (base dev, for now) |
| `origin/alpha` | `8390bac` | **fully contained in beta** (PR #183 merged alpha→beta 2026‑04‑07). 0 commits/content unique vs beta | keep (future base dev) — realign by advancing to beta |
| `origin/claude/add-tld-listing-GiisC` | `75515a2` | **fully merged into beta** (PR #184 merged 2026‑04‑21). 0 unique commits | **DELETE** (remote) |

Verified with `git merge-base --is-ancestor` (all three non-beta branches are
ancestors of beta) and `gh pr list` (PRs #182/#183/#184 all MERGED; **no open
PRs**). The GitHub "Branches" page chips for #183/#184 are stale links to
already-merged PRs.

### Key finding — corrects the original premise
There is **nothing on `alpha` that is not already on `beta`**. `alpha` is a
strict ancestor of `beta` (beta = alpha + 79 later commits). So "cherry-pick
alpha's unique code into beta" has **no candidates**. The tree diff
`origin/beta..origin/alpha` shows only files where **beta moved forward** (e.g.
beta relocated `config.php`→`includes/config.php`, added `feed*.php`,
`portfolio.php`, `tlds.php`, `SECURITY.md`, PWA files, etc.). The stale
`web/public_html/config.php` + `session_config.php` that appear "added" in alpha
are old files beta has since removed — **not** new work.

### Correct realignment
To realign with **beta as the source of truth**: fast-forward `alpha` up to
`beta` (`alpha` becomes identical to `beta`). This is a **push to origin/alpha**
→ needs explicit owner go-ahead.

## Pending decisions (need owner go-ahead — remote mutations)

- [ ] **Delete** remote branch `origin/claude/add-tld-listing-GiisC`
      (fully merged; no local copy). `git push origin --delete …`.
- [ ] **Advance `alpha` → `beta`** to realign (fast-forward push to origin/alpha).
- [ ] Do NOT touch `main` (normal beta→main promotion path) or `beta`.

## Working-tree caveats (local only, not on any branch)

- `web/public_html_beta/includes/infoAppVer.php` has an **uncommitted, broken**
  edit (dangling `})`, malformed `isset(... && ...)`) — abandoned. Recommend
  `git restore` (discard) unless the owner wants to salvage the Bundle-ID logic.
  **Not committed.**
- Untracked `.claude/settings.json` (enables `dev-team` plugin) and
  `.claude/agents/` (deep-architect, quick-edits). Decide whether to commit or
  gitignore.
- **Local `beta` is 92 commits behind `origin/beta`**, local `main` 2 behind.
  Update locals (`git pull --ff-only`) before any local branch work — but the
  broken `infoAppVer.php` edit must be resolved first or it will block a switch.

## Next steps when resuming

1. Get go-ahead on the two remote mutations above.
2. Per standing rules: open (or update) a GitHub issue for the cleanup, execute,
   then commit `.claude/` doc changes individually.
3. Then proceed to the documentation sweep (Issues/Wiki/Project/Milestones/OpenAPI).
