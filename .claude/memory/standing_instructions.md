# Standing Instructions (project-wide)

> These apply throughout the project/repo **regardless of which device or mechanism** the work
> is done on (Claude Code CLI, web, IDE, GitHub Action, etc.). Treat them as always-on defaults.
> Established: 2026-08-04.

## 1. Model routing / processing philosophy — GIRFT (Get It Right First Time)

- **Deep Analysis** and **Deep Planning**: use **sequential (not parallel) Fable 5 agents**.
  - Fall back to **Opus** only if Fable 5 is unavailable.
  - Always **retry Fable 5 first** on every subsequent deep-analysis / deep-planning run.
- **Implementation**: use **Sonnet or Haiku**, whichever is most appropriate for the task.
  - Use **Opus** only when the implementation is genuinely complex.
- Overriding philosophy: **efficiently use tokens / usage credits while producing top-quality,
  correct code**. Prefer getting it right the first time over iterating.

## 2. Plugins

- Feel free to use **dev-team-plugins** functionality for any of the work, and to manage/raise
  additional suggestions for fixes, tweaks, enhancements, and new features.
- (Note: as of 2026-08-04 no claude.ai plugins are enabled in the session — revisit if installed.)

## 3. After each piece of work (per task)

1. **Commit and push** the work to the current working branch (the one that will eventually be
   merged to **`alpha`**).
2. **Update the relevant GitHub issue(s)** — individually, one per task.
3. **Update Claude memory / context** in `.claude/` of this repo.
4. **Update the Handoff document** (`.claude/HANDOFF.md`) so work can be resumed if interrupted.

## 4. Documentation discipline

- Keep **all `.md` docs** current (README, DEV_NOTES, CHANGELOG, SECURITY, etc.).
- Keep **in-app help / guides** current.
- Keep **Claude memory/context** in `.claude/` current.
- If the project offers an API, keep the **OpenAPI/Swagger** docs current.
- If there are web components and browsable Swagger UI isn't present, include **Swagger UI**,
  prepared so it can be hosted on **shared hosting (no Docker)** — vendor assets locally.

## 5. Branching & PRs — NO PR STACKING

- **One working branch, one PR (created later).** Do **not** open multiple PRs — this avoids PR
  merge race conditions.
- Commit **all** changes to the working branch that will target **`alpha`**.
- Branch flow for this repo: `claude/*` → **`alpha`** → `beta` → `main` (production).
- If a designated branch's PR was already merged, restart from the latest base rather than
  stacking new commits on merged history.

## 6. Autonomy

- Work **autonomously** through **all** queued tasks.
- Only pause for a decision that **genuinely requires the user's explicit approval**; when pausing,
  state clearly and simply **what** is needed and **why**, then **continue autonomously** with all
  remaining queued tasks.
- Adjust ordering and bundle tasks as sensible for efficiency.
