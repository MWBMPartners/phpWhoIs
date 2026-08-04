# Findings Backlog (deep-analysis, 2026-08-04)

> Captured from the Fable 5 deep analysis run on the **stale `main`-based** branch
> `claude/daily-update-tasks-failures-q0w1xt`. **`beta` has diverged heavily** (consolidated to a
> single `web/public_html/`, OpenAPI at v1.50, README/CLAUDE/DEV_NOTES/lookup.php rewritten), so the
> app-code items below **must be re-verified on a `beta`-based branch before fixing** — do not fix
> blind from `main`. Recorded here so the analysis isn't lost while docs/OpenAPI/Swagger work is
> deferred (see HANDOFF.md "Decisions taken").

## Filed as GitHub issues

- **#251** (Bug, OPEN) — daily *Update DNS Resolvers* workflow path-mismatch failure. **Fixed** on this
  branch (commit `9dcf967`); stays open until the fix reaches `main`.
- **#252** (Bug, OPEN) — CI hardening: `deploy.yml` `deploy` job uses `if: always()` and deploys even
  when `sync-beta-to-production` fails on `main`. Confirmed on `main`. Suggested guard included.

## Workflow-robustness — to verify on `beta`, then file/fix

1. `version-bump.yml` triggers on `paths: web/public_html_beta/**` and edits
   `web/public_html_beta/includes/infoAppVer.php`. If `beta` dropped `public_html_beta/`, version
   bumping silently never fires on `beta`. Also `CURRENT=$(grep -oP …)` under `set -e` aborts on a
   non-match. (Runs from `beta`'s copy — verify there.)
2. General: `git`-based steps under `bash -e` that exit non-zero on an expected "no match / not found";
   push-retry loops that `break` on success but don't fail loudly after exhausting retries. (The DNS
   workflow's loop was hardened in `9dcf967`.) Consider `actionlint` in CI (relates to #250).

## Security — to verify on `beta`, then file/fix (NOT filed blind — beta rewrote these files)

1. **`?suggest=1` path** reportedly runs before CSRF / rate-limit checks in `lookup.php`. Verify order
   of guards on `beta`'s rewritten `lookup.php`.
2. **`monitor.php`** reportedly web-reachable with no CLI-only / auth guard. Verify on `beta`.
3. **Rate-limit "tier"** advertised in response headers but enforcement hard-caps at 30/min regardless
   of tier. Verify on `beta`.

## Docs / API / Swagger UI — deferred (do on a `beta`-based branch)

- Swagger UI already exists in `docs.php` but loads `swagger-ui-dist@5` from the **jsdelivr CDN**.
  Gaps: vendor assets locally for **shared hosting (no Docker)**, add a **CSP** header, and fix a live
  bug at ~`docs.php:200` referencing a never-loaded `SwaggerUIStandalonePreset`. (Relates to #158, #148.)
- OpenAPI: `beta` already advanced `openapi.yaml` to ~v1.50 (adds `suggest=1`, `dns_propagation_only`,
  `Retry-After`/429). Any spec work must build on `beta`, not `main`. (Relates to #245, #160.)
