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
