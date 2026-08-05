---
name: DomainCheckr (mwWhoIs) project overview
description: PHP domain WHOIS/RDAP lookup tool — architecture, tech stack, deployment, and current feature set (v1.22+ Beta)
type: project
---

# DomainCheckr Project Overview

**DomainCheckr** (repo: mwWhoIs/phpWhoIs) is a PHP web application by MWBM Partners Ltd for domain WHOIS/RDAP lookups, DNS analysis, and security checks.

**Tech Stack:**

- Frontend: Bootstrap 5.3, vanilla JS (no jQuery/frameworks), Bootstrap Icons
- Backend: PHP 8.0+ (8.4 recommended), RDAP-first with WHOIS fallback, cURL for external APIs
- Caching: Redis → Memcached → file-based fallback (15min TTL)
- Rate limiting: Dual session + IP-based (30 req/60s default, configurable per API key tier)
- Security: CSRF tokens, input sanitisation, CSP headers, session hardening, DNT support

**Directory Structure:**

- `web/public_html/` — **the single web-accessible source for ALL branches** (single-source deploy adopted 2026-07-10, matching iHymns/WebMS-Intra). The old `web/public_html_beta/` folder was consolidated away.
- `web/public_html/includes/` — PHP includes (config, functions, session, footer, version)
- `web/public_html/assets/` — CSS, images, API spec
- `web/public_html/lang/` — i18n JSON files (en, es, fr, de)
- `web/.auth/` — gitignored secret API keys (`keys.php`); `config.php` loads them; sits above the web root on the server
- Branch → SFTP target: `main→public_html`, `beta→public_html_dev_beta`, `alpha→public_html_dev_alpha`
- `tests/` — PHPUnit tests
- `.github/workflows/` — CI/CD (deploy, version-bump, changelog, test)

**Key Features (as of 2026-03-24):**

- WHOIS/RDAP lookups with parsed domain summary cards
- DNS records, SSL/TLS cert info, email security (SPF/DMARC/DKIM)
- Subdomain discovery, IP geolocation, website screenshot previews
- Bulk lookup with CSV/JSON export, side-by-side domain comparison
- WHOIS history timeline (localStorage snapshots with change diffs)
- 4 themes (light/dark/colourblind/auto), 4 languages (EN/ES/FR/DE)
- OpenAPI 3.0 spec + Swagger UI docs page
- Admin dashboard, API key system, domain monitoring cron
- Domain ownership verification (DNS TXT), registrar reputation flagging
- Google Safe Browsing, VirusTotal, HIBP integrations (require API keys)
- QR code sharing, Wayback Machine link, PWA support
- Privacy Policy, Terms of Service pages with DNT support
- WCAG 2.1 AA compliant, W3C HTML5 validated

**Deployment:** Automated via GitHub Actions SFTP on push to beta/main. Semantic versioning auto-incremented from commit prefixes (feat: → minor, fix: → patch).

**Why:** Understanding the full architecture and feature set ensures accurate work on any part of the codebase.

**How to apply:** Make all changes in `web/public_html/` (single source — no more `public_html_beta/`). The app name is now "DomainCheckr" (renamed from mwWhoIs). PHP includes use `includes/` subdirectory. Assets are in `assets/css/`, `assets/images/`, `assets/api/`. Secrets go in gitignored `web/.auth/keys.php`, never in `config.php`.
