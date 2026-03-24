# DomainCheckr

**Free domain intelligence tool** — WHOIS/RDAP lookups, DNS records, SSL/TLS certificates, email security, security assessments, and more.

[![Beta](https://img.shields.io/badge/beta-beta.whois.mwhost.online-blue)](https://beta.whois.mwhost.online)

## Overview

DomainCheckr is a comprehensive domain intelligence platform built in PHP. Enter a domain name or IP address and get a complete security and infrastructure analysis in seconds.

**Developed by [MWBM Partners Ltd](https://www.mwbmpartners.ltd) (t/a [MWservices](https://www.mwservices.it))**

## Features

### Core Lookups
- RDAP-first lookups with WHOIS fallback
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Domain availability detection with configurable registrar buttons
- Structured domain summary (registrar, dates, nameservers, expiry countdown)
- Reverse DNS lookup for IP addresses
- Bulk domain lookup with progress indicator and file import
- Domain comparison (side-by-side with export)
- On-demand domain name suggestions for unavailable domains

### Security Analysis
- **Security Score**: Aggregated A-F grade from 12 security checks
- **SSL/TLS**: Certificate info, TLS version audit, cipher suite check
- **Certificate Transparency**: crt.sh log lookup
- **CAA Records**: Certificate Authority Authorization
- **DANE/TLSA**: DNS-based Authentication of Named Entities
- **DNSSEC**: Validation status
- **HTTP Security Headers**: Audit with A-F grading (HSTS, CSP, X-Frame-Options, etc.)
- **HTTP Redirect Chain**: Detection and analysis
- **Email Security**: SPF, DMARC, DKIM, MTA-STS, BIMI, SMTP STARTTLS
- **Threat Intelligence**: Google Safe Browsing, VirusTotal, PhishTank, URLhaus, AbuseIPDB, Shodan
- **Blocklist Check**: Multi-DNSBL (Spamhaus, Barracuda, SpamCop, SORBS, UCEPROTECT, CBL, SpamRATS, Mailspike)
- **Domain Age Risk**: Flags recently registered domains
- **WHOIS Privacy Detection**: Identifies privacy proxy services
- **Hosting Country Risk**: Assessment based on IP geolocation

### Network & Infrastructure
- IP geolocation (country, city, ISP, AS)
- HTTP/2 and HTTP/3 protocol support detection
- IPv6 readiness check
- DNS resolution and HTTP response time measurement
- Nameserver diversity check (single point of failure detection)
- Reverse IP lookup (shared hosting detection)
- Technology stack detection (CMS, frameworks, CDNs, analytics)
- Robots.txt and sitemap.xml analysis
- DNS propagation checker (Google, Cloudflare, OpenDNS, Quad9)

### User Experience
- Dark mode, light mode, colourblind-safe theme, auto (system preference)
- Multi-language support (English, Spanish, French, German)
- Keyboard shortcuts (press `?` for help)
- PWA support (offline capable, Add to Home Screen)
- Client-side domain validation with real-time feedback
- Export results as JSON, CSV, or PDF
- Share lookup results via URL
- QR code sharing
- WHOIS diff (cached vs fresh comparison)
- Domain expiry watch list with notifications and ICS calendar export
- Security score history with sparkline visualisation
- Domain portfolio dashboard
- RSS feed for watched domain changes
- Print-friendly stylesheet
- Responsive design with scrollable tabs on mobile

### API & Integration
- JSON API (`?format=json`) with CORS support
- API key authentication with configurable rate limit tiers
- Standard rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`)
- Domain ownership verification via DNS TXT record
- RSS feed endpoint (`/feed`)
- OpenAPI 3.0 specification (`/docs`)
- Webhook notifications for domain changes
- Admin dashboard with usage statistics

### Security & Privacy
- Content Security Policy (CSP)
- CSRF protection on all forms
- Dual rate limiting (per-session + per-IP)
- Input validation and shell injection prevention
- Do Not Track (DNT) support — skips third-party requests when enabled
- WHOIS contact masking option for GDPR compliance
- Clean URLs (no .php extensions exposed)
- Custom `X-Powered-By` header (hides PHP)
- Privacy Policy and Terms of Service included
- WCAG 2.1 AA accessible
- W3C HTML5 validated

## Tech Stack

- **Backend**: PHP 8.4+
- **Frontend**: Bootstrap 5.3, Bootstrap Icons, vanilla JavaScript
- **Caching**: Redis → Memcached → file-based (15min TTL)
- **DNS**: PHP `dns_get_record()`, system `whois` and `dig` commands
- **CI/CD**: GitHub Actions (auto version bump, changelog, SFTP deploy, PHP lint)
- **Testing**: PHPUnit

## Project Structure

```
├── web/
│   ├── public_html_beta/          # Active development (beta branch)
│   │   ├── index.php              # Main frontend UI
│   │   ├── lookup.php             # Backend API endpoint
│   │   ├── admin.php              # Admin dashboard
│   │   ├── health.php             # Health check endpoint
│   │   ├── docs.php               # Swagger API documentation
│   │   ├── privacy.php            # Privacy Policy
│   │   ├── terms.php              # Terms of Service
│   │   ├── portfolio.php          # Domain portfolio dashboard
│   │   ├── feed.php               # RSS feed
│   │   ├── monitor.php            # Domain monitoring cron script
│   │   ├── manifest.json          # PWA manifest
│   │   ├── sw.js                  # Service worker
│   │   ├── assets/
│   │   │   ├── css/style.css      # Styles (4 themes + print)
│   │   │   ├── images/            # Favicons and logos
│   │   │   └── api/openapi.yaml   # OpenAPI 3.0 specification
│   │   ├── includes/
│   │   │   ├── config.php         # Application configuration
│   │   │   ├── functions.php      # Core functions (~2300 lines)
│   │   │   ├── session_config.php # Session/CSRF setup
│   │   │   ├── infoAppVer.php     # Version metadata
│   │   │   └── footer.php         # Shared footer template
│   │   └── lang/                  # i18n (en, es, fr, de)
│   └── public_html/               # Production (main branch)
├── tests/                         # PHPUnit tests
├── .github/workflows/             # CI/CD pipelines
└── .claude/                       # Claude Code context
```

## Deployment

Deployment is automated via GitHub Actions:

| Branch | Deploys to | Trigger |
|--------|-----------|---------|
| `beta` | `public_html_beta/` | Push |
| `main` | `public_html/` | Push |

Workflows: version bump → changelog → minification → SFTP upload.

## API Usage

```bash
# Basic lookup (JSON)
curl -X POST "https://beta.whois.mwhost.online/lookup?format=json" \
  -d "domain=example.com"

# With API key
curl -X POST "https://beta.whois.mwhost.online/lookup" \
  -H "X-API-Key: your-key-here" \
  -d "domain=example.com"

# Health check
curl "https://beta.whois.mwhost.online/health"
```

Full API documentation: [/docs](https://beta.whois.mwhost.online/docs)

## Requirements

- PHP 8.4+
- `curl` extension (recommended for RDAP and external APIs)
- `whois` system command
- `dig` command (for DNSSEC, CAA, DANE/TLSA checks)
- `openssl` command (for TLS audit)

## License

(C) 2024 MWBM Partners Ltd (t/a MWservices). All Rights Reserved.
