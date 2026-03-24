# WHOIS Lookup — Beta

**Version:** 1.30.1-beta
**Branch:** `beta`
**Status:** Active development

## Overview

PHP-based domain WHOIS/RDAP lookup tool with DNS records, availability detection, SSL/TLS info, email security checks, and domain registration integration.

## Features

- RDAP-first lookups with WHOIS fallback
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Domain availability detection with registration button
- Structured domain summary (registrar, dates, nameservers, expiry countdown)
- SSL/TLS certificate info, TLS version audit, cipher suite check
- Certificate Transparency log lookup (crt.sh)
- CAA (Certificate Authority Authorization) record check
- DANE/TLSA record check
- Email security checks (SPF, DMARC, DKIM, MTA-STS, BIMI)
- SMTP banner grab and STARTTLS check
- DNSSEC validation
- IP geolocation for resolved addresses
- HTTP security headers audit (HSTS, CSP, X-Frame-Options, etc.) with A-F grading
- HTTP redirect chain detection
- HTTP/2 and HTTP/3 protocol support detection
- IPv6 readiness check
- DNS resolution and response time measurement
- Nameserver diversity check (single point of failure detection)
- Subdomain discovery
- Reverse IP lookup (shared hosting detection)
- Domain age risk scoring
- WHOIS privacy detection
- Hosting country risk assessment
- Multi-DNSBL check (Spamhaus, Barracuda, SpamCop, SORBS, UCEPROTECT, CBL, SpamRATS, Mailspike)
- URLhaus, PhishTank, AbuseIPDB, Shodan, VirusTotal, Safe Browsing integration
- Technology stack detection (CMS, frameworks, CDNs, analytics)
- Robots.txt and sitemap.xml analysis
- DNS propagation checker (Google, Cloudflare, OpenDNS, Quad9)
- Aggregated security score (A-F grade, 12-check matrix)
- Bulk domain lookup with progress indicator and file import
- Domain comparison (side-by-side)
- Domain name suggestions for unavailable domains
- WHOIS diff (cached vs fresh)
- Export results as JSON/CSV/PDF
- Share lookup results via URL
- Lookup history & change timeline (localStorage)
- Domain expiry watch list with notifications and ICS calendar export
- RSS feed for watched domain changes
- Copy to clipboard / download as .txt
- Dark mode, light mode, colourblind-safe theme
- Multi-language support (English, Spanish, French, German)
- Keyboard shortcuts (press ? for help)
- PWA support (offline capable, Add to Home Screen)
- Client-side domain validation
- Print-friendly stylesheet
- Domain portfolio dashboard with watch list management
- JSON API (`?format=json`) with API key support, rate limit headers, and quota display
- Admin dashboard with usage stats and webhook testing
- Domain monitoring via webhooks
- Domain ownership verification via DNS TXT record
- Do Not Track (DNT) support — respects browser DNT signal
- Content Security Policy (CSP) and Subresource Integrity (SRI)
- JSON-LD structured data for SEO
- WHOIS contact masking option for GDPR compliance
- Privacy Policy and Terms of Service pages
- Multiple configurable domain registrars (single button or dropdown)
- CSRF protection, rate limiting, input validation
- Auto-updating IANA TLD list + second-level suffixes
- Accessibility: WCAG 2.1 AA, ARIA, reduced-motion, skip links, screen reader support
- W3C HTML5 validated

## Directory Structure

```
public_html_beta/
├── index.php          # Frontend UI
├── lookup.php         # Backend API endpoint
├── admin.php          # Admin dashboard
├── health.php         # Health check endpoint
├── docs.php           # Swagger API docs
├── privacy.php        # Privacy Policy
├── terms.php          # Terms of Service
├── monitor.php        # Domain monitoring cron script
├── manifest.json      # PWA manifest
├── sw.js              # Service worker
├── .htaccess          # Security rules
├── assets/
│   ├── css/style.css  # Styles (dark/light/colourblind/print)
│   ├── images/        # Favicons and logos
│   └── api/openapi.yaml  # OpenAPI 3.0 specification
├── includes/
│   ├── config.php     # Configuration
│   ├── session_config.php  # Session/CSRF setup
│   ├── functions.php  # Core lookup functions
│   └── infoAppVer.php # Version metadata
└── lang/              # i18n language files (en, es, fr, de)
```

## API Usage

```
POST /lookup?format=json
Body: domain=example.com

POST /lookup?format=json&source=whois
Body: domain=example.com

# With API key
POST /lookup
Header: X-API-Key: your-key-here
Body: domain=example.com
```

## Requirements

- PHP 8.4+
- `curl` extension (recommended for RDAP)
- `whois` system command
- `session` support

## License

(C) 2024 MWBM Partners Ltd (t/a MWservices). All Rights Reserved.
