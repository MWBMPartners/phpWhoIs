# WHOIS Lookup — Beta

**Version:** 1.17.6-beta
**Branch:** `beta`
**Status:** Active development

## Overview

PHP-based domain WHOIS/RDAP lookup tool with DNS records, availability detection, SSL/TLS info, email security checks, and domain registration integration.

## Features

- RDAP-first lookups with WHOIS fallback
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Domain availability detection with registration button
- Structured domain summary (registrar, dates, nameservers, expiry countdown)
- SSL/TLS certificate information
- Email security checks (SPF, DMARC, DKIM)
- IP geolocation for resolved addresses
- Subdomain discovery
- Bulk domain lookup with progress indicator
- Domain comparison (side-by-side)
- WHOIS diff (cached vs fresh)
- Export results as JSON/CSV
- Lookup history & change timeline (localStorage)
- Domain expiry watch list with notifications
- Copy to clipboard / download as .txt
- Dark mode, light mode, colourblind-safe theme
- Multi-language support (English, Spanish, French, German)
- Keyboard shortcuts (press ? for help)
- PWA support (offline capable, Add to Home Screen)
- Client-side domain validation
- Print-friendly stylesheet
- JSON API (`?format=json`) with API key support
- Admin dashboard with usage stats
- Domain monitoring via webhooks
- CSRF protection, rate limiting, input validation
- Auto-updating IANA TLD list + second-level suffixes
- Accessibility: ARIA, reduced-motion, skip links, screen reader support

## Directory Structure

```
public_html_beta/
├── index.php          # Frontend UI
├── lookup.php         # Backend API endpoint
├── admin.php          # Admin dashboard
├── health.php         # Health check endpoint
├── docs.php           # Swagger API docs
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
POST lookup.php?format=json
Body: domain=example.com

POST lookup.php?format=json&source=whois
Body: domain=example.com

# With API key
POST lookup.php
Header: X-API-Key: your-key-here
Body: domain=example.com
```

## Requirements

- PHP 7.4+
- `curl` extension (recommended for RDAP)
- `whois` system command
- `session` support

## License

(C) 2024 MWBM Partners Ltd (t/a MWservices). All Rights Reserved.
