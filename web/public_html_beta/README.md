# WHOIS Lookup — Beta

**Version:** 1.17.1-beta
**Branch:** `beta`
**Status:** Active development

## Overview

PHP-based domain WHOIS/RDAP lookup tool with DNS records, availability detection, and domain registration integration.

## Features

- RDAP-first lookups with WHOIS fallback
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Domain availability detection with registration button
- Structured domain summary (registrar, dates, nameservers, expiry countdown)
- Bulk domain lookup
- Lookup history (localStorage)
- Copy to clipboard / download as .txt
- Dark mode
- JSON API (`?format=json`)
- Source override (`?source=rdap` or `?source=whois`)
- CSRF protection, rate limiting, input validation
- Auto-updating IANA TLD list + second-level suffixes

## Files

| File | Purpose |
|------|---------|
| `index.php` | Frontend — HTML, CSS, JavaScript |
| `lookup.php` | Backend API — lookup logic, caching, security |
| `session_config.php` | Shared session/CSRF configuration |
| `infoAppVer.php` | Application version metadata |
| `style.css` | Custom styles (Bootstrap 5 theme-aware) |
| `tlds.txt` | Auto-generated IANA TLD list (daily update) |
| `second_level_suffixes.txt` | Auto-generated multi-part suffixes (daily update) |

## API Usage

```
POST lookup.php?format=json
Body: domain=example.com

POST lookup.php?format=json&source=whois
Body: domain=example.com
```

## Requirements

- PHP 7.4+
- `curl` extension (recommended for RDAP)
- `whois` system command
- `session` support

## License

(C) 2024 MWBM Partners Ltd (t/a MWservices). All Rights Reserved.
