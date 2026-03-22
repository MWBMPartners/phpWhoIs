# Changelog

All notable changes to this project will be documented in this file.
This changelog is automatically maintained by GitHub Actions on each push.

## [5c24896] - 2026-03-22

**feat: click-to-select on WHOIS output with highlight flash (#34)**

- Branch: `beta`
- Author: Salem874
- Commit: [`5c24896`](https://github.com/MWBMPartners/phpWhoIs/commit/5c24896f72e96e74f092be0f30c6e9357f8bbb09)

### Changed files

- `index.php`
- `style.css`


## [a0a1dec] - 2026-03-22

**docs: add DEV_NOTES.md, semver version bumping, block .md from web access**

- Branch: `beta`
- Author: Salem874
- Commit: [`a0a1dec`](https://github.com/MWBMPartners/phpWhoIs/commit/a0a1deca0591cbb18b423672378d0fde77aefa5a)

### Changed files

- `.htaccess`
- `DEV_NOTES.md`


## [e0198e0] - 2026-03-22

**Update deployment workflow and app version handling; set production status to NULL and manage development status based on environment**

- Branch: `beta`
- Author: Salem874
- Commit: [`e0198e0`](https://github.com/MWBMPartners/phpWhoIs/commit/e0198e020008c5a00cd038a4c3b1edd1e14b6809)

### Changed files

- `index.php`
- `infoAppVer.php`


## [1.0.0-beta.1] - 2026-03-21

### Added
- RDAP as primary lookup with WHOIS fallback (#12)
- DNS records display (A, AAAA, MX, NS, TXT, CNAME) (#6)
- Domain availability detection with registration button (#3, #13)
- Structured domain summary card with expiry countdown (#9)
- Bulk domain lookup with accordion display (#5)
- Lookup history via localStorage (#4)
- Copy to clipboard and download as .txt (#7)
- Dark mode toggle with persistence (#8)
- JSON API endpoint with CORS (#10)
- Source override parameter (`?source=rdap|whois`) (#17)
- WHOIS result caching (15 min TTL) (#11)
- Loading spinner and error feedback (#2)
- CSRF protection and session-based rate limiting (#1)
- Security headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.)
- Input validation (length, null bytes, shell-dangerous chars)
- Auto-updating IANA TLD list + second-level suffixes (#14)
- Shared session_config.php
- GitHub Actions: SFTP deploy + auto-release (#16)
- Empty state placeholder
- Dynamic browser tab title on lookup
- Fade-in animations for results
- Sticky header

### Changed
- Full rewrite of index.php and lookup.php (#15)
- Bootstrap 4.5.2 → 5.3.8 (#8)
- jQuery → vanilla JS fetch API (#8)
- Replaced 330KB Mozilla PSL with IANA TLD list (~25KB) + extracted second-level suffixes (~5KB) (#14)
- System font stack (Segoe UI / system-ui)
- All PHP shorthand expanded to full notation

### Removed
- WebMS framework boilerplate (~250 lines)
- jQuery dependency
- Legacy `protectSessionInjection()` (replaced by session_config.php)
- `public_suffix_list.dat` (330KB, replaced by auto-updating lists)

## [0.2.590] - 2024-xx-xx

### Added
- Initial WHOIS lookup functionality
- Public Suffix List for domain extraction
- Basic formatted/raw view toggle
- Bootstrap 4 responsive layout
