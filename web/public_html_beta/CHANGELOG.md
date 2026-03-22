# Changelog

All notable changes to this project will be documented in this file.
This changelog is automatically maintained by GitHub Actions on each push.

## [393b881] - 2026-03-22

**refactor: add build placeholders to infoAppVer.php, deploy overwrites NULLs**

- Branch: `beta`
- Author: Salem874
- Commit: [`393b881`](https://github.com/MWBMPartners/phpWhoIs/commit/393b881be70981ce22b9aa35921f43b986edcf16)

### Changed files

- `infoAppVer.php`


## [3e311d7] - 2026-03-22

**refactor: move build info into infoAppVer.php, remove build_info.php**

- Branch: `beta`
- Author: Salem874
- Commit: [`3e311d7`](https://github.com/MWBMPartners/phpWhoIs/commit/3e311d7826a705444e8a95070edbd97eb70cd7b5)

### Changed files

- `index.php`


## [7203e6c] - 2026-03-22

**feat: show commit ID and date in footer, linked to GitHub commit**

- Branch: `beta`
- Author: Salem874
- Commit: [`7203e6c`](https://github.com/MWBMPartners/phpWhoIs/commit/7203e6cba1a4ea4d3e6c9bec5658288c89b5ead0)

### Changed files

- `index.php`
- `style.css`


## [3d4ee1f] - 2026-03-22

**fix: increase font size for focused header links**

- Branch: `beta`
- Author: Salem874
- Commit: [`3d4ee1f`](https://github.com/MWBMPartners/phpWhoIs/commit/3d4ee1f0035f0a55aa505dfbbb9cc28a3014b504)

### Changed files

- `style.css`


## [7ec91ae] - 2026-03-22

**fix: add CSS cache-busting, use --transfer-all for SFTP deploy**

- Branch: `beta`
- Author: Salem874
- Commit: [`7ec91ae`](https://github.com/MWBMPartners/phpWhoIs/commit/7ec91aef04b9bc2ac68e7ec9bced2fcf3ba7da51)

### Changed files

- `index.php`


## [e121deb] - 2026-03-22

**fix: complete dark mode rewrite with hardcoded colours, fix title link styling**

- Branch: `beta`
- Author: Salem874
- Commit: [`e121deb`](https://github.com/MWBMPartners/phpWhoIs/commit/e121deb8367cef1de7310e135bd9478dfdf99dee)

### Changed files

- `index.php`
- `style.css`


## [ee2a0d9] - 2026-03-22

**fix: correct PHP syntax error in footer version display**

- Branch: `beta`
- Author: Salem874
- Commit: [`ee2a0d9`](https://github.com/MWBMPartners/phpWhoIs/commit/ee2a0d9118ed85926c5ca7561fa01b772fd5cb40)

### Changed files

- `index.php`


## [0d08aae] - 2026-03-22

**fix: correct footer version display and adjust font size in header**

- Branch: `beta`
- Author: Salem874
- Commit: [`0d08aae`](https://github.com/MWBMPartners/phpWhoIs/commit/0d08aae2fe75eacaad8eee51d9f28340910d93c8)

### Changed files

- `index.php`
- `style.css`


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
