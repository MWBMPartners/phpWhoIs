# Changelog

All notable changes to this project will be documented in this file.
This changelog is automatically maintained by GitHub Actions on each push.

## [9db2ddd] - 2026-03-23

**Add application version info and session configuration**

- Branch: `beta`
- Author: Salem874
- Commit: [`9db2ddd`](https://github.com/MWBMPartners/phpWhoIs/commit/9db2ddd25c9776e21df8bea5cd24cb2e4a6fab6e)

### Changed files

- `.htaccess`
- `DEV_NOTES.md`
- `admin.php`
- `assets/api/openapi.yaml`
- `assets/css/style.css`
- `assets/images/favicon.gif`
- `assets/images/favicon.icns`
- `assets/images/favicon.ico`
- `assets/images/favicon.png`
- `assets/images/favicon.svg`
- `assets/images/logo-notext.svg`
- `assets/images/logo.png`
- `assets/images/logo.svg`
- `docs.php`
- `health.php`
- `includes/config.php`
- `includes/functions.php`
- `includes/infoAppVer.php`
- `includes/session_config.php`
- `index.php`
- `lookup.php`
- `monitor.php`


## [107b6b9] - 2026-03-23

**fix: hide export CSV/JSON buttons until bulk lookup completes (#69)**

- Branch: `beta`
- Author: Salem874
- Commit: [`107b6b9`](https://github.com/MWBMPartners/phpWhoIs/commit/107b6b92608e643a98060f736e2ec100fb23a161)

### Changed files

- `index.php`


## [5d16826] - 2026-03-22

**feat: implement issues #58-#65 — i18n, monitoring, admin, API keys, HIBP, verification**

- Branch: `beta`
- Author: Salem874
- Commit: [`5d16826`](https://github.com/MWBMPartners/phpWhoIs/commit/5d16826547525e83d6d7a403d9ffe2c6a209aec7)

### Changed files

- `admin.php`
- `config.php`
- `functions.php`
- `index.php`
- `lang/de.json`
- `lang/en.json`
- `lang/es.json`
- `lang/fr.json`
- `lookup.php`
- `monitor.php`


## [b17bfdb] - 2026-03-22

**feat: implement issues #39-#68 batch — theme, accessibility, API docs, and new features**

- Branch: `beta`
- Author: Salem874
- Commit: [`b17bfdb`](https://github.com/MWBMPartners/phpWhoIs/commit/b17bfdb071d698983813d18b1b3376d983d71f54)

### Changed files

- `config.php`
- `docs.php`
- `functions.php`
- `index.php`
- `lookup.php`
- `openapi.yaml`
- `style.css`


## [2704392] - 2026-03-22

**Add theme toggle functionality and colourblind mode support**

- Branch: `beta`
- Author: Salem874
- Commit: [`2704392`](https://github.com/MWBMPartners/phpWhoIs/commit/270439230b5f4ab8204293e709d6712e221ba4e2)

### Changed files

- `index.php`
- `logo-notext.svg`
- `style.css`


## [e2e973f] - 2026-03-22

**fix: domain validation regex rejects trailing hyphens (fixes test)**

- Branch: `beta`
- Author: Salem874
- Commit: [`e2e973f`](https://github.com/MWBMPartners/phpWhoIs/commit/e2e973fd9d0e871f9d8bee1502e21e9417ba86d7)

### Changed files

- `functions.php`


## [897e57f] - 2026-03-22

**fix: update line break formatting in app version output**

- Branch: `beta`
- Author: Salem874
- Commit: [`897e57f`](https://github.com/MWBMPartners/phpWhoIs/commit/897e57f0b87b457fe5f676bc81244a3fb0a19264)

### Changed files

- `index.php`


## [a038d9f] - 2026-03-22

**feat: update page description logic and add synopsis to app version info**

- Branch: `beta`
- Author: Salem874
- Commit: [`a038d9f`](https://github.com/MWBMPartners/phpWhoIs/commit/a038d9f1794f4dbabc09ea2eae3c1ae13f9926a5)

### Changed files

- `index.php`
- `infoAppVer.php`


## [838aa9b] - 2026-03-22

**fix: XSS vulnerabilities, header scroll bounce, logo/favicon updates, security hardening**

- Branch: `beta`
- Author: Salem874
- Commit: [`838aa9b`](https://github.com/MWBMPartners/phpWhoIs/commit/838aa9bfebdfd57f95e7948316b5fa15de96fd46)

### Changed files

- `favicon.gif`
- `favicon.icns`
- `favicon.ico`
- `favicon.png`
- `favicon.svg`
- `functions.php`
- `index.php`
- `logo.png`
- `style.css`


## [a89a475] - 2026-03-22

**feat: IP geolocation for DNS A records (#18)**

- Branch: `beta`
- Author: Salem874
- Commit: [`a89a475`](https://github.com/MWBMPartners/phpWhoIs/commit/a89a47573909d52f49f1636ddcbb47e37b6f4989)

### Changed files

- `functions.php`
- `index.php`
- `lookup.php`


## [e461ce1] - 2026-03-22

**fix: split footer into two responsive columns**

- Branch: `beta`
- Author: Salem874
- Commit: [`e461ce1`](https://github.com/MWBMPartners/phpWhoIs/commit/e461ce1323dee838b9918fe00445adeafc3f1d11)

### Changed files

- `index.php`
- `logo.svg`
- `style.css`


## [15a4250] - 2026-03-22

**feat: SSL/TLS certificate info tab (#19)**

- Branch: `beta`
- Author: Salem874
- Commit: [`15a4250`](https://github.com/MWBMPartners/phpWhoIs/commit/15a4250b05c7bee0225c9fb731632d9bc3a7227f)

### Changed files

- `functions.php`
- `index.php`
- `lookup.php`


## [4fdf8c4] - 2026-03-22

**feat: QR code sharing modal for lookup results (#50)**

- Branch: `beta`
- Author: Salem874
- Commit: [`4fdf8c4`](https://github.com/MWBMPartners/phpWhoIs/commit/4fdf8c40933a16c578ff9c442192dfc400163501)

### Changed files

- `index.php`


## [bfd555e] - 2026-03-22

**feat: DMARC/SPF/DKIM email security check (#56)**

- Branch: `beta`
- Author: Salem874
- Commit: [`bfd555e`](https://github.com/MWBMPartners/phpWhoIs/commit/bfd555e612a9d6b7f6e67de485b945d6fbbb813f)

### Changed files

- `functions.php`
- `index.php`
- `lookup.php`


## [6039757] - 2026-03-22

**feat: batch export bulk results as CSV or JSON (#49)**

- Branch: `beta`
- Author: Salem874
- Commit: [`6039757`](https://github.com/MWBMPartners/phpWhoIs/commit/603975770aec20dfcad12b4c1b86a733d7ccf000)

### Changed files

- `index.php`


## [be59d2b] - 2026-03-22

**feat: reverse DNS lookup — enter IP address, get PTR hostname (#45)**

- Branch: `beta`
- Author: Salem874
- Commit: [`be59d2b`](https://github.com/MWBMPartners/phpWhoIs/commit/be59d2b0f9e3940b7b3474a1bab126ea9325104d)

### Changed files

- `functions.php`
- `lookup.php`


## [4b8b1da] - 2026-03-22

**feat: add Wayback Machine link to action buttons (#54)**

- Branch: `beta`
- Author: Salem874
- Commit: [`4b8b1da`](https://github.com/MWBMPartners/phpWhoIs/commit/4b8b1da23b4c078e346f61063c9a415c239070ef)

### Changed files

- `index.php`


## [71cd21c] - 2026-03-22

**feat: handle browser back/forward with popstate (#36)**

- Branch: `beta`
- Author: Salem874
- Commit: [`71cd21c`](https://github.com/MWBMPartners/phpWhoIs/commit/71cd21cc78df9e9258c393d16715685e15b90458)

### Changed files

- `index.php`


## [b334bb2] - 2026-03-22

**feat: add SVG logo and favicon (#66, #31)**

- Branch: `beta`
- Author: Salem874
- Commit: [`b334bb2`](https://github.com/MWBMPartners/phpWhoIs/commit/b334bb2a18deef4ae116910d02d90af75f8fe51b)

### Changed files

- `favicon.svg`
- `index.php`
- `logo.svg`


## [52c2531] - 2026-03-22

**feat: add error logging, /health endpoint, block log access (#43)**

- Branch: `beta`
- Author: Salem874
- Commit: [`52c2531`](https://github.com/MWBMPartners/phpWhoIs/commit/52c2531930053d66db3f9910d135d39749389b31)

### Changed files

- `.htaccess`
- `functions.php`
- `health.php`


## [0e43157] - 2026-03-22

**feat: add per-IP rate limiting alongside session-based (#22)**

- Branch: `beta`
- Author: Salem874
- Commit: [`0e43157`](https://github.com/MWBMPartners/phpWhoIs/commit/0e431572038b63e37f8acd90e5c5699ac1ec717c)

### Changed files

- `functions.php`
- `lookup.php`


## [a8039b4] - 2026-03-22

**feat: add PHPUnit tests, CI linting, extract functions.php (#44)**

- Branch: `beta`
- Author: Salem874
- Commit: [`a8039b4`](https://github.com/MWBMPartners/phpWhoIs/commit/a8039b4a9898c414f14a78975410c12adb38aad0)

### Changed files

- `functions.php`
- `lookup.php`


## [95a5a43] - 2026-03-22

**fix: improve footer display logic for application version and commit details**

- Branch: `beta`
- Author: Salem874
- Commit: [`95a5a43`](https://github.com/MWBMPartners/phpWhoIs/commit/95a5a43460a0547d4ab50a01a3ce831102bb6aee)

### Changed files

- `index.php`


## [5a63747] - 2026-03-22

**fix: initialize pageTitle to NULL and conditionally display it in the footer**

- Branch: `beta`
- Author: Salem874
- Commit: [`5a63747`](https://github.com/MWBMPartners/phpWhoIs/commit/5a63747e477661afcdfbc8e9b03d16dc3123fd85)

### Changed files

- `index.php`


## [87c673b] - 2026-03-22

**refactor: update license structure in infoAppVer.php for clarity**

- Branch: `beta`
- Author: Salem874
- Commit: [`87c673b`](https://github.com/MWBMPartners/phpWhoIs/commit/87c673be465e3715e27430058aee9ba28b206cb3)

### Changed files

- `index.php`
- `infoAppVer.php`


## [26b5267] - 2026-03-22

**refactor: rename Build to Repo for commit info in app version array**

- Branch: `beta`
- Author: Salem874
- Commit: [`26b5267`](https://github.com/MWBMPartners/phpWhoIs/commit/26b5267b936cd28a0099dcb48153df910578772b)

### Changed files

- `index.php`
- `infoAppVer.php`


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
