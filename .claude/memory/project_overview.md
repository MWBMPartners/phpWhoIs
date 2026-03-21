---
name: mwWhoIs project overview
description: PHP-based WHOIS lookup tool - architecture, deployment structure, and current state (v0.2.590 Beta)
type: project
---

mwWhoIs is a PHP/jQuery WHOIS lookup tool (v0.2.590 Beta) by MWBM Partners Ltd / MWservices.

**Architecture:**
- Frontend: Bootstrap 4.5.2, jQuery AJAX, formatted/raw toggle views
- Backend: PHP `shell_exec('whois')`, Mozilla Public Suffix List for domain extraction
- Files: `index.php` (UI), `lookup.php` (backend), `infoAppVer.php` (version metadata), `style.css`, `public_suffix_list.dat`

**Deployment structure under `web/`:**
- `public_html/` — production (currently identical to beta)
- `public_html_beta/` — beta build (active development target)
- `public_html_dev/`, `public_html_landing/`, `public_html_redir/`, `private_html/` — empty, for future use

**Framework integration:** References WebMS shared framework (`_functions/all.php`, `_libraries/`, etc.), supports `?dev` and `?debug` URL params.

**Why:** Understanding the full layout avoids confusion between the multiple public_html directories.

**How to apply:** Always make changes in `public_html_beta/` first. Production (`public_html/`) gets updated only when user promotes beta.
