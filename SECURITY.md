# Security Policy

**DomainCheckr** (mwWhoIs) is developed by MWBM Partners Ltd (t/a MWservices).
We take the security of the application and its users seriously and welcome
responsible disclosure of vulnerabilities.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through **GitHub's private vulnerability reporting**:

- Go to the [**Security Advisories**](https://github.com/MWBMPartners/phpWhoIs/security/advisories/new)
  page for this repository and open a new draft advisory.

<!-- OWNER: to enable this, turn on "Private vulnerability reporting" in
     Settings → Security & analysis. Add a dedicated security contact email
     below if you want an alternative channel. -->

If you cannot use GitHub, contact the maintainers via
[MWservices](https://www.mwservices.it) / [MWBM Partners](https://www.mwbmpartners.ltd).

Please include, where possible:

- A description of the vulnerability and its impact.
- Steps to reproduce (a proof of concept, affected URL/endpoint, request/response).
- The affected version or environment (production, beta, or a specific commit).

## What to Expect

- We will acknowledge your report as soon as practicable.
- We will investigate, keep you informed of progress, and coordinate disclosure
  timing with you once a fix is prepared.
- Fixes ship to production first; where a fix touches the promotion chain
  (`alpha → beta → release-candidate → main`) we prioritise the path to
  production.
- We are happy to credit reporters (unless you prefer to remain anonymous).
- As a small team we do **not** offer a formal SLA or a paid bug-bounty, but we
  genuinely appreciate and act on good-faith reports.

## Supported Versions

Security fixes are applied to the current **production** release (the `main`
branch, deployed to the production site) and flow through the normal promotion
chain. Pre-production branches (`alpha`, `beta`, `release-candidate`) are fixed
in the course of active development. Older releases are not supported.

| Version                     | Supported          |
| --------------------------- | ------------------ |
| Current production (`main`) | :white_check_mark: |
| Pre-production branches      | :white_check_mark: (in development) |
| Anything older              | :x:                |

## Scope

**In scope** — the web application and its API, including `/lookup`, `/health`,
`/feed`, `/feed-watchlist`, and the admin/docs pages:

- Cross-site scripting (XSS), CSRF, and HTML/JS injection.
- Server-side request forgery via a lookup target, command/argument injection.
- Authentication, API-key, or rate-limit bypass.
- Cache poisoning and information disclosure.

**Out of scope:**

- Volumetric denial-of-service / traffic-flooding.
- Vulnerabilities in third-party services the app queries (RDAP/WHOIS registries,
  jsdelivr, and other external data providers) rather than in this codebase.
- The beta host being publicly reachable — that is intentional.
- Reports from automated scanners without a demonstrated, exploitable impact.

## Good-Faith Safe Harbour

We will not pursue or support legal action against researchers who act in good
faith, avoid privacy violations and service disruption, only interact with
accounts they own or have permission to test, and give us reasonable time to
remediate before any public disclosure.
