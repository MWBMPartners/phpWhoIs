# Developer Notes

## Versioning

This project follows [Semantic Versioning (semver)](https://semver.org/).

Version numbers are **automatically incremented** by GitHub Actions on each push to `beta`, based on the commit message prefix.

### Format

```
MAJOR.MINOR.PATCH
```

- **MAJOR** — incremented for breaking/incompatible changes
- **MINOR** — incremented for new features (backwards-compatible)
- **PATCH** — incremented for bug fixes, refactors, docs, chores

### Commit message conventions

Commit messages must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>
```

| Commit prefix | Bump type | Example version change |
|---|---|---|
| `fix:` | Patch | 1.0.1 → 1.0.2 |
| `chore:` | Patch | 1.0.2 → 1.0.3 |
| `docs:` | Patch | 1.0.3 → 1.0.4 |
| `style:` | Patch | 1.0.4 → 1.0.5 |
| `refactor:` | Patch | 1.0.5 → 1.0.6 |
| `feat:` | Minor | 1.0.6 → 1.1.0 |
| `feat!:` or `BREAKING CHANGE` in body | Major | 1.1.0 → 2.0.0 |

### Examples

```bash
# Bug fix — patch bump
git commit -m "fix: resolve dark mode text contrast on WHOIS output"

# New feature — minor bump
git commit -m "feat: add SSL certificate info tab"

# Breaking change — major bump
git commit -m "feat!: restructure JSON API response format"

# Chore/docs/refactor — patch bump
git commit -m "chore: update Bootstrap to 5.3.8"
git commit -m "docs: add API usage examples to README"
git commit -m "refactor: extract session config to shared file"
```

### Manual version control

To manually set the version (e.g. for a major release), edit the version in `includes/infoAppVer.php`:

```php
$app["Application"]["Version"]["Number"] = "2.0.0";
```

The auto-increment will continue from that version on the next push.

## Branching

| Branch | Purpose | Server folder | SFTP secret |
|---|---|---|---|
| `alpha` | Development (experimental) | `public_html_dev_alpha` | `SFTP_DEV_PATH` |
| `beta` | Active development | `public_html_dev_beta` | `SFTP_BETA_PATH` |
| `main` | Production/stable | `public_html` | `SFTP_LIVE_PATH` |

All branches deploy from the same `web/public_html/` source folder.

### Workflow

1. Work on the `beta` branch
2. Push triggers: version bump → changelog update → SFTP deploy (changed files only)
3. When stable, merge `beta` into `main` and tag a release

### Promoting beta to production

```bash
git checkout main
git merge beta
git tag v1.1.0
git push origin main --tags
```

## Development status

The development status in `includes/infoAppVer.php` is set automatically via a CI-injected `.env-channel` file:

- **For production (`main`):** GitHub Actions sets `Development Status` to `NULL` before uploading
- **For development (`alpha`/`beta`):** GitHub Actions sets `Development Status` to the channel name (`alpha` or `beta`)

## SFTP deployment

Deployment is controlled by the `SFTP_ENABLED` repository variable (Settings → Secrets and variables → Actions → Variables).

- Set to `true` to enable, remove or set to anything else to disable
- Only files changed in the commit are uploaded (not a full sync)
- `README.md`, `CHANGELOG.md`, `DEV_NOTES.md`, `.DS_Store`, `.gitkeep`, `.gitignore` are excluded from uploads

### Required GitHub secrets

| Secret | Description |
|---|---|
| `SFTP_HOST` | Server hostname |
| `SFTP_PORT` | SSH/SFTP port (usually 22) |
| `SFTP_USER` | SFTP username |
| `SFTP_PASSWORD` | SFTP password (used if `SFTP_KEY` is not set) |
| `SFTP_KEY` | SSH private key (takes priority over password) |
| `SFTP_DEV_PATH` | Remote path for alpha branch (`public_html_dev_alpha`) — no trailing slash |
| `SFTP_BETA_PATH` | Remote path for beta branch (`public_html_dev_beta`) — no trailing slash |
| `SFTP_LIVE_PATH` | Remote path for production (`public_html`) — no trailing slash |

### API keys and secrets

API keys and third-party credentials are stored in `web/.auth/keys.php` (gitignored). The `.auth/` directory contains:

| File | Purpose |
|---|---|
| `keys.php` | Active keys and credentials (gitignored, not tracked) |
| `keys.example.php` | Template showing the structure and format |
| `.htaccess` | Deny-all protection (prevents web access) |

On the server, the `.auth/` folder sits above the web root (sibling of the deployed `public_html/` folder), and is loaded by `includes/config.php` at runtime.

## GitHub Actions

| Workflow | Trigger | Purpose |
|---|---|---|
| `deploy.yml` | Push to `main`, `beta`, or `alpha` | SFTP upload of changed files to appropriate server folder |
| `version-bump.yml` | Push to `main`, `beta`, or `alpha` (code changes) | Auto-increment semver in `includes/infoAppVer.php` |
| `changelog.yml` | Push to `main`, `beta`, or `alpha` | Auto-append entry to `CHANGELOG.md` |
| `release.yml` | Tag push (`v*`) | Create GitHub Release (stable or pre-release) |
| `update-dns-resolvers.yml` | Daily 04:00 UTC / manual | Auto-update DNS resolver list from public-dns.info |

All workflows deploy from `web/public_html/` source and determine the target server folder via branch name and SFTP path secrets.

## URL Parameters

Optional URL parameters control the UI layout for focused or embedded views.

| Parameter | Type | Description |
|---|---|---|
| `hideSecScore` | flag | Hides the Security Score card from results |
| `hideDomainSummary` | flag | Hides the domain summary section (registrar, dates, geo, etc.) |
| `Only` | CSV | Comma-separated list of tabs to show: `whois`, `dns`, `email`, `ssl`, `subdomains`, `security` |

### Behaviour

- Flag parameters are presence-based (no value needed): `?hideSecScore`
- `?Only` accepts one or more tab names: `?Only=dns` or `?Only=dns,security`
- When `?Only` specifies a single tab, the tab bar is hidden and that tab is auto-focused
- Using `?Only` automatically implies `hideSecScore` and `hideDomainSummary`
- Parameters can be combined: `?hideSecScore&hideDomainSummary`
- Default view settings can be configured via the Settings panel (gear icon) and are persisted in localStorage

### URL Parameter Examples

```text
# Show only DNS tab (no summary, no score, no tab bar)
https://example.com/?Only=dns

# Show DNS and Security tabs
https://example.com/?Only=dns,security

# Full view with security score hidden
https://example.com/?hideSecScore

# Embed-ready minimal view
https://example.com/?Only=ssl&hideDomainSummary
```

## Settings

User settings (theme, default view mode) are stored in `localStorage` under the key `appSettings`. When user accounts (#163) are implemented, settings will sync to the user profile server-side.
