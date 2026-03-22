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

To manually set the version (e.g. for a major release), edit the version in `infoAppVer.php`:

```php
$app["Application"]["Version"]["Version"] = "2.0.0";
```

The auto-increment will continue from that version on the next push.

## Branching

| Branch | Purpose | Deploys to |
|---|---|---|
| `main` | Production/stable | `public_html/` via SFTP |
| `beta` | Active development | `public_html_beta/` via SFTP |

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

The development status in `infoAppVer.php` is set automatically:

- **Deploy action (Option 1):** When deploying from `main`, the GitHub Action sets `Development Status` to `NULL` before uploading
- **Runtime failsafe (Option 2):** `infoAppVer.php` checks `__DIR__` — if not in `public_html_beta/` or `public_html_dev/`, status is forced to `NULL`

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
| `SFTP_LIVE_PATH` | Remote path for production (`public_html/`) |
| `SFTP_BETA_PATH` | Remote path for beta (`public_html_beta/`) |

## GitHub Actions

| Workflow | Trigger | Purpose |
|---|---|---|
| `deploy.yml` | Push to `main` or `beta` | SFTP upload of changed files |
| `version-bump.yml` | Push to `beta` (code changes) | Auto-increment semver in `infoAppVer.php` |
| `changelog.yml` | Push to `main` or `beta` | Auto-append entry to `CHANGELOG.md` |
| `release.yml` | Tag push (`v*`) | Create GitHub Release (stable or pre-release) |
