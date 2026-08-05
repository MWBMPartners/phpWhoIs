#!/usr/bin/env bash
#
# Vendor Swagger UI (swagger-ui-dist) into the app's web trees so /docs.php
# serves it locally — no CDN, no build step, works on plain shared hosting.
#
# Assets are pulled from the npm registry (registry.npmjs.org) and the
# resulting files are COMMITTED to the repo. Re-run this to upgrade, then
# commit the diff.
#
#   Usage: scripts/vendor-swagger-ui.sh [version]     (default below)
#
set -euo pipefail

VERSION="${1:-5.32.12}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Fetching swagger-ui-dist@${VERSION} from the npm registry ..."
( cd "$TMP" && npm pack "swagger-ui-dist@${VERSION}" --silent >/dev/null )
tar -xzf "$TMP"/swagger-ui-dist-*.tgz -C "$TMP"

# Minimal runtime set for a BaseLayout Swagger UI page (topbar/standalone
# preset deliberately excluded — docs.php hides the topbar), plus the
# Apache-2.0 licence/notice files for redistribution compliance.
FILES=(
  swagger-ui.css
  swagger-ui-bundle.js
  swagger-ui-bundle.js.LICENSE.txt
  LICENSE
  NOTICE
)

for TREE in web/public_html_beta web/public_html; do
  [ -d "$ROOT/$TREE" ] || continue
  DEST="$ROOT/$TREE/assets/vendor/swagger-ui"
  mkdir -p "$DEST"
  for f in "${FILES[@]}"; do
    cp "$TMP/package/$f" "$DEST/$f"
  done
  printf '%s\n' "$VERSION" > "$DEST/VERSION"
  echo "  vendored -> $TREE/assets/vendor/swagger-ui/"
done

echo "Done. swagger-ui-dist@${VERSION} vendored into both web trees. Commit the diff."
