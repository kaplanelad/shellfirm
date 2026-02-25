#!/usr/bin/env bash
set -euo pipefail

# Syncs the version from Cargo.toml into all npm package.json files.
# Usage: ./scripts/bump-npm-version.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/shellfirm/Cargo.toml"

VERSION=$(grep -m1 '^version' "$CARGO_TOML" | sed 's/version *= *"\(.*\)"/\1/')

if [ -z "$VERSION" ]; then
  echo "Error: could not extract version from $CARGO_TOML"
  exit 1
fi

echo "Syncing version $VERSION to all npm packages..."

PACKAGES=(
  "npm/shellfirm"
  "npm/cli-darwin-arm64"
  "npm/cli-darwin-x64"
  "npm/cli-linux-x64"
  "npm/cli-win32-x64"
)

for pkg in "${PACKAGES[@]}"; do
  PKG_JSON="$REPO_ROOT/$pkg/package.json"
  if [ ! -f "$PKG_JSON" ]; then
    echo "Warning: $PKG_JSON not found, skipping"
    continue
  fi

  # Update the package's own version
  tmp=$(mktemp)
  node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('$PKG_JSON', 'utf8'));
    pkg.version = '$VERSION';
    if (pkg.optionalDependencies) {
      for (const dep of Object.keys(pkg.optionalDependencies)) {
        pkg.optionalDependencies[dep] = '$VERSION';
      }
    }
    fs.writeFileSync('$PKG_JSON', JSON.stringify(pkg, null, 2) + '\n');
  "
  echo "  Updated $pkg -> $VERSION"
done

echo "Done."
