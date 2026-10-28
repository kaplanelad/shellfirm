#!/usr/bin/env bash
set -euo pipefail

# Prints the Homebrew formula for a release, with a native binary for each
# macOS / Linux architecture.
# Usage: ./scripts/render-homebrew-formula.sh <version> <dir with the release .tar.xz files>

VERSION="${1:?usage: $0 <version> <assets dir>}"
ASSETS="${2:?usage: $0 <version> <assets dir>}"
VERSION="${VERSION#v}"

BASE_URL="https://github.com/kaplanelad/shellfirm/releases/download/v$VERSION"

checksum() {
  local file="$ASSETS/shellfirm-v$VERSION-$1.tar.xz"
  if [ ! -f "$file" ]; then
    echo "Error: $file not found" >&2
    exit 1
  fi
  if command -v sha256sum > /dev/null; then
    sha256sum "$file" | cut -d' ' -f1
  else
    shasum -a 256 "$file" | cut -d' ' -f1
  fi
}

AARCH64_MACOS=$(checksum aarch64-macos)
X86_64_MACOS=$(checksum x86_64-macos)
AARCH64_LINUX=$(checksum aarch64-linux)
X86_64_LINUX=$(checksum x86_64-linux)

cat <<EOF
class Shellfirm < Formula
  desc "Intercept any risky patterns (default or defined by you) and prompt you a small challenge for double verification"
  homepage "https://github.com/kaplanelad/shellfirm"
  version "$VERSION"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "$BASE_URL/shellfirm-v$VERSION-aarch64-macos.tar.xz"
      sha256 "$AARCH64_MACOS"
    end
    on_intel do
      url "$BASE_URL/shellfirm-v$VERSION-x86_64-macos.tar.xz"
      sha256 "$X86_64_MACOS"
    end
  end

  on_linux do
    on_arm do
      url "$BASE_URL/shellfirm-v$VERSION-aarch64-linux.tar.xz"
      sha256 "$AARCH64_LINUX"
    end
    on_intel do
      url "$BASE_URL/shellfirm-v$VERSION-x86_64-linux.tar.xz"
      sha256 "$X86_64_LINUX"
    end
  end

  def install
    bin.install "shellfirm"
  end

  test do
    assert_match("shellfirm #{version}", shell_output("#{bin}/shellfirm --version"))
  end
end
EOF
