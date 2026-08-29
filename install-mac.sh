#!/bin/bash
# codesentry - one-time installer for macOS
# Run this once per Mac: bash install-mac.sh

set -e

echo "Installing prerequisites via Homebrew..."
brew install python node git dotnet-sdk semgrep gitleaks

echo "Installing bandit (Python SAST)..."
pip3 install bandit --break-system-packages

echo "Installing ESLint + plugins into the toolkit (not global, not per-project)..."
cd "$(dirname "${BASH_SOURCE[0]}")"
npm install

echo ""
echo "Done. Verify with:"
echo "  semgrep --version"
echo "  gitleaks version"
echo "  bandit --version"
echo "  ./node_modules/.bin/eslint --version"
echo ""
echo "Then run a scan from anywhere with:"
echo "  bash $(pwd)/scan.sh /path/to/any/project"
