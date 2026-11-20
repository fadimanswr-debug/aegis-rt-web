#!/usr/bin/env bash
set -e
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$REPO_DIR/aegis"
ln -sf "$REPO_DIR/aegis" /usr/local/bin/aegis
echo "Aegis-RT installed from $REPO_DIR"
