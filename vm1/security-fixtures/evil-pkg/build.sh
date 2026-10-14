#!/bin/bash
# Builds evil-pkg-1.0.0.tgz fixture from package.json
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
npm pack
echo "Built evil-pkg-1.0.0.tgz in $DIR"
