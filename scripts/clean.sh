#!/usr/bin/env bash
set -euo pipefail

# Remove common build artifacts and generated files
echo "Cleaning build artifacts..."
rm -f zktool
rm -f coverage.out
rm -rf bin
echo "Done."

