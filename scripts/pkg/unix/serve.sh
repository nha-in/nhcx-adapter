#!/usr/bin/env sh
# Run nhcx-adapter in this terminal. Ctrl+C stops it.
# Extra arguments are passed through, e.g. ./serve.sh --skip-checks
cd "$(dirname "$0")" || exit 1
exec ./nhcx-adapter serve "$@"
