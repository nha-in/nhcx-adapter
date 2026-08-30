#!/usr/bin/env sh
# Upgrade or downgrade nhcx-adapter from the GitHub releases.
#   ./update.sh              pick a version from a menu
#   ./update.sh --latest -y  newest release, no questions
#   ./update.sh --to v1.2.0  a specific version (older = downgrade)
#   ./update.sh --list       show what is available
#   ./update.sh --check      exit code 1 when a newer release exists
cd "$(dirname "$0")" || exit 1

./nhcx-adapter update "$@" || exit $?

PIDFILE=nhcx-adapter.pid
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo
  echo "The running server (PID $(cat "$PIDFILE")) still uses the previous version."
  echo "Run ./stop.sh and then ./serve-hidden.sh to switch."
fi
