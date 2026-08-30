#!/usr/bin/env sh
# Start nhcx-adapter in the background, detached from this terminal.
#   logs  -> logs/nhcx-adapter.log  (previous run kept as logs/nhcx-adapter.prev.log)
#   pid   -> nhcx-adapter.pid
#   stop  -> ./stop.sh
# Runs "serve --no-tui": setup problems are written to the log and the
# process exits, so check the log if nothing is listening.
cd "$(dirname "$0")" || exit 1
PIDFILE=nhcx-adapter.pid
LOG=logs/nhcx-adapter.log

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "nhcx-adapter is already running (PID $(cat "$PIDFILE")). Run ./stop.sh first."
  exit 1
fi
rm -f "$PIDFILE"

mkdir -p logs
[ -f "$LOG" ] && mv -f "$LOG" logs/nhcx-adapter.prev.log

nohup ./nhcx-adapter serve --no-tui "$@" </dev/null >"$LOG" 2>&1 &
echo $! >"$PIDFILE"

# Give the startup checks a moment, then report.
sleep 3
if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "nhcx-adapter started (PID $(cat "$PIDFILE")) - logs in $LOG"
else
  echo "nhcx-adapter exited during startup. Last log lines:"
  echo
  tail -n 20 "$LOG"
  rm -f "$PIDFILE"
  exit 1
fi
