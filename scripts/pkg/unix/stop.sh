#!/usr/bin/env sh
# Stop the nhcx-adapter started by ./serve-hidden.sh.
# Sends SIGTERM (in-flight requests drain for up to 30 s), then SIGKILL if
# it is still there.
cd "$(dirname "$0")" || exit 1
PIDFILE=nhcx-adapter.pid

if [ ! -f "$PIDFILE" ]; then
  if pkill -TERM -f 'nhcx-adapter serve' 2>/dev/null; then
    echo "nhcx-adapter stopped"
  else
    echo "nhcx-adapter is not running"
  fi
  exit 0
fi

PID=$(cat "$PIDFILE")
if ! kill -0 "$PID" 2>/dev/null; then
  echo "nhcx-adapter is not running (stale pid $PID)"
  rm -f "$PIDFILE"
  exit 0
fi

kill -TERM "$PID"
i=0
while kill -0 "$PID" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -ge 35 ]; then
    echo "still running after 35 s - killing"
    kill -KILL "$PID" 2>/dev/null
    break
  fi
  sleep 1
done
rm -f "$PIDFILE"
echo "nhcx-adapter stopped"
