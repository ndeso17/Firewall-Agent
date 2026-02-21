#!/system/bin/sh
MODDIR=${0%/*}/../..
LOG="$MODDIR/runtime/logs/service.log"

if [ -f "$LOG" ]; then
  tail -n 200 "$LOG"
else
  echo "[log] service.log not found"
fi
