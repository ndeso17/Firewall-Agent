#!/system/bin/sh

MODDIR=${0%/*}
RUNDIR="$MODDIR/runtime"

if command -v iptables >/dev/null 2>&1; then
  iptables -F >/dev/null 2>&1
fi

rm -rf "$RUNDIR" >/dev/null 2>&1
