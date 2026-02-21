#!/system/bin/sh
MODDIR=${0%/*}/../..

if command -v iptables >/dev/null 2>&1; then
  echo "# iptables -S OUTPUT"
  iptables -S OUTPUT 2>&1
else
  echo "iptables not available on this runtime"
fi

echo
sh "$MODDIR/webroot/api/incidents.sh"
